package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// onboard.go — operator "onboard a holder" screen for the Inji auth-code flow.
// One form creates the eSignet identity (so the holder can log in) AND upserts
// their credential claims into certify.vc_subject (so Inji Certify issues their
// VC). Self-service replacement for seed-mock-identity.sh + the manual SQL.

// mockIdentityURL is the eSignet mock-identity-system base. Per-host via env;
// defaults to the compose service so deploy.sh up <scenario> just works.
func mockIdentityURL() string {
	if v := strings.TrimSpace(os.Getenv("MOCK_IDENTITY_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://injiweb-mock-identity:8082"
}

func mlValue(v string) []map[string]string {
	return []map[string]string{{"language": "eng", "value": v}}
}

// createMockIdentity registers an identity in the eSignet mock-identity-system so
// the holder can authenticate via eSignet OTP. Mirrors seed-mock-identity.sh.
// Treats an already-existing identity as success (idempotent).
func createMockIdentity(ctx context.Context, id, pin, fullName, given, family, gender, dobSlash, email, phone string) error {
	if gender == "" {
		gender = "Male"
	}
	if dobSlash == "" {
		dobSlash = "1990/01/01"
	}
	if given == "" {
		given = fullName
	}
	if family == "" {
		family = fullName
	}
	body := map[string]any{
		"requestTime": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"request": map[string]any{
			"individualId": id, "pin": pin, "password": pin,
			"fullName": mlValue(fullName), "givenName": mlValue(given), "middleName": mlValue("-"),
			"familyName": mlValue(family), "nickName": mlValue(given),
			"preferredUsername": mlValue(strings.ToLower(strings.ReplaceAll(given, " ", ""))),
			"preferredLang":     "eng", "locale": "en-US", "zoneInfo": "Africa/Nairobi",
			"dateOfBirth": dobSlash, "gender": mlValue(gender),
			"email": email, "phone": phone,
			"streetAddress": mlValue("1 Main Street"), "locality": mlValue("City"),
			"region": mlValue("Region"), "postalCode": "00100", "country": mlValue("KEN"),
			"encodedPhoto": "",
		},
	}
	buf, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		mockIdentityURL()+"/v1/mock-identity-system/identity", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var rb struct {
		Response any `json:"response"`
		Errors   []struct {
			ErrorCode    string `json:"errorCode"`
			ErrorMessage string `json:"errorMessage"`
		} `json:"errors"`
	}
	_ = json.Unmarshal(raw, &rb)
	if len(rb.Errors) > 0 {
		msg := strings.ToLower(rb.Errors[0].ErrorCode + " " + rb.Errors[0].ErrorMessage)
		if strings.Contains(msg, "exist") || strings.Contains(msg, "duplicate") {
			return nil // already onboarded — fine
		}
		return fmt.Errorf("%s", strings.TrimSpace(rb.Errors[0].ErrorMessage+" "+rb.Errors[0].ErrorCode))
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncateForLog(string(raw), 200))
	}
	return nil
}

// ShowOnboard renders the operator onboarding/provisioning form.
func (h *H) ShowOnboard(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	h.render(w, r, "issuer_onboard", h.pageData(sess, map[string]any{
		"Enabled":       h.Subjects != nil,
		"DefaultClient": defaultAuthCodeClientID(),
	}))
}

// OnboardUser creates the eSignet identity + provisions the credential claims.
func (h *H) OnboardUser(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	render := func(extra map[string]any) {
		base := map[string]any{"Enabled": h.Subjects != nil, "DefaultClient": defaultAuthCodeClientID()}
		for k, v := range extra {
			base[k] = v
		}
		h.render(w, r, "issuer_onboard", h.pageData(sess, base))
	}
	if h.Subjects == nil {
		render(map[string]any{"Error": "Subject provisioning not enabled (INJI_CERTIFY_DATABASE_URL not set)"})
		return
	}
	_ = r.ParseForm()
	id := strings.TrimSpace(r.FormValue("individual_id"))
	full := strings.TrimSpace(r.FormValue("full_name"))
	pin := strings.TrimSpace(r.FormValue("pin"))
	if pin == "" {
		pin = "111111"
	}
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	if clientID == "" {
		clientID = defaultAuthCodeClientID()
	}
	if id == "" || full == "" {
		render(map[string]any{"Error": "Individual ID and full name are required.", "Form": r.Form})
		return
	}
	given := strings.TrimSpace(r.FormValue("given_name"))
	family := strings.TrimSpace(r.FormValue("family_name"))
	gender := strings.TrimSpace(r.FormValue("gender"))
	dob := strings.TrimSpace(r.FormValue("date_of_birth")) // YYYY-MM-DD
	email := strings.TrimSpace(r.FormValue("email"))
	phone := strings.TrimSpace(r.FormValue("phone"))

	// 1) eSignet identity (mock-identity wants YYYY/MM/DD)
	if err := createMockIdentity(r.Context(), id, pin, full, given, family, gender, strings.ReplaceAll(dob, "-", "/"), email, phone); err != nil {
		render(map[string]any{"Error": "Create eSignet identity: " + err.Error()})
		return
	}
	// 2) credential claims keyed by the eSignet PSU-token
	claims := map[string]string{"fullName": full}
	for k, v := range map[string]string{"givenName": given, "familyName": family, "gender": gender, "dateOfBirth": dob, "email": email, "phoneNumber": phone} {
		if v != "" {
			claims[k] = v
		}
	}
	subjectID := esignetSubjectID(id, clientID)
	if err := h.Subjects.ProvisionSubject(r.Context(), subjectID, claims); err != nil {
		render(map[string]any{"Error": "Provision claims: " + err.Error()})
		return
	}
	render(map[string]any{
		"Success": true, "IndividualID": id, "PIN": pin, "FullName": full, "SubjectID": subjectID,
	})
}
