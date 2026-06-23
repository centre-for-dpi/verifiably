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

// onboard.go — holder SELF-REGISTRATION for the Inji auth-code flow. The holder
// creates their own eSignet identity (so they can sign in) and verifiably
// AUTO-PROVISIONS their claims into certify.vc_subject by looking them up in the
// configured authoritative registries (by Individual ID) — the issuer never types
// a holder's data. Identity creation is an identity-authority concern, not an
// issuer one — hence /holder/register.

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

// ShowHolderRegister renders the holder self-registration form.
func (h *H) ShowHolderRegister(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	h.render(w, r, "holder_register", h.pageData(sess, map[string]any{
		"Enabled": h.Subjects != nil,
	}))
}

// RegisterHolder creates the holder's own eSignet identity AND auto-provisions their
// claims into certify.vc_subject (keyed by the eSignet PSU-token) from the configured
// authoritative registries, looked up by Individual ID. No manual entry — the issuer
// never types a holder's data. Derives full name from given + family for the identity.
func (h *H) RegisterHolder(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	render := func(extra map[string]any) {
		base := map[string]any{"Enabled": h.Subjects != nil}
		for k, v := range extra {
			base[k] = v
		}
		h.render(w, r, "holder_register", h.pageData(sess, base))
	}
	if h.Subjects == nil {
		render(map[string]any{"Error": "Registration is not enabled on this deployment."})
		return
	}
	_ = r.ParseForm()
	id := strings.TrimSpace(r.FormValue("individual_id"))
	given := strings.TrimSpace(r.FormValue("given_name"))
	family := strings.TrimSpace(r.FormValue("family_name"))
	email := strings.TrimSpace(r.FormValue("email"))
	phone := strings.TrimSpace(r.FormValue("phone"))
	// email + phone are required by the eSignet mock-identity-system (it rejects an
	// empty/invalid email); check here for a clear message instead of its raw error.
	if id == "" || given == "" || family == "" || email == "" || phone == "" {
		render(map[string]any{"Error": "Individual ID, given/family name, email and phone are required.", "Form": r.Form})
		return
	}
	pin := strings.TrimSpace(r.FormValue("pin"))
	if pin == "" {
		pin = "111111"
	}
	full := strings.TrimSpace(given + " " + family)
	gender := strings.TrimSpace(r.FormValue("gender"))
	dob := strings.TrimSpace(r.FormValue("date_of_birth")) // YYYY-MM-DD

	// 1) eSignet identity (mock-identity wants YYYY/MM/DD)
	if err := createMockIdentity(r.Context(), id, pin, full, given, family, gender, strings.ReplaceAll(dob, "-", "/"), email, phone); err != nil {
		render(map[string]any{"Error": "Create identity: " + err.Error(), "Form": r.Form})
		return
	}
	// 2) Auto-provision the holder's credential data from the configured authoritative
	// registries (keyed by their Individual ID). No manual entry; the issuer never types.
	claims := map[string]string{}
	for _, p := range registryProviders() {
		for k, v := range fetchRegistry(r.Context(), p, id) {
			claims[k] = v
		}
	}
	subjectID := esignetSubjectID(id, injiAuthcodeClientID())
	if len(claims) > 0 {
		if err := h.Subjects.ProvisionSubject(r.Context(), subjectID, claims); err != nil {
			render(map[string]any{"Error": "Save registry data: " + err.Error(), "Form": r.Form})
			return
		}
	}
	render(map[string]any{"Success": true, "IndividualID": id, "FullName": full})
}
