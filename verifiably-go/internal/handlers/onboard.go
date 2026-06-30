package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
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

// ShowHolderRegister renders step 1 of holder ACTIVATION: enter your Individual
// ID. (Despite the route name, this is no longer self-registration — the holder
// must already be enrolled by a registrar; see RegisterHolder.)
func (h *H) ShowHolderRegister(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	sess.ActivationToken = "" // a fresh visit starts a clean activation
	h.render(w, r, "holder_register", h.pageData(sess, map[string]any{
		"Enabled":      h.Subjects != nil,
		"EmailEnabled": h.Mailer != nil,
	}))
}

// RegisterHolder is registry-gated holder ACTIVATION — the MOSIP/eSignet model.
// The holder does NOT mint their own identity; they must already exist in the
// authoritative identity registry (enrolled by a registrar). Activation is two
// steps:
//
//	step "request": look the Individual ID up in the identity registry; if
//	  enrolled, email a one-time code to the address ON FILE (proof of ownership).
//	step "verify":  the holder submits the code + a PIN of their choosing; on
//	  success we materialise their eSignet identity from the REGISTRY demographics
//	  (never self-asserted) + their PIN, then auto-provision their credential
//	  claims from the credential registries (unchanged).
//
// Not enrolled → refused. This is the only place identity is created, and it is
// gated on an authoritative record + email ownership.
func (h *H) RegisterHolder(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	_ = r.ParseForm()
	render := func(extra map[string]any) {
		base := map[string]any{"Enabled": h.Subjects != nil, "EmailEnabled": h.Mailer != nil}
		for k, v := range extra {
			base[k] = v
		}
		h.render(w, r, "holder_register", h.pageData(sess, base))
	}
	if h.Subjects == nil {
		render(map[string]any{"Error": "Activation is not enabled on this deployment."})
		return
	}
	if strings.TrimSpace(r.FormValue("step")) == "verify" {
		h.activateVerify(w, r, sess, render)
		return
	}
	h.activateRequest(w, r, sess, render)
}

// activateRequest is step 1: gate on the identity registry, then email the OTP.
func (h *H) activateRequest(w http.ResponseWriter, r *http.Request, sess *Session, render func(map[string]any)) {
	id := strings.TrimSpace(r.FormValue("individual_id"))
	if id == "" {
		render(map[string]any{"Error": "Enter your Individual ID."})
		return
	}
	rec, err := h.Subjects.GetIdentity(r.Context(), id)
	if err != nil {
		render(map[string]any{"Error": "Identity lookup failed: " + err.Error()})
		return
	}
	if len(rec) == 0 {
		// The core gate: a holder cannot create themselves. Not enrolled → refused.
		render(map[string]any{"Error": "This Individual ID is not enrolled in the identity registry. Contact your registrar to be enrolled before you can sign up."})
		return
	}
	email := strings.TrimSpace(rec["email"])
	if email == "" {
		render(map[string]any{"Error": "Your identity record has no email on file, so we can't verify ownership. Contact your registrar."})
		return
	}
	if h.Mailer == nil {
		render(map[string]any{"Error": "Email delivery isn't configured on this deployment, so ownership can't be verified."})
		return
	}
	token, code := h.OTPs.Issue(id, email)
	body := "Your verification code is: " + code + "\n\n" +
		"Enter it on the activation page to set your PIN and claim your credentials. " +
		"It expires in 10 minutes.\n\nIf you didn't request this, you can ignore this email."
	if err := h.Mailer.Send(email, "Your activation code", body); err != nil {
		log.Printf("activation: send OTP to %s failed: %v", maskEmail(email), err)
		render(map[string]any{"Error": "Couldn't send the verification email — please try again shortly."})
		return
	}
	sess.ActivationToken = token
	log.Printf("activation: holder %q enrolled; OTP sent to %s", id, maskEmail(email))
	render(map[string]any{"Step": "verify", "IndividualID": id, "MaskedEmail": maskEmail(email), "FullName": strings.TrimSpace(rec["fullName"])})
}

// activateVerify is step 2: check the OTP, then materialise the eSignet identity
// from the authoritative registry demographics + the holder's PIN, and provision
// their credential claims.
func (h *H) activateVerify(w http.ResponseWriter, r *http.Request, sess *Session, render func(map[string]any)) {
	token := sess.ActivationToken
	if token == "" {
		render(map[string]any{"Error": "Your activation session expired — start again."})
		return
	}
	id, email, ok := h.OTPs.Peek(token)
	if !ok {
		sess.ActivationToken = ""
		render(map[string]any{"Error": "Your verification code expired — start again."})
		return
	}
	reprompt := func(msg string) {
		render(map[string]any{"Step": "verify", "IndividualID": id, "MaskedEmail": maskEmail(email), "Error": msg})
	}
	otp := strings.TrimSpace(r.FormValue("otp"))
	pin := strings.TrimSpace(r.FormValue("pin"))
	if otp == "" || pin == "" {
		reprompt("Enter the code we emailed and choose a PIN.")
		return
	}
	if len(pin) < 6 {
		reprompt("Your PIN must be at least 6 digits.")
		return
	}
	verifiedID, vok, reason := h.OTPs.Verify(token, otp)
	if !vok {
		reprompt("Verification failed: " + reason + ".")
		return
	}
	sess.ActivationToken = ""

	// Demographics come from the AUTHORITATIVE registry, never the holder.
	rec, err := h.Subjects.GetIdentity(r.Context(), verifiedID)
	if err != nil || len(rec) == 0 {
		render(map[string]any{"Error": "Your identity record could not be read — contact your registrar."})
		return
	}
	given := strings.TrimSpace(rec["givenName"])
	family := strings.TrimSpace(rec["familyName"])
	full := strings.TrimSpace(rec["fullName"])
	if full == "" {
		full = strings.TrimSpace(given + " " + family)
	}
	gender := strings.TrimSpace(rec["gender"])
	dob := strings.ReplaceAll(strings.TrimSpace(rec["dateOfBirth"]), "-", "/") // mock-identity wants YYYY/MM/DD

	// 1) Materialise the eSignet identity (the IDA stand-in) from the registry
	// record + the holder's chosen PIN. NOTE: createMockIdentity is idempotent —
	// if the individualId already had an eSignet identity its PIN is NOT changed
	// (a re-activation keeps the original PIN; a fresh enrolment sets it here).
	if err := createMockIdentity(r.Context(), verifiedID, pin, full, given, family, gender, dob, email, strings.TrimSpace(rec["phone"])); err != nil {
		render(map[string]any{"Error": "Create identity: " + err.Error()})
		return
	}
	// 2) Auto-provision the holder's credential claims from the CREDENTIAL
	// registries (keyed by the eSignet PSU-token). Unchanged from before — the
	// identity registry supplies WHO they are; the credential registries supply
	// their claim data.
	provs := registryProviders()
	claims := map[string]string{}
	for _, p := range provs {
		for k, v := range fetchRegistry(r.Context(), p, verifiedID) {
			claims[k] = v
		}
	}
	if len(claims) > 0 {
		subjectID := esignetSubjectID(verifiedID, injiAuthcodeClientID())
		if err := h.Subjects.ProvisionSubject(r.Context(), subjectID, claims); err != nil {
			render(map[string]any{"Error": "Save registry data: " + err.Error()})
			return
		}
	}
	log.Printf("activation: holder %q activated; provisioned %d claim(s) from %d registr(y/ies)", verifiedID, len(claims), len(provs))
	render(map[string]any{"Success": true, "IndividualID": verifiedID, "FullName": full, "Provisioned": len(claims)})
}
