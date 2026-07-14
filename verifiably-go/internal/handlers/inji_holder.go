package handlers

// inji_holder.go — verifiably's own OID4VCI authorization_code wallet for the
// Inji / eSignet dynamic-issuance flow. Lets a holder claim their credential
// INSIDE verifiably (no redirect to the external Inji Web subdomain):
//
//   GET /holder/wallet/inji/start    -> eSignet authorize (PKCE) redirect
//   GET /holder/wallet/inji/callback -> code -> token (private_key_jwt) ->
//                                       holder-proof (did:jwk) -> credential ->
//                                       store on the session -> show it
//   GET /holder/wallet/inji          -> render the claimed credential
//
// This is the protocol-proof logic (token + holder proof + credential request)
// ported to Go, reusing the eSignet wallet-demo-client key the deploy provides.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/internal/delegation"
	"github.com/verifiably/verifiably-go/internal/storage/injiwallet"
)

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func injiAuthcodeEnabled() bool { return strings.TrimSpace(os.Getenv("INJI_AUTHCODE_CLIENT_KEY_PEM")) != "" }
func injiAuthcodeClientID() string { return envOr("INJI_AUTHCODE_CLIENT_ID", "wallet-demo-client") }
func injiAuthcodeKID() string      { return envOr("INJI_AUTHCODE_CLIENT_KID", "wallet-demo-client-kid") }
func injiAuthcodeScope() string    { return envOr("INJI_AUTHCODE_SCOPE", "mock_identity_vc_ldp") }

// injiAuthcodeACR steers eSignet to PIN login: acr "static-code" maps to the PIN
// auth factor in eSignet's amr_acr_mapping (vs "generated-code" = OTP). The holder's
// PIN is the one stored in the mock-identity by /holder/register. Override via env.
func injiAuthcodeACR() string { return envOr("INJI_AUTHCODE_ACR", "mosip:idp:acr:static-code") }
func esignetBase() string          { return strings.TrimRight(envOr("ESIGNET_BASE_URL", ""), "/") }

func injiHolderCallbackURL() string {
	return strings.TrimRight(envOr("VERIFIABLY_PUBLIC_URL", ""), "/") + "/holder/wallet/inji/callback"
}

// injiAuthcodeClientKey parses the wallet-demo-client RSA key (PKCS#8 PEM the
// deploy extracts from oidckeystore.p12).
func injiAuthcodeClientKey() (*rsa.PrivateKey, error) {
	blk, _ := pem.Decode([]byte(os.Getenv("INJI_AUTHCODE_CLIENT_KEY_PEM")))
	if blk == nil {
		return nil, fmt.Errorf("INJI_AUTHCODE_CLIENT_KEY_PEM not a PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		k2, err2 := x509.ParsePKCS1PrivateKey(blk.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse client key: %w", err)
		}
		return k2, nil
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("client key is not RSA")
	}
	return rk, nil
}

func b64u(b []byte) string         { return base64.RawURLEncoding.EncodeToString(b) }
func b64uJSON(v any) string        { b, _ := json.Marshal(v); return b64u(b) }
func randB64(n int) string         { b := make([]byte, n); _, _ = rand.Read(b); return b64u(b) }
func pkceChallenge(v string) string { h := sha256.Sum256([]byte(v)); return b64u(h[:]) }

func signRS256(key *rsa.PrivateKey, header, claims map[string]any) (string, error) {
	signing := b64uJSON(header) + "." + b64uJSON(claims)
	h := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	return signing + "." + b64u(sig), nil
}

func signES256(key *ecdsa.PrivateKey, header, claims map[string]any) (string, error) {
	signing := b64uJSON(header) + "." + b64uJSON(claims)
	h := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[0:32])
	s.FillBytes(sig[32:64])
	return signing + "." + b64u(sig), nil
}

// StartInjiClaim kicks off the eSignet authorization_code flow.
func (h *H) StartInjiClaim(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if !injiAuthcodeEnabled() || esignetBase() == "" {
		sess.InjiClaimError = "In-app Inji claim is not configured (INJI_AUTHCODE_CLIENT_KEY_PEM / ESIGNET_BASE_URL)."
		h.redirect(w, r, "/holder/wallet/inji")
		return
	}
	verifier := randB64(32)
	state := randB64(16)
	sess.PendingState = state
	sess.PendingPKCE = verifier
	sess.PendingProvider = "inji-authcode"
	// Which credential the holder picked from the catalog (?cred=<key>); look up
	// its per-credential eSignet scope. Default to the base scope/credential.
	cred := strings.TrimSpace(r.URL.Query().Get("cred"))
	scope := injiAuthcodeScope()
	if cred != "" && h.Subjects != nil {
		if s, err := h.Subjects.CredentialScope(r.Context(), cred); err == nil && s != "" {
			scope = s
		}
	}
	sess.InjiClaimCred = cred
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", injiAuthcodeClientID())
	q.Set("scope", scope)
	q.Set("redirect_uri", injiHolderCallbackURL())
	q.Set("state", state)
	q.Set("nonce", randB64(12))
	q.Set("code_challenge", pkceChallenge(verifier))
	q.Set("code_challenge_method", "S256")
	q.Set("ui_locales", "en")
	q.Set("acr_values", h.injiAuthcodeACRValues()) // enabled login factors (admin-config'd via /admin/esignet; env fallback)
	http.Redirect(w, r, esignetBase()+"/authorize?"+q.Encode(), http.StatusFound)
}

// InjiClaimCallback completes the flow: token -> holder proof -> credential.
func (h *H) InjiClaimCallback(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	fail := func(msg string) {
		sess.InjiClaimError = msg
		sess.InjiClaimedVC = ""
		h.redirect(w, r, "/holder/wallet/inji")
	}
	if e := r.URL.Query().Get("error"); e != "" {
		fail("eSignet returned: " + e + " " + r.URL.Query().Get("error_description"))
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" || r.URL.Query().Get("state") != sess.PendingState {
		fail("Missing code or state mismatch (CSRF). Try again from the wallet.")
		return
	}
	credType := sess.InjiClaimCred
	if credType == "" {
		credType = "VerifiablePersonCredential"
	}
	// Look up the credential's format + @context + vct so the request matches its
	// credential_config (ldp_vc with the v1/v2 context, or vc+sd-jwt with a vct).
	format, vcContext, vct := "ldp_vc", "https://www.w3.org/2018/credentials/v1", ""
	if sess.InjiClaimCred != "" && h.Subjects != nil {
		if f, c, v, e := h.Subjects.CredentialClaimSpec(r.Context(), sess.InjiClaimCred); e == nil && f != "" {
			format = f
			if c != "" {
				vcContext = c
			}
			vct = v
		}
	}
	var holderKeyPEM string
	vc, err := h.injiClaimCredential(r.Context(), code, sess.PendingPKCE, credType, format, vcContext, vct, &holderKeyPEM)
	sess.PendingState, sess.PendingPKCE, sess.PendingProvider = "", "", ""
	if err != nil {
		msg := "Claim failed: " + err.Error()
		// Certify returns ERROR_FETCHING_DATA_RECORD_FROM_TABLE when the holder's
		// eSignet identity has no provisioned row for this credential's data.
		if strings.Contains(err.Error(), "DATA_RECORD") || strings.Contains(err.Error(), "FETCHING_DATA") {
			msg = "No data was found for your eSignet identity for this credential. " +
				"Activate your identity at /holder/register (you must be enrolled in the " +
				"identity registry by a registrar), then claim again."
		}
		fail(msg)
		return
	}
	// Guard: Certify does NOT error when the Postgres data provider returns no
	// value for a claim — its Velocity engine renders the undefined marker
	// verbatim (e.g. "${last_name}"), so the claim "succeeds" with junk. Refuse to
	// store such a credential; the holder's eSignet identity isn't provisioned for
	// this credential type. (The DATA_RECORD branch above only fires when Certify
	// finds NO row at all; a row missing individual columns slips past it.)
	if hasUnsubstitutedTemplateMarkers(vc) {
		fail("This credential came back with unfilled template fields (e.g. ${…}) — " +
			"your eSignet identity has no data provisioned for this credential type. " +
			"Enrol/activate at /holder/register (a registrar must enrol you in the " +
			"identity registry), then claim again.")
		return
	}
	sess.InjiClaimedVC = vc
	sess.InjiClaimedVCs = append([]string{vc}, sess.InjiClaimedVCs...) // newest first; shown on the held page
	// Retain the SD-JWT's holder binding key so the credential can later be
	// presented over OID4VP to Inji Verify with a key-bound KB-JWT (F21).
	if holderKeyPEM != "" && strings.Contains(vc, "~") {
		if sess.InjiHolderKeys == nil {
			sess.InjiHolderKeys = map[string]string{}
		}
		sess.InjiHolderKeys[vcID(vc)] = holderKeyPEM
	}
	// Durably persist the credential under the holder's OIDC identity so the wallet
	// follows the logged-in user across sessions/restarts (the session cache alone
	// is cookie-scoped). Best-effort; the session copy above still serves this view.
	if h.InjiWallet != nil {
		_ = h.InjiWallet.Add(sessionWalletKey(sess), injiwallet.HeldCred{
			VCID: vcID(vc), VC: vc, HolderKey: holderKeyPEM, ClaimedAt: time.Now().UTC(),
		})
	}
	sess.InjiClaimError = ""
	h.redirect(w, r, "/holder/wallet/inji/credentials")
}

// unsubstitutedMarkerRe matches a leftover Velocity substitution marker like
// ${last_name} or ${_holderId} — the shape Inji Certify emits verbatim when its
// data provider returned no value for that claim.
var unsubstitutedMarkerRe = regexp.MustCompile(`\$\{[A-Za-z_][A-Za-z0-9_]*\}`)

// hasUnsubstitutedTemplateMarkers reports whether a freshly-claimed Inji
// credential still contains unfilled ${var} template markers (the identity
// wasn't provisioned for this credential type). For a W3C ldp_vc the markers sit
// in the plaintext JSON. For a compact SD-JWT they live inside the base64url
// disclosures (the raw compact string is base64url + dots and can't contain
// '${'), so decode each '~'-separated disclosure and check its bytes; the issuer
// JWT and any KB-JWT segments contain dots, so their base64url decode fails and
// they're skipped.
func hasUnsubstitutedTemplateMarkers(vc string) bool {
	if strings.Contains(vc, "~") { // compact SD-JWT: <jwt>~<disclosure>~…[~<kb-jwt>]
		for _, part := range strings.Split(vc, "~") {
			if dec, err := base64.RawURLEncoding.DecodeString(part); err == nil && unsubstitutedMarkerRe.Match(dec) {
				return true
			}
		}
		return false
	}
	return unsubstitutedMarkerRe.MatchString(vc)
}

// injiClaimCredential does token exchange (private_key_jwt) + holder proof +
// credential request, returning the issued VC as a JSON string. When keyOut is
// non-nil it also receives the PEM of the ES256 holder key the credential's cnf
// was bound to, so the caller can retain it for a later key-bound OID4VP
// presentation (F21). keyOut is populated only on a successful claim.
func (h *H) injiClaimCredential(ctx context.Context, code, verifier, credType, format, vcContext, vct string, keyOut *string) (string, error) {
	key, err := injiAuthcodeClientKey()
	if err != nil {
		return "", err
	}
	tokenEP := esignetBase() + "/v1/esignet/oauth/v2/token"
	now := time.Now()
	assertion, err := signRS256(key,
		map[string]any{"alg": "RS256", "kid": injiAuthcodeKID(), "typ": "JWT"},
		map[string]any{"iss": injiAuthcodeClientID(), "sub": injiAuthcodeClientID(),
			"aud": tokenEP, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "jti": randB64(12)})
	if err != nil {
		return "", err
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", injiHolderCallbackURL())
	form.Set("code_verifier", verifier)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)
	var tok struct {
		AccessToken string `json:"access_token"`
		CNonce      string `json:"c_nonce"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := postForm(ctx, tokenEP, form, &tok); err != nil {
		return "", fmt.Errorf("token: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("token endpoint: %s %s", tok.Error, tok.ErrorDesc)
	}

	issuer := injiCredentialIssuer(ctx)
	credEP := injiCertifyUpstream() + "/v1/certify/issuance/credential"
	holderKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if keyOut != nil {
		if pemStr, e := marshalECKeyPEM(holderKey); e == nil {
			*keyOut = pemStr
		}
	}
	xb := make([]byte, 32)
	yb := make([]byte, 32)
	holderKey.X.FillBytes(xb)
	holderKey.Y.FillBytes(yb)
	jwk := map[string]any{"kty": "EC", "crv": "P-256", "x": b64u(xb), "y": b64u(yb), "alg": "ES256"}

	claim := func(nonce string) (int, []byte, error) {
		proofClaims := map[string]any{"iss": injiAuthcodeClientID(), "aud": issuer, "iat": time.Now().Unix()}
		if nonce != "" {
			proofClaims["nonce"] = nonce
		}
		proof, e := signES256(holderKey,
			map[string]any{"alg": "ES256", "typ": "openid4vci-proof+jwt", "jwk": jwk}, proofClaims)
		if e != nil {
			return 0, nil, e
		}
		reqMap := map[string]any{
			"format": format,
			"proof":  map[string]any{"proof_type": "jwt", "jwt": proof},
		}
		if format == "vc+sd-jwt" || format == "dc+sd-jwt" {
			reqMap["vct"] = vct
		} else {
			reqMap["credential_definition"] = map[string]any{
				"@context": []string{vcContext},
				"type":     []string{"VerifiableCredential", credType},
			}
		}
		reqBody, _ := json.Marshal(reqMap)
		return postJSON(ctx, credEP, reqBody, "Bearer "+tok.AccessToken)
	}
	status, body, err := claim(tok.CNonce)
	if err != nil {
		return "", err
	}
	if status >= 400 {
		// retry once with the c_nonce the issuer hands back on a 400
		var e struct {
			CNonce string `json:"c_nonce"`
			Error  string `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		if e.CNonce != "" {
			status, body, err = claim(e.CNonce)
			if err != nil {
				return "", err
			}
		}
		if status >= 400 {
			return "", fmt.Errorf("credential endpoint %d: %s", status, truncateForLog(string(body), 200))
		}
	}
	// Certify returns {"credential": {...VC...}} (ldp_vc, a JSON object) or
	// {"credential": "eyJ…~"} (SD-JWT, a JSON *string*). For SD-JWT, unwrap the
	// JSON string so we store the raw compact SD-JWT, not a quoted "eyJ…~"
	// literal (which the wallet would render as a malformed blob).
	var wrap struct {
		Credential json.RawMessage `json:"credential"`
	}
	if json.Unmarshal(body, &wrap) == nil && len(wrap.Credential) > 0 {
		raw := wrap.Credential
		if raw[0] == '"' {
			var s string
			if json.Unmarshal(raw, &s) == nil {
				return s, nil
			}
		}
		return string(raw), nil
	}
	return string(body), nil
}

// injiCredentialIssuer reads the credential_issuer identifier from Certify's
// well-known (the holder-proof aud must match it). Falls back to the upstream.
func injiCredentialIssuer(ctx context.Context) string {
	url := injiCertifyUpstream() + "/v1/certify/.well-known/openid-credential-issuer"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err == nil {
		if resp, e := http.DefaultClient.Do(req); e == nil {
			defer resp.Body.Close()
			var m struct {
				CredentialIssuer string `json:"credential_issuer"`
			}
			if json.NewDecoder(resp.Body).Decode(&m) == nil && m.CredentialIssuer != "" {
				return m.CredentialIssuer
			}
		}
	}
	return injiCertifyUpstream()
}

func postForm(ctx context.Context, endpoint string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return json.Unmarshal(body, out)
}

func postJSON(ctx context.Context, endpoint string, body []byte, auth string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, rb, nil
}

// ShowInjiClaim renders the claimed credential (or an error / a CTA to start).
func (h *H) ShowInjiClaim(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	body := map[string]any{
		"Enabled": injiAuthcodeEnabled() && esignetBase() != "",
		"Error":   sess.InjiClaimError,
	}
	if h.Subjects != nil {
		if creds, err := h.Subjects.ListCredentials(r.Context()); err == nil {
			body["Catalog"] = creds
		}
	}
	body["HeldCount"] = len(sess.InjiClaimedVCs)
	h.render(w, r, "holder_inji", h.pageData(sess, body))
}

// parseClaimedVC turns an issued VC (JSON string) into display fields for the held page:
// the pretty-printed VC, the credentialSubject, the specific type, issuer and validUntil.
// vcID is a stable short id for a stored claimed-VC string (so deletion keys on
// the credential, not its volatile newest-first index).
func vcID(vc string) string {
	sum := sha256.Sum256([]byte(vc))
	return base64.RawURLEncoding.EncodeToString(sum[:9])
}

func parseClaimedVC(vc string) map[string]any {
	out := map[string]any{"VC": vc, "ID": vcID(vc)}
	var pretty any
	if json.Unmarshal([]byte(vc), &pretty) != nil {
		// Not JSON — an SD-JWT VC is a compact "header.payload.sig~disclosure~…"
		// string. Decode it so the wallet shows fields/issuer/name like ldp_vc.
		if sd := parseSDJWTClaimedVC(vc); sd != nil {
			return sd
		}
		return out
	}
	if b, err := json.MarshalIndent(pretty, "", "  "); err == nil {
		out["VC"] = string(b)
	}
	m, ok := pretty.(map[string]any)
	if !ok {
		return out
	}
	if cs, ok := m["credentialSubject"].(map[string]any); ok {
		out["Subject"] = cs
	}
	if ts, ok := m["type"].([]any); ok {
		for _, t := range ts {
			if s, _ := t.(string); s != "" && s != "VerifiableCredential" {
				out["ClaimedName"] = s
				break
			}
		}
	}
	if iss, ok := m["issuer"].(string); ok {
		out["Issuer"] = iss
	}
	if vu, ok := m["validUntil"].(string); ok {
		out["ValidUntil"] = vu
	}
	return out
}

// b64uDecode decodes base64url, tolerating padded and unpadded forms (JWT
// segments and SD-JWT disclosures are unpadded, but be lenient).
func b64uDecode(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// sdJWTPayload decodes the JWT payload (claims) of a compact SD-JWT VC
// ("header.payload.sig~disclosure~…"). Returns nil if it doesn't parse as one.
func sdJWTPayload(vc string) map[string]any {
	jwt := vc
	if i := strings.IndexByte(vc, '~'); i >= 0 {
		jwt = vc[:i]
	}
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return nil
	}
	pb, err := b64uDecode(parts[1])
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(pb, &m) != nil {
		return nil
	}
	return m
}

// sdJWTReserved are SD-JWT / JWT claims that aren't holder-facing subject fields.
var sdJWTReserved = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true, "nbf": true, "iat": true,
	"jti": true, "cnf": true, "vct": true, "status": true, "id": true,
	"_sd": true, "_sd_alg": true,
}

// parseSDJWTClaimedVC decodes a compact SD-JWT VC into the display map the held
// page expects (Subject / Issuer / ClaimedName / ValidUntil / VC). Selective-
// disclosure segments ("~<base64url([salt,name,value])>~…") are merged into
// Subject so recipients see the disclosed claims too. Returns nil for non-SD-JWT.
func parseSDJWTClaimedVC(vc string) map[string]any {
	payload := sdJWTPayload(vc)
	if payload == nil {
		return nil
	}
	out := map[string]any{"ID": vcID(vc)}
	subject := map[string]any{}
	for k, v := range payload {
		if sdJWTReserved[k] {
			continue
		}
		subject[k] = v
	}
	// Merge any disclosed claims (3-element [salt, name, value] disclosures).
	for _, d := range strings.Split(vc, "~")[1:] {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		db, err := b64uDecode(d)
		if err != nil {
			continue
		}
		var arr []any
		if json.Unmarshal(db, &arr) != nil || len(arr) != 3 {
			continue
		}
		if name, ok := arr[1].(string); ok {
			subject[name] = arr[2]
		}
	}
	if len(subject) > 0 {
		out["Subject"] = subject
	}
	if iss, ok := payload["iss"].(string); ok {
		out["Issuer"] = iss
	}
	if vct, ok := payload["vct"].(string); ok && vct != "" {
		name := vct
		if i := strings.LastIndexAny(vct, "/:#"); i >= 0 && i+1 < len(vct) {
			name = vct[i+1:]
		}
		out["ClaimedName"] = name
	}
	if exp, ok := payload["exp"].(float64); ok {
		out["ValidUntil"] = time.Unix(int64(exp), 0).UTC().Format(time.RFC3339)
	}
	out["Format"] = "vc+sd-jwt"
	// Show the decoded payload (readable JSON) followed by the compact token, so
	// the "Raw credential" block isn't an opaque eyJ… blob.
	vcText := vc
	if b, err := json.MarshalIndent(payload, "", "  "); err == nil {
		vcText = string(b) + "\n\n——— compact SD-JWT ———\n" + vc
	}
	out["VC"] = vcText
	return out
}

// heldClaims parses the session's persisted claimed VCs into display maps.
func heldClaims(sess *Session) []map[string]any {
	held := make([]map[string]any, 0, len(sess.InjiClaimedVCs))
	for _, vc := range sess.InjiClaimedVCs {
		held = append(held, parseClaimedVC(vc))
	}
	return held
}

// heldClaimsWithStatus is heldClaims augmented with each credential's LIVE
// revocation status — "active", "revoked", or "" — resolved against the
// issuer's published status list via the same signature-verifying cache the
// verifier uses. So the holder sees when a held credential has been revoked,
// not merely that it was claimed. "" means the credential carries no status
// pointer, or the list is unresolvable (non-Hub / unreachable).
func (h *H) heldClaimsWithStatus(ctx context.Context, sess *Session) []map[string]any {
	out := make([]map[string]any, 0, len(sess.InjiClaimedVCs))
	var check delegation.StatusChecker
	if h.StatusListCache != nil {
		check = h.delegationStatusChecker()
	}
	for _, vc := range sess.InjiClaimedVCs {
		m := parseClaimedVC(vc)
		m["RevStatus"] = ""
		// Presentable = can be presented over OID4VP to Inji Verify: an SD-JWT
		// whose holder binding key we retained (key-bound KB-JWT, F21), OR a W3C
		// ldp_vc (wrapped in an unsigned ldp_vp — no key needed, F23).
		_, haveKey := sess.InjiHolderKeys[vcID(vc)]
		m["Presentable"] = (haveKey && strings.Contains(vc, "~")) || injiIsW3C(vc)
		if check != nil {
			if creds := normalizeClaimedInjiCreds([]string{vc}); len(creds) > 0 {
				if ref, ok := delegation.StatusRefOf(creds[0]); ok {
					if revoked, err := check(ctx, ref); err == nil {
						if revoked {
							m["RevStatus"] = "revoked"
						} else {
							m["RevStatus"] = "active"
						}
					}
				}
			}
		}
		out = append(out, m)
	}
	return out
}

// injiHeldBody builds the held-credentials view model: the parsed credentials
// plus HasPair (≥2 presentable SD-JWT credentials, so the delegated-pair present
// control is offered). Shared by the page and the delete re-render.
func (h *H) injiHeldBody(ctx context.Context, sess *Session) map[string]any {
	held := h.heldClaimsWithStatus(ctx, sess)
	presentable := 0
	for _, m := range held {
		if p, _ := m["Presentable"].(bool); p {
			presentable++
		}
	}
	return map[string]any{"Held": held, "HasPair": presentable >= 2}
}

// ShowInjiHeld renders the holder's claimed credentials (persisted on the
// session), on a page separate from the available-to-claim catalog at
// /holder/wallet/inji.
func (h *H) ShowInjiHeld(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	h.render(w, r, "holder_inji_held", h.pageData(sess, h.injiHeldBody(r.Context(), sess)))
}

// DeleteInjiClaimed removes one credential from the in-app Inji wallet by its
// stable id, then re-renders the held list. The removal persists on the next
// session flush, so it stays gone across restarts.
func (h *H) DeleteInjiClaimed(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	id := r.PathValue("id")
	kept := make([]string, 0, len(sess.InjiClaimedVCs))
	for _, vc := range sess.InjiClaimedVCs {
		if vcID(vc) != id {
			kept = append(kept, vc)
		}
	}
	sess.InjiClaimedVCs = kept
	delete(sess.InjiHolderKeys, id) // drop the retained holder key with the credential
	if h.InjiWallet != nil {        // remove from the durable per-user wallet too
		_ = h.InjiWallet.Delete(sessionWalletKey(sess), id)
	}
	if len(kept) > 0 {
		sess.InjiClaimedVC = kept[0]
	} else {
		sess.InjiClaimedVC = ""
	}
	h.renderFragment(w, r, "fragment_inji_held_list", map[string]any{"Body": h.injiHeldBody(r.Context(), sess), "Lang": h.langFor(r)})
}
