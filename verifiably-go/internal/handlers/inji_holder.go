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
	"strings"
	"time"
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
	vc, err := h.injiClaimCredential(r.Context(), code, sess.PendingPKCE, credType, format, vcContext, vct)
	sess.PendingState, sess.PendingPKCE, sess.PendingProvider = "", "", ""
	if err != nil {
		msg := "Claim failed: " + err.Error()
		// Certify returns ERROR_FETCHING_DATA_RECORD_FROM_TABLE when the holder's
		// eSignet identity has no provisioned row for this credential's data.
		if strings.Contains(err.Error(), "DATA_RECORD") || strings.Contains(err.Error(), "FETCHING_DATA") {
			msg = "No claims are provisioned for your eSignet identity for this credential. " +
				"An issuer must provision your data first — onboard a holder at /issuer/onboard " +
				"(or POST /api/v1/subjects with your individualId), then sign in and claim again."
		}
		fail(msg)
		return
	}
	sess.InjiClaimedVC = vc
	sess.InjiClaimError = ""
	h.redirect(w, r, "/holder/wallet/inji")
}

// injiClaimCredential does token exchange (private_key_jwt) + holder proof +
// credential request, returning the issued VC as a JSON string.
func (h *H) injiClaimCredential(ctx context.Context, code, verifier, credType, format, vcContext, vct string) (string, error) {
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
	// Certify returns {"credential": {...VC...}} or the VC directly.
	var wrap struct {
		Credential json.RawMessage `json:"credential"`
	}
	if json.Unmarshal(body, &wrap) == nil && len(wrap.Credential) > 0 {
		return string(wrap.Credential), nil
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
	if sess.InjiClaimedVC != "" {
		var pretty any
		if json.Unmarshal([]byte(sess.InjiClaimedVC), &pretty) == nil {
			b, _ := json.MarshalIndent(pretty, "", "  ")
			body["VC"] = string(b)
			if m, ok := pretty.(map[string]any); ok {
				if cs, ok := m["credentialSubject"].(map[string]any); ok {
					body["Subject"] = cs
				}
			}
		} else {
			body["VC"] = sess.InjiClaimedVC
		}
	}
	h.render(w, r, "holder_inji", h.pageData(sess, body))
}
