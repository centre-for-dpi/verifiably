package handlers

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"html/template"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/internal/statuslistcache"
	"github.com/verifiably/verifiably-go/internal/storage/injiwallet"
)

// loadPageTemplate parses one templates/pages/<page>.html with the minimal
// FuncMap the content blocks touch (`t`, `list`). Renders go through
// render() with HX-Target=main so only content_<page> is executed (no layout).
func loadPageTemplate(t *testing.T, page string) *template.Template {
	t.Helper()
	tmpl := template.New("").Funcs(template.FuncMap{
		"t":    func(s string, _ ...any) string { return s },
		"list": func(args ...any) []any { return args },
	})
	if _, err := tmpl.ParseFiles("../../templates/pages/" + page + ".html"); err != nil {
		t.Fatalf("parse %s: %v", page, err)
	}
	return tmpl
}

// htmxMainRequest builds a GET request that render() treats as an HTMX swap of
// <main>, so it executes the content_<page> template directly.
func htmxMainRequest(method, path string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("HX-Request", "true")
	req.Header.Set("HX-Target", "main")
	return req
}

// ─── parseClaimedVC ────────────────────────────────────────────────────────────

func TestParseClaimedVC(t *testing.T) {
	t.Run("valid VC yields all display fields", func(t *testing.T) {
		vc := `{"type":["VerifiableCredential","PersonCredential"],"issuer":"did:web:issuer.example","validUntil":"2030-01-01T00:00:00Z","credentialSubject":{"fullName":"Grace Hopper","dob":"1906"}}`
		out := parseClaimedVC(vc)

		if out["ClaimedName"] != "PersonCredential" {
			t.Errorf("ClaimedName = %v, want PersonCredential", out["ClaimedName"])
		}
		if out["Issuer"] != "did:web:issuer.example" {
			t.Errorf("Issuer = %v", out["Issuer"])
		}
		if out["ValidUntil"] != "2030-01-01T00:00:00Z" {
			t.Errorf("ValidUntil = %v", out["ValidUntil"])
		}
		subj, ok := out["Subject"].(map[string]any)
		if !ok || subj["fullName"] != "Grace Hopper" {
			t.Errorf("Subject = %v", out["Subject"])
		}
		// VC is pretty-printed (indented) JSON.
		pretty, _ := out["VC"].(string)
		if !strings.Contains(pretty, "\n  ") {
			t.Errorf("VC should be indented JSON, got: %s", pretty)
		}
	})

	t.Run("type with only VerifiableCredential leaves ClaimedName unset", func(t *testing.T) {
		out := parseClaimedVC(`{"type":["VerifiableCredential"],"credentialSubject":{}}`)
		if _, ok := out["ClaimedName"]; ok {
			t.Errorf("ClaimedName should be unset, got %v", out["ClaimedName"])
		}
	})

	t.Run("malformed JSON returns just the raw VC", func(t *testing.T) {
		out := parseClaimedVC("this is not json{")
		if out["VC"] != "this is not json{" {
			t.Errorf("VC = %v, want the raw input", out["VC"])
		}
		if _, ok := out["Subject"]; ok {
			t.Error("Subject must not be present for malformed input")
		}
		if _, ok := out["ClaimedName"]; ok {
			t.Error("ClaimedName must not be present for malformed input")
		}
	})

	t.Run("non-object JSON (array) returns pretty VC only", func(t *testing.T) {
		out := parseClaimedVC(`[1,2,3]`)
		if _, ok := out["Subject"]; ok {
			t.Error("Subject must not be present for a non-object VC")
		}
		if _, ok := out["VC"].(string); !ok {
			t.Error("VC should still be set")
		}
	})
}

// ─── env-derived config helpers ────────────────────────────────────────────────

func TestInjiAuthcodeACR(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		t.Setenv("INJI_AUTHCODE_ACR", "")
		if got := injiAuthcodeACR(); got != "mosip:idp:acr:static-code" {
			t.Errorf("got %q, want mosip:idp:acr:static-code", got)
		}
	})
	t.Run("env override", func(t *testing.T) {
		t.Setenv("INJI_AUTHCODE_ACR", "mosip:idp:acr:generated-code")
		if got := injiAuthcodeACR(); got != "mosip:idp:acr:generated-code" {
			t.Errorf("got %q, want the override", got)
		}
	})
}

func TestEnvOr(t *testing.T) {
	t.Setenv("SOME_KEY", "")
	if got := envOr("SOME_KEY", "fallback"); got != "fallback" {
		t.Errorf("unset -> got %q, want fallback", got)
	}
	t.Setenv("SOME_KEY", "  spaced  ")
	if got := envOr("SOME_KEY", "fallback"); got != "spaced" {
		t.Errorf("set -> got %q, want trimmed 'spaced'", got)
	}
}

func TestInjiAuthcodeDefaults(t *testing.T) {
	for _, k := range []string{"INJI_AUTHCODE_CLIENT_ID", "INJI_AUTHCODE_CLIENT_KID", "INJI_AUTHCODE_SCOPE"} {
		t.Setenv(k, "")
	}
	if got := injiAuthcodeClientID(); got != "wallet-demo-client" {
		t.Errorf("clientID default = %q", got)
	}
	if got := injiAuthcodeKID(); got != "wallet-demo-client-kid" {
		t.Errorf("kid default = %q", got)
	}
	if got := injiAuthcodeScope(); got != "mock_identity_vc_ldp" {
		t.Errorf("scope default = %q", got)
	}
}

func TestInjiAuthcodeEnabled(t *testing.T) {
	t.Run("unset -> disabled", func(t *testing.T) {
		t.Setenv("INJI_AUTHCODE_CLIENT_KEY_PEM", "")
		if injiAuthcodeEnabled() {
			t.Error("want disabled when PEM unset")
		}
	})
	t.Run("set -> enabled", func(t *testing.T) {
		t.Setenv("INJI_AUTHCODE_CLIENT_KEY_PEM", "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----")
		if !injiAuthcodeEnabled() {
			t.Error("want enabled when PEM set")
		}
	})
}

// ─── ShowInjiHeld (render) ─────────────────────────────────────────────────────

func TestShowInjiHeld(t *testing.T) {
	store := NewStore()
	h := &H{Sessions: store, Templates: loadPageTemplate(t, "holder_inji_held")}

	// Seed a session with a claimed VC, then reuse its cookie on the real request.
	rr0 := httptest.NewRecorder()
	sess := store.MustGet(rr0, httptest.NewRequest(http.MethodGet, "/", nil))
	sess.InjiClaimedVCs = []string{
		`{"type":["VerifiableCredential","PersonCredential"],"credentialSubject":{"fullName":"Grace Hopper"}}`,
	}
	cookies := rr0.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no session cookie issued")
	}

	req := htmxMainRequest(http.MethodGet, "/holder/wallet/inji/credentials")
	req.AddCookie(cookies[0])
	rr := httptest.NewRecorder()
	h.ShowInjiHeld(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{"PersonCredential", "Grace Hopper", "CLAIMED"} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered held page missing %q\nbody=%s", want, body)
		}
	}
}

// TestShowInjiHeld_Empty renders the empty-state branch when the session has no
// claimed credentials.
func TestShowInjiHeld_Empty(t *testing.T) {
	h := &H{Sessions: NewStore(), Templates: loadPageTemplate(t, "holder_inji_held")}
	rr := httptest.NewRecorder()
	h.ShowInjiHeld(rr, htmxMainRequest(http.MethodGet, "/holder/wallet/inji/credentials"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	// NB: html/template escapes the apostrophe in "haven't", so match on a
	// substring that has none.
	if !strings.Contains(rr.Body.String(), "claimed any credentials") {
		t.Errorf("empty-state copy missing\nbody=%s", rr.Body.String())
	}
}

// ─── in-app Inji auth-code claim flow (coverage-B2) ───────────────────────────

// injiHolderRSAPEM returns a PKCS#8 PEM of a fresh 2048-bit RSA key (the
// wallet-demo-client key shape the deploy provides) plus the key itself.
func injiHolderRSAPEM(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// injiHolderTinyRSAPEM returns a PKCS#1 PEM of a deliberately insecure 12-bit
// RSA key: it parses, but crypto/rsa refuses to sign with it, which is the only
// way to make signRS256 fail without patching the crypto package.
func injiHolderTinyRSAPEM() (*rsa.PrivateKey, string) {
	k := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: big.NewInt(3233), E: 17}, D: big.NewInt(2753),
		Primes: []*big.Int{big.NewInt(61), big.NewInt(53)}}
	return k, string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
}

// injiHolderSDJWT builds a compact SD-JWT "header.payload.sig~disclosure…" from
// a payload map and pre-encoded disclosure segments.
func injiHolderSDJWT(t *testing.T, payload map[string]any, disclosures ...string) string {
	t.Helper()
	pb, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	tok := b64u([]byte(`{"alg":"ES256"}`)) + "." + b64u(pb) + ".sig"
	for _, d := range disclosures {
		tok += "~" + d
	}
	return tok
}

// injiHolderClaimEnv points the flow at two httptest servers: esignet (token
// endpoint) and certify (well-known + credential endpoint). certifyFn handles
// POST /v1/certify/issuance/credential; the well-known advertises issuer.example.
func injiHolderClaimEnv(t *testing.T, pemStr string, tokenBody string, certifyFn http.HandlerFunc) (esignet, certify *httptest.Server) {
	t.Helper()
	esignet = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/esignet/oauth/v2/token" || r.Method != http.MethodPost {
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, 404)
			return
		}
		if err := r.ParseForm(); err != nil || r.Form.Get("grant_type") != "authorization_code" ||
			r.Form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" ||
			r.Form.Get("client_assertion") == "" || r.Form.Get("code_verifier") == "" {
			http.Error(w, "bad token form", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(tokenBody))
	}))
	t.Cleanup(esignet.Close)
	certify = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/certify/.well-known/openid-credential-issuer":
			_, _ = w.Write([]byte(`{"credential_issuer":"https://issuer.example"}`))
		case r.URL.Path == "/v1/certify/issuance/credential" && r.Method == http.MethodPost:
			if r.Header.Get("Authorization") != "Bearer tok-1" {
				http.Error(w, "missing bearer", 401)
				return
			}
			certifyFn(w, r)
		default:
			http.Error(w, "unexpected "+r.URL.Path, 404)
		}
	}))
	t.Cleanup(certify.Close)
	t.Setenv("INJI_AUTHCODE_CLIENT_KEY_PEM", pemStr)
	t.Setenv("ESIGNET_BASE_URL", esignet.URL+"/")
	t.Setenv("INJI_CERTIFY_UPSTREAM_URL", certify.URL)
	t.Setenv("VERIFIABLY_PUBLIC_URL", "https://app.example/")
	return esignet, certify
}

// injiHolderSubjects is fakeSubjects with a CredentialClaimSpec that also
// returns a @context and vct (fakeSubjects leaves both empty).
type injiHolderSubjects struct {
	fakeSubjects
	vcContext, vct string
}

func (f *injiHolderSubjects) CredentialClaimSpec(ctx context.Context, key string) (string, string, string, error) {
	format, _, _, err := f.fakeSubjects.CredentialClaimSpec(ctx, key)
	return format, f.vcContext, f.vct, err
}

// injiHolderCredReq decodes the credential request Certify received.
func injiHolderCredReq(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		t.Fatalf("credential request body: %v", err)
	}
	return m
}

func TestEsignetBaseAndCallbackURL(t *testing.T) {
	t.Setenv("ESIGNET_BASE_URL", "https://esignet.example/")
	t.Setenv("VERIFIABLY_PUBLIC_URL", "https://app.example/")
	if got := esignetBase(); got != "https://esignet.example" {
		t.Errorf("esignetBase = %q", got)
	}
	if got := injiHolderCallbackURL(); got != "https://app.example/holder/wallet/inji/callback" {
		t.Errorf("callback = %q", got)
	}
}

func TestInjiAuthcodeClientKey(t *testing.T) {
	t.Run("not a PEM block", func(t *testing.T) {
		t.Setenv("INJI_AUTHCODE_CLIENT_KEY_PEM", "garbage")
		if _, err := injiAuthcodeClientKey(); err == nil || !strings.Contains(err.Error(), "not a PEM block") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("PKCS#8 RSA", func(t *testing.T) {
		key, pemStr := injiHolderRSAPEM(t)
		t.Setenv("INJI_AUTHCODE_CLIENT_KEY_PEM", pemStr)
		got, err := injiAuthcodeClientKey()
		if err != nil || got.N.Cmp(key.N) != 0 {
			t.Errorf("got %v, err %v", got, err)
		}
	})
	t.Run("PKCS#1 RSA fallback", func(t *testing.T) {
		key, _ := injiHolderRSAPEM(t)
		pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
		t.Setenv("INJI_AUTHCODE_CLIENT_KEY_PEM", pemStr)
		got, err := injiAuthcodeClientKey()
		if err != nil || got.N.Cmp(key.N) != 0 {
			t.Errorf("got %v, err %v", got, err)
		}
	})
	t.Run("neither PKCS#8 nor PKCS#1", func(t *testing.T) {
		t.Setenv("INJI_AUTHCODE_CLIENT_KEY_PEM", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}})))
		if _, err := injiAuthcodeClientKey(); err == nil || !strings.Contains(err.Error(), "parse client key") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("PKCS#8 EC key is not RSA", func(t *testing.T) {
		ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalPKCS8PrivateKey(ec)
		t.Setenv("INJI_AUTHCODE_CLIENT_KEY_PEM", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
		if _, err := injiAuthcodeClientKey(); err == nil || !strings.Contains(err.Error(), "not RSA") {
			t.Errorf("err = %v", err)
		}
	})
}

func TestPkceChallengeAndSignRS256(t *testing.T) {
	// RFC 7636 appendix B test vector.
	if got := pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Errorf("pkceChallenge = %q", got)
	}
	key, _ := injiHolderRSAPEM(t)
	jwt, err := signRS256(key, map[string]any{"alg": "RS256"}, map[string]any{"iss": "c"})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt = %q", jwt)
	}
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sig, _ := b64uDecode(parts[2])
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, h[:], sig); err != nil {
		t.Errorf("signature does not verify: %v", err)
	}
	if hdr, _ := b64uDecode(parts[0]); string(hdr) != `{"alg":"RS256"}` {
		t.Errorf("header = %s", hdr)
	}
	tiny, _ := injiHolderTinyRSAPEM()
	if _, err := signRS256(tiny, map[string]any{}, map[string]any{}); err == nil {
		t.Error("expected signing with a 12-bit key to fail")
	}
}

func TestStartInjiClaim(t *testing.T) {
	t.Run("not configured redirects with an error", func(t *testing.T) {
		t.Setenv("INJI_AUTHCODE_CLIENT_KEY_PEM", "")
		t.Setenv("ESIGNET_BASE_URL", "")
		h := &H{Sessions: NewStore()}
		req := httptest.NewRequest(http.MethodGet, "/holder/wallet/inji/start", nil)
		for _, c := range seedSession(t, h, nil) {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		h.StartInjiClaim(rr, req)
		if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/holder/wallet/inji" {
			t.Fatalf("got %d %q", rr.Code, rr.Header().Get("Location"))
		}
		if sess := sessionOf(h, req); !strings.Contains(sess.InjiClaimError, "not configured") {
			t.Errorf("InjiClaimError = %q", sess.InjiClaimError)
		}
	})
	t.Run("redirects to eSignet authorize with PKCE and the credential scope", func(t *testing.T) {
		_, pemStr := injiHolderRSAPEM(t)
		t.Setenv("INJI_AUTHCODE_CLIENT_KEY_PEM", pemStr)
		t.Setenv("ESIGNET_BASE_URL", "https://esignet.example")
		t.Setenv("VERIFIABLY_PUBLIC_URL", "https://app.example")
		t.Setenv("INJI_AUTHCODE_SCOPE", "")
		// Pre-load the ACR cache so injiAuthcodeACRValues never consults the
		// eSignet database through the docker socket.
		esignetResetCache(t)
		setESignetACRCache([]string{"mosip:idp:acr:generated-code"})
		subj := &fakeSubjects{scopeByKey: map[string]string{"diploma": "diploma_vc_ldp"}}
		h := &H{Sessions: NewStore(), Subjects: subj}
		cookies := seedSession(t, h, nil)
		for _, tc := range []struct{ cred, wantScope string }{
			{"diploma", "diploma_vc_ldp"},
			{"unknown", "mock_identity_vc_ldp"},
			{"", "mock_identity_vc_ldp"},
		} {
			req := httptest.NewRequest(http.MethodGet, "/holder/wallet/inji/start?cred="+tc.cred, nil)
			for _, c := range cookies {
				req.AddCookie(c)
			}
			rr := httptest.NewRecorder()
			h.StartInjiClaim(rr, req)
			if rr.Code != http.StatusFound {
				t.Fatalf("[%s] status %d", tc.cred, rr.Code)
			}
			loc, err := url.Parse(rr.Header().Get("Location"))
			if err != nil || loc.Host != "esignet.example" || loc.Path != "/authorize" {
				t.Fatalf("[%s] Location = %q (%v)", tc.cred, rr.Header().Get("Location"), err)
			}
			q := loc.Query()
			sess := sessionOf(h, req)
			if q.Get("scope") != tc.wantScope || q.Get("client_id") != "wallet-demo-client" ||
				q.Get("redirect_uri") != "https://app.example/holder/wallet/inji/callback" ||
				q.Get("acr_values") != "mosip:idp:acr:generated-code" || q.Get("code_challenge_method") != "S256" {
				t.Errorf("[%s] query = %v", tc.cred, q)
			}
			if q.Get("state") == "" || q.Get("state") != sess.PendingState || q.Get("code_challenge") != pkceChallenge(sess.PendingPKCE) ||
				sess.PendingProvider != "inji-authcode" || sess.InjiClaimCred != tc.cred {
				t.Errorf("[%s] session = %+v query = %v", tc.cred, sess, q)
			}
		}
	})
}

func TestInjiClaimCallback(t *testing.T) {
	const ldp = `{"@context":["https://www.w3.org/2018/credentials/v1"],"type":["VerifiableCredential","PersonCredential"],"issuer":"did:web:issuer.example","credentialSubject":{"fullName":"Alice Example"}}`
	newH := func(t *testing.T, subj SubjectProvisioner, mutate func(*Session)) (*H, []*http.Cookie) {
		t.Helper()
		h := &H{Sessions: NewStore(), Subjects: subj}
		cookies := seedSession(t, h, func(s *Session) {
			s.PendingState = "st"
			s.PendingPKCE = "verifier"
			s.PendingProvider = "inji-authcode"
			if mutate != nil {
				mutate(s)
			}
		})
		return h, cookies
	}
	call := func(h *H, path string, cookies []*http.Cookie, htmx bool) (*httptest.ResponseRecorder, *Session) {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if htmx {
			req.Header.Set("HX-Request", "true")
		}
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		h.InjiClaimCallback(rr, req)
		return rr, sessionOf(h, req)
	}
	wantFail := func(t *testing.T, rr *httptest.ResponseRecorder, sess *Session, msg string) {
		t.Helper()
		if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/holder/wallet/inji" {
			t.Fatalf("got %d %q", rr.Code, rr.Header().Get("Location"))
		}
		if !strings.Contains(sess.InjiClaimError, msg) || sess.InjiClaimedVC != "" {
			t.Errorf("InjiClaimError = %q, InjiClaimedVC = %q", sess.InjiClaimError, sess.InjiClaimedVC)
		}
	}

	t.Run("eSignet error", func(t *testing.T) {
		h, cookies := newH(t, nil, nil)
		rr, sess := call(h, "/cb?error=access_denied&error_description=user+cancelled", cookies, false)
		wantFail(t, rr, sess, "eSignet returned: access_denied user cancelled")
	})
	t.Run("missing code and state mismatch", func(t *testing.T) {
		h, cookies := newH(t, nil, nil)
		rr, sess := call(h, "/cb?state=st", cookies, false)
		wantFail(t, rr, sess, "Missing code or state mismatch")
		rr, sess = call(h, "/cb?code=c&state=other", cookies, false)
		wantFail(t, rr, sess, "Missing code or state mismatch")
	})
	t.Run("token exchange failure surfaces as Claim failed", func(t *testing.T) {
		_, pemStr := injiHolderRSAPEM(t)
		injiHolderClaimEnv(t, pemStr, `{"error":"invalid_grant","error_description":"bad code"}`, nil)
		h, cookies := newH(t, nil, nil)
		rr, sess := call(h, "/cb?code=c&state=st", cookies, false)
		wantFail(t, rr, sess, "Claim failed: token endpoint: invalid_grant bad code")
		if sess.PendingState != "" || sess.PendingPKCE != "" || sess.PendingProvider != "" {
			t.Errorf("pending state not cleared: %+v", sess)
		}
	})
	t.Run("no data record maps to the enrol hint", func(t *testing.T) {
		_, pemStr := injiHolderRSAPEM(t)
		injiHolderClaimEnv(t, pemStr, `{"access_token":"tok-1"}`, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"error":"ERROR_FETCHING_DATA_RECORD_FROM_TABLE"}`, 500)
		})
		h, cookies := newH(t, nil, nil)
		rr, sess := call(h, "/cb?code=c&state=st", cookies, false)
		wantFail(t, rr, sess, "No data was found for your eSignet identity")
	})
	t.Run("unsubstituted template markers are refused", func(t *testing.T) {
		_, pemStr := injiHolderRSAPEM(t)
		injiHolderClaimEnv(t, pemStr, `{"access_token":"tok-1"}`, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"credential":{"type":["VerifiableCredential"],"credentialSubject":{"name":"${full_name}"}}}`))
		})
		h, cookies := newH(t, nil, nil)
		rr, sess := call(h, "/cb?code=c&state=st", cookies, false)
		wantFail(t, rr, sess, "unfilled template fields")
	})
	t.Run("ldp_vc claim is stored on the session and in the wallet", func(t *testing.T) {
		_, pemStr := injiHolderRSAPEM(t)
		var gotReq map[string]any
		injiHolderClaimEnv(t, pemStr, `{"access_token":"tok-1","c_nonce":"n1"}`, func(w http.ResponseWriter, r *http.Request) {
			gotReq = injiHolderCredReq(t, r)
			_, _ = w.Write([]byte(`{"credential":` + ldp + `}`))
		})
		wallet, err := injiwallet.NewStore(filepath.Join(t.TempDir(), "wallet.json"), bytes.Repeat([]byte{7}, 32))
		if err != nil {
			t.Fatal(err)
		}
		subj := &injiHolderSubjects{fakeSubjects: fakeSubjects{formatByKey: map[string]string{"person": "ldp_vc"}}, vcContext: "https://www.w3.org/ns/credentials/v2"}
		h, cookies := newH(t, subj, func(s *Session) { s.InjiClaimCred = "person"; s.UserEmail = "holder@example.org" })
		h.InjiWallet = wallet
		rr, sess := call(h, "/cb?code=c&state=st", cookies, true)
		if rr.Code != http.StatusOK || rr.Header().Get("HX-Redirect") != "/holder/wallet/inji/credentials" {
			t.Fatalf("got %d %q (err=%q)", rr.Code, rr.Header().Get("HX-Redirect"), sess.InjiClaimError)
		}
		if sess.InjiClaimedVC != ldp || len(sess.InjiClaimedVCs) != 1 || sess.InjiClaimError != "" || len(sess.InjiHolderKeys) != 0 {
			t.Errorf("session = %+v", sess)
		}
		if held := wallet.List("holder@example.org"); len(held) != 1 || held[0].VC != ldp || held[0].VCID != vcID(ldp) || held[0].HolderKey == "" {
			t.Errorf("wallet = %+v", held)
		}
		if gotReq["format"] != "ldp_vc" || gotReq["credential_definition"] == nil {
			t.Errorf("credential request = %v", gotReq)
		}
		def := gotReq["credential_definition"].(map[string]any)
		if ts, _ := def["type"].([]any); len(ts) != 2 || ts[1] != "person" {
			t.Errorf("type = %v", def["type"])
		}
		if cx, _ := def["@context"].([]any); len(cx) != 1 || cx[0] != "https://www.w3.org/ns/credentials/v2" {
			t.Errorf("@context = %v", def["@context"])
		}
	})
	t.Run("SD-JWT claim retains the holder key", func(t *testing.T) {
		_, pemStr := injiHolderRSAPEM(t)
		sd := injiHolderSDJWT(t, map[string]any{"iss": "https://issuer.example", "vct": "urn:example:Person", "given_name": "Alice"}, b64u([]byte(`["s","age","30"]`)))
		injiHolderClaimEnv(t, pemStr, `{"access_token":"tok-1"}`, func(w http.ResponseWriter, r *http.Request) {
			req := injiHolderCredReq(t, r)
			// fakeSubjects.CredentialClaimSpec returns no vct, so the request carries an empty one.
			if req["format"] != "vc+sd-jwt" || req["vct"] != "" || req["credential_definition"] != nil {
				t.Errorf("credential request = %v", req)
			}
			_, _ = w.Write([]byte(`{"credential":"` + sd + `"}`))
		})
		subj := &fakeSubjects{formatByKey: map[string]string{"person": "vc+sd-jwt"}}
		h, cookies := newH(t, subj, func(s *Session) { s.InjiClaimCred = "person" })
		rr, sess := call(h, "/cb?code=c&state=st", cookies, false)
		if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/holder/wallet/inji/credentials" {
			t.Fatalf("got %d %q (err=%q)", rr.Code, rr.Header().Get("Location"), sess.InjiClaimError)
		}
		if sess.InjiClaimedVC != sd || !strings.Contains(sess.InjiHolderKeys[vcID(sd)], "PRIVATE KEY") {
			t.Errorf("session = %+v", sess)
		}
	})
}

func TestInjiClaimCredential(t *testing.T) {
	ctx := context.Background()
	t.Run("client key error", func(t *testing.T) {
		t.Setenv("INJI_AUTHCODE_CLIENT_KEY_PEM", "nope")
		if _, err := (&H{}).injiClaimCredential(ctx, "c", "v", "T", "ldp_vc", "ctx", "", nil); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("assertion signing error", func(t *testing.T) {
		_, pemStr := injiHolderTinyRSAPEM()
		t.Setenv("INJI_AUTHCODE_CLIENT_KEY_PEM", pemStr)
		t.Setenv("ESIGNET_BASE_URL", "http://127.0.0.1:1")
		if _, err := (&H{}).injiClaimCredential(ctx, "c", "v", "T", "ldp_vc", "ctx", "", nil); err == nil || strings.Contains(err.Error(), "token:") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("token endpoint unreachable", func(t *testing.T) {
		_, pemStr := injiHolderRSAPEM(t)
		t.Setenv("INJI_AUTHCODE_CLIENT_KEY_PEM", pemStr)
		t.Setenv("ESIGNET_BASE_URL", "http://127.0.0.1:1")
		if _, err := (&H{}).injiClaimCredential(ctx, "c", "v", "T", "ldp_vc", "ctx", "", nil); err == nil || !strings.HasPrefix(err.Error(), "token:") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("retries once with the c_nonce from a 400", func(t *testing.T) {
		_, pemStr := injiHolderRSAPEM(t)
		var nonces []string
		injiHolderClaimEnv(t, pemStr, `{"access_token":"tok-1"}`, func(w http.ResponseWriter, r *http.Request) {
			req := injiHolderCredReq(t, r)
			proof := req["proof"].(map[string]any)["jwt"].(string)
			claims := sdJWTPayload(proof)
			nonce, _ := claims["nonce"].(string)
			nonces = append(nonces, nonce)
			if claims["aud"] != "https://issuer.example" {
				t.Errorf("proof aud = %v", claims["aud"])
			}
			if nonce == "" {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"error":"invalid_proof","c_nonce":"fresh"}`))
				return
			}
			_, _ = w.Write([]byte(`{"credential":{"type":["VerifiableCredential"]}}`))
		})
		var keyPEM string
		vc, err := (&H{}).injiClaimCredential(ctx, "c", "v", "T", "ldp_vc", "ctx", "", &keyPEM)
		if err != nil || vc != `{"type":["VerifiableCredential"]}` {
			t.Fatalf("vc = %q err = %v", vc, err)
		}
		if len(nonces) != 2 || nonces[0] != "" || nonces[1] != "fresh" || !strings.Contains(keyPEM, "PRIVATE KEY") {
			t.Errorf("nonces = %v keyPEM = %q", nonces, keyPEM)
		}
	})
	t.Run("400 without c_nonce is an error", func(t *testing.T) {
		_, pemStr := injiHolderRSAPEM(t)
		injiHolderClaimEnv(t, pemStr, `{"access_token":"tok-1"}`, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"error":"invalid_request"}`, 400)
		})
		_, err := (&H{}).injiClaimCredential(ctx, "c", "v", "T", "ldp_vc", "ctx", "", nil)
		if err == nil || !strings.Contains(err.Error(), "credential endpoint 400: {\"error\":\"invalid_request\"}") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("retry still failing after the c_nonce", func(t *testing.T) {
		_, pemStr := injiHolderRSAPEM(t)
		injiHolderClaimEnv(t, pemStr, `{"access_token":"tok-1"}`, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"invalid_proof","c_nonce":"again"}`))
		})
		_, err := (&H{}).injiClaimCredential(ctx, "c", "v", "T", "ldp_vc", "ctx", "", nil)
		if err == nil || !strings.HasPrefix(err.Error(), "credential endpoint 400") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("retry transport failure", func(t *testing.T) {
		_, pemStr := injiHolderRSAPEM(t)
		calls := 0
		injiHolderClaimEnv(t, pemStr, `{"access_token":"tok-1"}`, func(w http.ResponseWriter, r *http.Request) {
			calls++
			if calls == 1 {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"c_nonce":"n2"}`))
				return
			}
			// Drop the connection so the client sees a transport error.
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
		})
		_, err := (&H{}).injiClaimCredential(ctx, "c", "v", "T", "ldp_vc", "ctx", "", nil)
		if err == nil || strings.HasPrefix(err.Error(), "credential endpoint") || calls != 2 {
			t.Fatalf("err = %v calls = %d", err, calls)
		}
	})
	t.Run("first request transport failure", func(t *testing.T) {
		_, pemStr := injiHolderRSAPEM(t)
		injiHolderClaimEnv(t, pemStr, `{"access_token":"tok-1"}`, nil)
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", "http://127.0.0.1:1")
		_, err := (&H{}).injiClaimCredential(ctx, "c", "v", "T", "vc+sd-jwt", "", "urn:x", nil)
		if err == nil || strings.HasPrefix(err.Error(), "credential endpoint") || strings.HasPrefix(err.Error(), "token") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("credential JSON string is unwrapped and non-JSON bodies pass through", func(t *testing.T) {
		_, pemStr := injiHolderRSAPEM(t)
		body := `{"credential":"eyJ.x.y~d~"}`
		injiHolderClaimEnv(t, pemStr, `{"access_token":"tok-1"}`, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(body))
		})
		vc, err := (&H{}).injiClaimCredential(ctx, "c", "v", "T", "dc+sd-jwt", "", "urn:x", nil)
		if err != nil || vc != "eyJ.x.y~d~" {
			t.Fatalf("vc = %q err = %v", vc, err)
		}
		body = `raw-not-json`
		vc, err = (&H{}).injiClaimCredential(ctx, "c", "v", "T", "ldp_vc", "ctx", "", nil)
		if err != nil || vc != "raw-not-json" {
			t.Fatalf("vc = %q err = %v", vc, err)
		}
	})
}

func TestInjiCredentialIssuer(t *testing.T) {
	ctx := context.Background()
	t.Run("well-known value", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/certify/.well-known/openid-credential-issuer" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(`{"credential_issuer":"https://issuer.example/certify"}`))
		}))
		defer srv.Close()
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", srv.URL)
		if got := injiCredentialIssuer(ctx); got != "https://issuer.example/certify" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("unreachable falls back to the upstream", func(t *testing.T) {
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", "http://127.0.0.1:1")
		if got := injiCredentialIssuer(ctx); got != "http://127.0.0.1:1" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("empty well-known falls back", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{}`)) }))
		defer srv.Close()
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", srv.URL)
		if got := injiCredentialIssuer(ctx); got != srv.URL {
			t.Errorf("got %q", got)
		}
	})
	t.Run("invalid upstream URL falls back", func(t *testing.T) {
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", "http://bad host")
		if got := injiCredentialIssuer(ctx); got != "http://bad host" {
			t.Errorf("got %q", got)
		}
	})
}

func TestPostFormAndPostJSON(t *testing.T) {
	ctx := context.Background()
	var out map[string]any
	if err := postForm(ctx, "http://bad host", url.Values{}, &out); err == nil {
		t.Error("postForm: expected request-build error")
	}
	if err := postForm(ctx, "http://127.0.0.1:1/", url.Values{}, &out); err == nil {
		t.Error("postForm: expected dial error")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.Form.Get("a") != "1" {
			http.Error(w, "bad form", 400)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	if err := postForm(ctx, srv.URL, url.Values{"a": {"1"}}, &out); err != nil || out["ok"] != true {
		t.Errorf("postForm: out=%v err=%v", out, err)
	}
	if _, _, err := postJSON(ctx, "http://bad host", nil, ""); err == nil {
		t.Error("postJSON: expected request-build error")
	}
	if _, _, err := postJSON(ctx, "http://127.0.0.1:1/", nil, ""); err == nil {
		t.Error("postJSON: expected dial error")
	}
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			http.Error(w, "unexpected auth", 400)
			return
		}
		w.WriteHeader(201)
		_, _ = w.Write([]byte("created"))
	}))
	defer srv2.Close()
	if st, b, err := postJSON(ctx, srv2.URL, []byte(`{}`), ""); err != nil || st != 201 || string(b) != "created" {
		t.Errorf("postJSON: %d %q %v", st, b, err)
	}
}

func TestShowInjiClaim(t *testing.T) {
	_, pemStr := injiHolderRSAPEM(t)
	t.Setenv("INJI_AUTHCODE_CLIENT_KEY_PEM", pemStr)
	t.Setenv("ESIGNET_BASE_URL", "https://esignet.example")
	subj := &fakeSubjects{listCreds: []map[string]string{{"key": "diploma", "displayName": "Diploma", "scope": "diploma_vc"}}}
	h := &H{Sessions: NewStore(), Subjects: subj, Templates: loadPageTemplates(t, "holder_inji")}
	cookies := seedSession(t, h, func(s *Session) {
		s.InjiClaimError = "boom happened"
		s.InjiClaimedVCs = []string{`{"a":1}`, `{"b":2}`}
	})
	req := htmxMainRequest(http.MethodGet, "/holder/wallet/inji")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	h.ShowInjiClaim(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{"boom happened", "Your credentials", "(2)", "Diploma", "/holder/wallet/inji/start?cred=diploma"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in\n%s", want, body)
		}
	}
	// Not configured and no catalog.
	t.Setenv("ESIGNET_BASE_URL", "")
	h2 := &H{Sessions: NewStore(), Subjects: &fakeSubjects{listCredsErr: errors.New("db down")}, Templates: loadPageTemplates(t, "holder_inji")}
	rr = httptest.NewRecorder()
	h2.ShowInjiClaim(rr, htmxMainRequest(http.MethodGet, "/holder/wallet/inji"))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "is not configured on this deployment") || strings.Contains(rr.Body.String(), "Diploma") {
		t.Errorf("status %d body %s", rr.Code, rr.Body.String())
	}
}

func TestB64uDecodeAndSDJWTPayload(t *testing.T) {
	if b, err := b64uDecode("YWJj"); err != nil || string(b) != "abc" {
		t.Errorf("unpadded: %q %v", b, err)
	}
	if b, err := b64uDecode("YQ=="); err != nil || string(b) != "a" {
		t.Errorf("padded: %q %v", b, err)
	}
	if _, err := b64uDecode("!!"); err == nil {
		t.Error("expected error for invalid input")
	}
	if sdJWTPayload("nodots") != nil {
		t.Error("single segment must be nil")
	}
	if sdJWTPayload("h.!!!.s") != nil {
		t.Error("undecodable payload must be nil")
	}
	if sdJWTPayload("h."+b64u([]byte("[1]"))+".s") != nil {
		t.Error("non-object payload must be nil")
	}
	if m := sdJWTPayload(injiHolderSDJWT(t, map[string]any{"iss": "x"}, "d1")); m == nil || m["iss"] != "x" {
		t.Errorf("payload = %v", m)
	}
}

func TestParseSDJWTClaimedVC(t *testing.T) {
	if parseSDJWTClaimedVC("not a token") != nil {
		t.Fatal("non SD-JWT must be nil")
	}
	disc := func(v any) string {
		b, _ := json.Marshal(v)
		return b64u(b)
	}
	payload := map[string]any{"iss": "https://issuer.example", "vct": "https://issuer.example/vct/Diploma", "exp": float64(1893456000),
		"_sd": []any{"h"}, "cnf": map[string]any{}, "degree": "BSc"}
	vc := injiHolderSDJWT(t, payload,
		disc([]any{"salt", "given_name", "Alice"}),
		"", "!!!",
		disc([]any{"salt", "only-two"}),
		disc([]any{"salt", 42, "not-a-name"}),
		disc(map[string]any{"x": 1}),
	)
	out := parseClaimedVC(vc)
	subj, _ := out["Subject"].(map[string]any)
	if subj["degree"] != "BSc" || subj["given_name"] != "Alice" || len(subj) != 2 {
		t.Errorf("Subject = %v", subj)
	}
	if out["Issuer"] != "https://issuer.example" || out["ClaimedName"] != "Diploma" || out["ValidUntil"] != "2030-01-01T00:00:00Z" || out["Format"] != "vc+sd-jwt" || out["ID"] != vcID(vc) {
		t.Errorf("out = %v", out)
	}
	if text, _ := out["VC"].(string); !strings.Contains(text, "compact SD-JWT") || !strings.HasSuffix(text, vc) {
		t.Errorf("VC = %q", text)
	}
	// vct without a separator keeps the whole value; trailing separator keeps it too; no subject claims → no Subject.
	for _, vct := range []string{"Diploma", "urn:x:"} {
		o := parseSDJWTClaimedVC(injiHolderSDJWT(t, map[string]any{"vct": vct, "iss": "i"}))
		if o["ClaimedName"] != vct {
			t.Errorf("vct %q → ClaimedName %v", vct, o["ClaimedName"])
		}
		if _, ok := o["Subject"]; ok {
			t.Errorf("vct %q → unexpected Subject %v", vct, o["Subject"])
		}
	}
}

func TestHeldClaimsWithStatus(t *testing.T) {
	const ldp = `{"type":["VerifiableCredential","PersonCredential"],"issuer":"did:web:issuer.example","credentialSubject":{"name":"A"},"credentialStatus":{"type":"BitstringStatusListEntry","statusListCredential":"https://issuer.example/status/1","statusListIndex":"5"}}`
	sd := injiHolderSDJWT(t, map[string]any{"iss": "i", "vct": "urn:x:Person", "status": map[string]any{"status_list": map[string]any{"uri": "https://issuer.example/status/2", "idx": float64(3)}}}, b64u([]byte(`["s","age","30"]`)))
	plain := `{"type":["VerifiableCredential"],"credentialSubject":{"x":"y"}}`
	sess := &Session{InjiClaimedVCs: []string{ldp, sd, plain, "garbage"}, InjiHolderKeys: map[string]string{vcID(sd): "pem"}}

	if got := heldClaims(sess); len(got) != 4 || got[0]["ClaimedName"] != "PersonCredential" || got[1]["ClaimedName"] != "Person" {
		t.Fatalf("heldClaims = %v", got)
	}

	t.Run("no cache: presentable flags only", func(t *testing.T) {
		got := (&H{}).heldClaimsWithStatus(context.Background(), sess)
		for i, want := range []bool{true, true, true, false} {
			if got[i]["Presentable"] != want || got[i]["RevStatus"] != "" {
				t.Errorf("[%d] = %v", i, got[i])
			}
		}
	})
	t.Run("revoked / active / lookup error", func(t *testing.T) {
		cache := &pubVerifySLCache{res: statuslistcache.Result{RawJWT: delegBitstringDoc(t, 5)}}
		got := (&H{StatusListCache: cache}).heldClaimsWithStatus(context.Background(), sess)
		// ldp: bit 5 set → revoked; sd: TokenStatusList decode of a bitstring doc fails → ""; plain: no ref → "".
		if got[0]["RevStatus"] != "revoked" || got[1]["RevStatus"] != "" || got[2]["RevStatus"] != "" || got[3]["RevStatus"] != "" {
			t.Errorf("got = %v", got)
		}
		if len(cache.urls) != 2 || cache.urls[0] != "https://issuer.example/status/1" {
			t.Errorf("urls = %v", cache.urls)
		}
		cache = &pubVerifySLCache{res: statuslistcache.Result{RawJWT: delegBitstringDoc(t, 9)}}
		got = (&H{StatusListCache: cache}).heldClaimsWithStatus(context.Background(), sess)
		if got[0]["RevStatus"] != "active" {
			t.Errorf("got = %v", got[0])
		}
	})
}

func TestDeleteInjiClaimed(t *testing.T) {
	vcA := `{"type":["VerifiableCredential","A"],"credentialSubject":{"n":"a"}}`
	vcB := `{"type":["VerifiableCredential","B"],"credentialSubject":{"n":"b"}}`
	wallet, err := injiwallet.NewStore(filepath.Join(t.TempDir(), "w.json"), bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := wallet.Add("holder@example.org", injiwallet.HeldCred{VCID: vcID(vcA), VC: vcA}); err != nil {
		t.Fatal(err)
	}
	h := &H{Sessions: NewStore(), Templates: loadPageTemplates(t, "holder_inji_held"), InjiWallet: wallet}
	cookies := seedSession(t, h, func(s *Session) {
		s.UserEmail = "holder@example.org"
		s.InjiClaimedVCs = []string{vcA, vcB}
		s.InjiClaimedVC = vcA
		s.InjiHolderKeys = map[string]string{vcID(vcA): "pem"}
	})
	del := func(id string) (*httptest.ResponseRecorder, *Session) {
		req := httptest.NewRequest(http.MethodDelete, "/holder/wallet/inji/credentials/"+id, nil)
		req.SetPathValue("id", id)
		req.Header.Set("HX-Request", "true")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		h.DeleteInjiClaimed(rr, req)
		return rr, sessionOf(h, req)
	}
	rr, sess := del(vcID(vcA))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), ">B<") || strings.Contains(rr.Body.String(), ">A<") {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	if len(sess.InjiClaimedVCs) != 1 || sess.InjiClaimedVC != vcB || len(sess.InjiHolderKeys) != 0 || len(wallet.List("holder@example.org")) != 0 {
		t.Errorf("session = %+v wallet = %v", sess, wallet.List("holder@example.org"))
	}
	h.InjiWallet = nil
	rr, sess = del(vcID(vcB))
	if rr.Code != http.StatusOK || len(sess.InjiClaimedVCs) != 0 || sess.InjiClaimedVC != "" || !strings.Contains(rr.Body.String(), "claimed any credentials") {
		t.Errorf("status %d session %+v body %s", rr.Code, sess, rr.Body.String())
	}
}
