package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/issuance"
	"github.com/verifiably/verifiably-go/internal/statuslist"
)

// loadTestTemplates parses templates/pages/issuer_issued_log.html so
// RevokeIssuedCredential's fragment swap (fragment_issued_credentials_row) can
// render the row in this test. The issued-log fragments live in that file since
// the My Credentials / issued-log split (issuer_credentials.html is now the
// former). Keeps a tiny FuncMap shim with just the helpers that template touches
// (`list`, `t`); the production funcMap in cmd/server/main.go has a much
// larger surface but those helpers aren't reached on this code path.
func loadTestTemplates(t *testing.T) *template.Template {
	t.Helper()
	tmpl := template.New("").Funcs(template.FuncMap{
		"list": func(args ...any) []any { return args },
		"t":    func(s string, _ ...any) string { return s },
	})
	files, err := filepath.Glob("../../templates/pages/issuer_issued_log.html")
	if err != nil || len(files) == 0 {
		t.Fatalf("locate issuer_issued_log.html: err=%v files=%v", err, files)
	}
	if _, err := tmpl.ParseFiles(files...); err != nil {
		t.Fatalf("parse template: %v", err)
	}
	return tmpl
}

// fakeSigningAdapter is the minimum implementation of the
// signingKeyAdapter interface used by the status-list HTTP path. The
// other backend.Adapter methods aren't reached on this code path, so we
// only need to satisfy IssuerSigningKey + provide a stable key for two
// successive publish calls (so a verifier-style consumer can compare the
// state of the bit before vs after a Revoke).
type fakeSigningAdapter struct {
	priv *ecdsa.PrivateKey
}

// IssuerSigningKey emits the JWK envelope walt.id would produce on
// /onboard/issuer. The status-list code path goes through
// statuslist.ParseWaltidIssuerKey, which accepts both the {"type":"jwk",
// "jwk":{...}} envelope and a bare JWK; we use the envelope shape because
// that's what production walt.id v0.18.2 returns.
func (f fakeSigningAdapter) IssuerSigningKey(_ context.Context) ([]byte, string, error) {
	jwk := map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(f.priv.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(f.priv.Y.Bytes()),
		"d":   base64.RawURLEncoding.EncodeToString(f.priv.D.Bytes()),
		"kid": "e2e-test-key",
	}
	jwkB, _ := json.Marshal(jwk)
	env, _ := json.Marshal(map[string]any{"type": "jwk", "jwk": json.RawMessage(jwkB)})
	return env, "did:test:e2e-issuer", nil
}

// To satisfy the embedded backend.Adapter interface for compile, but the
// HTTP routes we exercise here never reach these methods. The struct
// embeds a nil interface; any unintended method call would panic with a
// clear nil-pointer trace.
type fakeAdapter struct {
	fakeSigningAdapter
	backend.Adapter
}

// decodeBitstringJWT extracts the encoded bitstring from a published
// status-list JWT and returns it as a *statuslist.Bitstring so the test
// can assert which bits are revoked.
func decodeBitstringJWT(t *testing.T, key *statuslist.SigningKey, jwt string, size int) *statuslist.Bitstring {
	t.Helper()
	payload, err := key.VerifyES256(jwt)
	if err != nil {
		t.Fatalf("verify bitstring JWT: %v", err)
	}
	var p struct {
		VC map[string]any `json:"vc"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		t.Fatalf("parse bitstring JWT payload: %v", err)
	}
	cs, _ := p.VC["credentialSubject"].(map[string]any)
	encoded, _ := cs["encodedList"].(string)
	if encoded == "" {
		t.Fatalf("bitstring JWT missing encodedList: %+v", p)
	}
	// W3C BSL 2023 §5.1: encodedList is multibase. Strip the 'u' prefix
	// (base64url no padding alphabet identifier) before decoding.
	if !strings.HasPrefix(encoded, "u") {
		t.Fatalf("bitstring JWT encodedList missing multibase 'u' prefix")
	}
	bs, err := statuslist.DecodeGzipBase64URL(encoded[1:], size)
	if err != nil {
		t.Fatalf("decode bitstring: %v", err)
	}
	return bs
}

func decodeTokenJWT(t *testing.T, key *statuslist.SigningKey, jwt string, size int) *statuslist.Bitstring {
	t.Helper()
	payload, err := key.VerifyES256(jwt)
	if err != nil {
		t.Fatalf("verify token JWT: %v", err)
	}
	var p struct {
		StatusList map[string]any `json:"status_list"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		t.Fatalf("parse token JWT payload: %v", err)
	}
	encoded, _ := p.StatusList["lst"].(string)
	if encoded == "" {
		t.Fatalf("token JWT missing lst: %+v", p)
	}
	bs, err := statuslist.DecodeZlibBase64URL(encoded, size)
	if err != nil {
		t.Fatalf("decode token list: %v", err)
	}
	return bs
}

// TestStatusListE2E walks the full revocation lifecycle for both formats
// over real HTTP routes. For each format:
//
//  1. Allocate an index from the Store (simulating what the issuance
//     handler does inline before calling walt.id).
//  2. Append an IssuedCredential to the audit log with that binding.
//  3. GET /status-list/<kind>/v1 — verify, decode, assert bit is 0.
//  4. POST /issuer/credentials/{id}/revoke.
//  5. GET /status-list/<kind>/v1 again — assert the bit is now 1.
//
// This is the scenario a downstream verifier would walk: fetch the list,
// see "active", then later fetch again and see "revoked". It exercises
// every new code path end to end (issuance log, statuslist Store,
// signing key resolution, public HTTP routes, revocation HTTP route).
func TestStatusListE2E(t *testing.T) {
	dir := t.TempDir()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	logger, err := issuance.NewLog(filepath.Join(dir, "issued.json"))
	if err != nil {
		t.Fatal(err)
	}
	bs, err := statuslist.NewStore("bitstring", "v1",
		filepath.Join(dir, "bs.json"),
		"https://issuer.test/status-list/bitstring/v1")
	if err != nil {
		t.Fatal(err)
	}
	tk, err := statuslist.NewStore("token", "v1",
		filepath.Join(dir, "tk.json"),
		"https://issuer.test/status-list/token/v1")
	if err != nil {
		t.Fatal(err)
	}

	h := &H{
		Adapter:        fakeAdapter{fakeSigningAdapter: fakeSigningAdapter{priv: priv}},
		Sessions:       NewStore(),
		Templates:      loadTestTemplates(t),
		IssuanceLog:    logger,
		BitstringStore: bs,
		TokenStore:     tk,
	}

	// Mount the routes the test exercises. We only need a subset here —
	// the production wiring in cmd/server/main.go does the same, so this
	// keeps the test independent of route order changes there.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status-list/bitstring/{id}", h.PublishBitstringStatusList)
	mux.HandleFunc("GET /status-list/token/{id}", h.PublishTokenStatusList)
	mux.HandleFunc("POST /issuer/credentials/{id}/revoke", h.RevokeIssuedCredential)
	// Test-only prime endpoint — the status-list publishers don't touch
	// the session store, so we need a route that does to mint the
	// session cookie the cookie jar carries into the revoke POST.
	mux.HandleFunc("GET /test/prime", func(w http.ResponseWriter, r *http.Request) {
		_ = h.Sessions.MustGet(w, r)
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Drive the test with a cookie jar so the issuer-scoped session
	// stays stable across the GET → POST → GET calls below. Without it
	// every request gets a fresh sess.ID and sessionOwnerKey returns a
	// different "session-<id>" each time, so RevokeIssuedCredential's
	// owner-check fails (the appended record's OwnerKey is bound to
	// the first session, the revoke comes in under a different one).
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// Pre-resolve the parsed signing key once so the assertions below can
	// verify the JWT signatures.
	key, err := statuslist.ParseWaltidIssuerKey(envelope(t, priv), "did:test:e2e-issuer")
	if err != nil {
		t.Fatalf("ParseWaltidIssuerKey: %v", err)
	}

	cases := []struct {
		name     string
		std      string
		store    *statuslist.Store
		decoder  func(*testing.T, *statuslist.SigningKey, string, int) *statuslist.Bitstring
		fetchURL string
	}{
		{"bitstring", "w3c_vcdm_2", bs, decodeBitstringJWT, srv.URL + "/status-list/bitstring/v1"},
		{"token", "sd_jwt_vc (IETF)", tk, decodeTokenJWT, srv.URL + "/status-list/token/v1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 0. Prime the session cookie via the test-only /test/prime
			//    route which runs Sessions.MustGet. The cookie jar
			//    captures the verifiably_session cookie for later
			//    POSTs, and we read its value out to compute the same
			//    owner key the revoke handler will derive when our
			//    cookie comes back in.
			primeResp, err := client.Get(srv.URL + "/test/prime")
			if err != nil {
				t.Fatalf("prime session: %v", err)
			}
			_ = primeResp.Body.Close()
			u, _ := url.Parse(srv.URL)
			var sid string
			for _, ck := range jar.Cookies(u) {
				if ck.Name == "verifiably_session" {
					sid = ck.Value
					break
				}
			}
			if sid == "" {
				t.Fatalf("session cookie not minted on prime GET")
			}
			// Mirror sessionOwnerKey's fallback path: no AuthProvider/
			// UserSubject/UserEmail in this test, so the owner key is
			// "session-<sid>".
			testOwner := "session-" + sid

			// 1. Allocate (mimics what the issuance handler does inline).
			idx, err := tc.store.Allocate()
			if err != nil {
				t.Fatalf("allocate: %v", err)
			}
			// 2. Record an issued credential pointing at that bit. Stamp
			//    OwnerKey to match the session so the owner-scoped revoke
			//    succeeds. Without this the new owner check rejects the
			//    revoke as 404 not-found.
			recID := "vc-test-" + tc.name
			if _, err := logger.Append(issuance.IssuedCredential{
				ID:         recID,
				SchemaID:   "schema-" + tc.name,
				SchemaName: "Test " + tc.name,
				Std:        tc.std,
				Format:     tc.name,
				IssuerDpg:  "Walt Community Stack",
				OwnerKey:   testOwner,
				HolderHint: "Test Holder",
				StatusList: &issuance.StatusListEntry{
					Type:   tc.store.GetKind(),
					ListID: tc.store.GetListID(),
					Index:  idx,
				},
			}); err != nil {
				t.Fatalf("append: %v", err)
			}

			// 3. Verifier-style fetch: GET the published list, decode, check bit==0.
			body := httpGet(t, tc.fetchURL)
			before := tc.decoder(t, key, body, tc.store.Size())
			if before.Get(idx) {
				t.Fatalf("[%s] before revoke: bit %d should be 0", tc.name, idx)
			}

			// 4. Operator action: POST the revoke route via the SAME
			//    cookie jar so the session id (and hence owner key)
			//    matches what we stamped on the appended record.
			revokeURL := srv.URL + "/issuer/credentials/" + recID + "/revoke"
			req, err := http.NewRequest(http.MethodPost, revokeURL, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("revoke: %v", err)
			}
			respBody, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("[%s] revoke status: %d body=%s", tc.name, resp.StatusCode, string(respBody))
			}
			// The fragment swap should mention "revoked" since the row template
			// renders the new status pill.
			if !strings.Contains(string(respBody), "revoked") {
				t.Fatalf("[%s] revoke fragment missing 'revoked' marker: %s", tc.name, string(respBody))
			}

			// 5. Verifier re-fetches: bit should now be 1.
			body = httpGet(t, tc.fetchURL)
			after := tc.decoder(t, key, body, tc.store.Size())
			if !after.Get(idx) {
				t.Fatalf("[%s] after revoke: bit %d should be 1", tc.name, idx)
			}

			// 6. The next allocation must give a fresh index — Revoke must not
			//    have mutated nextFree.
			next, err := tc.store.Allocate()
			if err != nil {
				t.Fatalf("post-revoke allocate: %v", err)
			}
			if next <= idx {
				t.Fatalf("[%s] next index %d should be > %d", tc.name, next, idx)
			}
			if tc.store.IsRevoked(next) {
				t.Fatalf("[%s] freshly allocated bit %d must not be revoked", tc.name, next)
			}

			// 7. The audit log must reflect the revocation timestamp.
			rec, ok := logger.Get(recID)
			if !ok || rec.RevokedAt == nil {
				t.Fatalf("[%s] log entry should be marked revoked: %+v", tc.name, rec)
			}
		})
	}
}

// envelope serializes priv as a walt.id-style JWK envelope, mirroring
// what fakeSigningAdapter.IssuerSigningKey returns. We need a separate
// helper because the test's verification path also has to parse the
// envelope, and copying the bytes between two functions would risk drift.
func envelope(t *testing.T, priv *ecdsa.PrivateKey) []byte {
	t.Helper()
	jwk := map[string]string{
		"kty": "EC", "crv": "P-256", "kid": "e2e-test-key",
		"x": base64.RawURLEncoding.EncodeToString(priv.X.Bytes()),
		"y": base64.RawURLEncoding.EncodeToString(priv.Y.Bytes()),
		"d": base64.RawURLEncoding.EncodeToString(priv.D.Bytes()),
	}
	jwkB, _ := json.Marshal(jwk)
	env, _ := json.Marshal(map[string]any{"type": "jwk", "jwk": json.RawMessage(jwkB)})
	return env
}

// httpGet does a 200-or-fail GET. Status-list endpoints return 200 with
// the JWT body; anything else surfaces the error directly.
func httpGet(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d body=%s", url, resp.StatusCode, string(body))
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "+jwt") {
		t.Fatalf("GET %s: expected +jwt content-type, got %q", url, ct)
	}
	return string(body)
}
