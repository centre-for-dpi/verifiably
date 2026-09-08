package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/verifiably/verifiably-go/internal/injidid"
)

// didDocWith builds a minimal did.json doc whose assertionMethod/authentication
// are the BARE did (the shape Inji's upstream did.json emits) plus one VM per id.
func didDocWith(vmIDs ...string) map[string]any {
	methods := make([]any, 0, len(vmIDs))
	for _, id := range vmIDs {
		methods = append(methods, map[string]any{
			"id":                 id,
			"type":               "Ed25519VerificationKey2020",
			"controller":         "did:web:ex",
			"publicKeyMultibase": "z6MkExampleKeyMaterial",
			"@context":           "https://w3id.org/security/suites/ed25519-2020/v1",
		})
	}
	return map[string]any{
		"id":                 "did:web:ex",
		"assertionMethod":    []any{"did:web:ex"}, // bare DID — upstream form
		"authentication":     []any{"did:web:ex"},
		"verificationMethod": methods,
	}
}

func asStrings(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// patchedDidDoc must rewrite the bare-DID assertionMethod/authentication to the
// FULL verification-method id (did#kid) so strict verifiers accept the proof.
func TestPatchedDidDoc_NormalizesRelationshipsToFullVMIDs(t *testing.T) {
	doc := didDocWith("did:web:ex#k1")
	patchedDidDoc(doc, nil)
	want := []string{"did:web:ex#k1"}
	if got := asStrings(doc["assertionMethod"]); !reflect.DeepEqual(got, want) {
		t.Errorf("assertionMethod = %v, want %v", got, want)
	}
	if got := asStrings(doc["authentication"]); !reflect.DeepEqual(got, want) {
		t.Errorf("authentication = %v, want %v", got, want)
	}
}

// Extra observed kids are cloned into verificationMethod and surfaced in the
// relationships.
func TestPatchedDidDoc_ClonesExtraKids(t *testing.T) {
	doc := didDocWith("did:web:ex#k1")
	patchedDidDoc(doc, []string{"k2"})
	vms, _ := doc["verificationMethod"].([]any)
	if len(vms) != 2 {
		t.Fatalf("verificationMethod len = %d, want 2", len(vms))
	}
	clone, _ := vms[1].(map[string]any)
	if clone["id"] != "did:web:ex#k2" {
		t.Errorf("clone id = %v, want did:web:ex#k2", clone["id"])
	}
	if clone["publicKeyMultibase"] != "z6MkExampleKeyMaterial" {
		t.Error("clone did not copy the template key material")
	}
	want := []string{"did:web:ex#k1", "did:web:ex#k2"}
	if got := asStrings(doc["assertionMethod"]); !reflect.DeepEqual(got, want) {
		t.Errorf("assertionMethod = %v, want %v", got, want)
	}
}

// Already-present kids are not duplicated.
func TestPatchedDidDoc_DedupesExistingKid(t *testing.T) {
	doc := didDocWith("did:web:ex#k1")
	patchedDidDoc(doc, []string{"k1"})
	if vms, _ := doc["verificationMethod"].([]any); len(vms) != 1 {
		t.Errorf("verificationMethod len = %d, want 1 (no dup)", len(vms))
	}
}

// No verification methods → early return, relationships untouched (not added).
func TestPatchedDidDoc_NoVerificationMethodsNoop(t *testing.T) {
	doc := map[string]any{"id": "did:web:ex", "verificationMethod": []any{}}
	patchedDidDoc(doc, []string{"k1"})
	if _, ok := doc["assertionMethod"]; ok {
		t.Error("assertionMethod should not be synthesised when there are no VMs")
	}
}

// Running twice is stable.
func TestPatchedDidDoc_Idempotent(t *testing.T) {
	doc := didDocWith("did:web:ex#k1")
	patchedDidDoc(doc, nil)
	first := asStrings(doc["assertionMethod"])
	patchedDidDoc(doc, nil)
	if got := asStrings(doc["assertionMethod"]); !reflect.DeepEqual(got, first) {
		t.Errorf("not idempotent: %v vs %v", got, first)
	}
}

// ─── upstream resolution ───────────────────────────────────────────────────────

func TestInjiCertifyUpstream_EnvAndDefault(t *testing.T) {
	t.Setenv("INJI_CERTIFY_UPSTREAM_URL", "")
	if got := injiCertifyUpstream(); got != "http://inji-certify:8090" {
		t.Errorf("default = %q", got)
	}
	t.Setenv("INJI_CERTIFY_UPSTREAM_URL", "http://certify.example:8090///")
	if got := injiCertifyUpstream(); got != "http://certify.example:8090" {
		t.Errorf("env (trailing slashes trimmed) = %q", got)
	}
}

func TestInjiCertifyPreauthUpstream_EnvAndDefault(t *testing.T) {
	t.Setenv("INJI_CERTIFY_PREAUTH_UPSTREAM_URL", "")
	if got := injiCertifyPreauthUpstream(); got != "http://inji-certify-preauth-backend:8090" {
		t.Errorf("default = %q", got)
	}
	t.Setenv("INJI_CERTIFY_PREAUTH_UPSTREAM_URL", "http://preauth.example/")
	if got := injiCertifyPreauthUpstream(); got != "http://preauth.example" {
		t.Errorf("env = %q", got)
	}
}

// proxyErrReader fails on the first Read so InjiProxyCredential's body-read
// error branch is reachable.
type proxyErrReader struct{}

func (proxyErrReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

// proxyUpstream records the last request the proxy forwarded and serves the
// configured response.
type proxyUpstream struct {
	method, path, ctype, auth, body string
	status                          int
	respCT, resp                    string
}

func (u *proxyUpstream) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		u.method, u.path, u.ctype, u.auth, u.body = r.Method, r.URL.Path, r.Header.Get("Content-Type"), r.Header.Get("Authorization"), string(b)
		if u.respCT != "" {
			w.Header().Set("Content-Type", u.respCT)
		}
		if u.status != 0 {
			w.WriteHeader(u.status)
		}
		_, _ = io.WriteString(w, u.resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ─── InjiProxyCredential ───────────────────────────────────────────────────────

func TestInjiProxyCredential(t *testing.T) {
	t.Run("forwards body with injected @context, headers and remembers the signing kid", func(t *testing.T) {
		up := &proxyUpstream{respCT: "application/json", resp: `{"credential":{"proof":{"verificationMethod":"did:web:issuer.example#proxy-kid-1"}}}`}
		srv := up.start(t)
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", srv.URL)

		req := httptest.NewRequest(http.MethodPost, "/inji-proxy/issuance/credential",
			strings.NewReader(`{"format":"ldp_vc","credential_definition":{"type":["VerifiableCredential"]}}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer tok")
		rr := httptest.NewRecorder()
		(&H{}).InjiProxyCredential(rr, req)

		if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("status=%d ct=%q", rr.Code, rr.Header().Get("Content-Type"))
		}
		if !strings.Contains(rr.Body.String(), "proxy-kid-1") {
			t.Errorf("upstream body not relayed: %s", rr.Body.String())
		}
		if up.method != http.MethodPost || up.path != "/v1/certify/issuance/credential" {
			t.Errorf("forwarded %s %s", up.method, up.path)
		}
		if up.ctype != "application/json" || up.auth != "Bearer tok" {
			t.Errorf("headers not forwarded: ct=%q auth=%q", up.ctype, up.auth)
		}
		if !strings.Contains(up.body, `"@context":["https://www.w3.org/ns/credentials/v2"]`) {
			t.Errorf("@context not injected into forwarded body: %s", up.body)
		}
		found := false
		for _, k := range injidid.Primary.Snapshot() {
			if k == "proxy-kid-1" {
				found = true
			}
		}
		if !found {
			t.Errorf("primary observer did not remember the kid: %v", injidid.Primary.Snapshot())
		}
	})

	t.Run("upstream 4xx is relayed as-is and not remembered", func(t *testing.T) {
		up := &proxyUpstream{status: 400, resp: `{"proof":{"verificationMethod":"did:web:x#never-remembered"}}`}
		srv := up.start(t)
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", srv.URL)
		req := httptest.NewRequest(http.MethodPost, "/inji-proxy/issuance/credential", strings.NewReader(`not json`))
		rr := httptest.NewRecorder()
		(&H{}).InjiProxyCredential(rr, req)
		if rr.Code != 400 || !strings.Contains(rr.Body.String(), "never-remembered") {
			t.Errorf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		if up.body != "not json" || up.ctype != "" || up.auth != "" {
			t.Errorf("non-JSON body must pass through unchanged without synthesised headers: body=%q ct=%q auth=%q", up.body, up.ctype, up.auth)
		}
		for _, k := range injidid.Primary.Snapshot() {
			if k == "never-remembered" {
				t.Error("error response must not feed the observer")
			}
		}
	})

	t.Run("body read error -> 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/inji-proxy/issuance/credential", proxyErrReader{})
		rr := httptest.NewRecorder()
		(&H{}).InjiProxyCredential(rr, req)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "read body: boom") {
			t.Errorf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("unparseable upstream URL -> 500", func(t *testing.T) {
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", "http://bad host")
		req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{}`))
		rr := httptest.NewRecorder()
		(&H{}).InjiProxyCredential(rr, req)
		if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "build upstream request") {
			t.Errorf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("unreachable upstream -> 502", func(t *testing.T) {
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", "http://127.0.0.1:1")
		req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{}`))
		rr := httptest.NewRecorder()
		(&H{}).InjiProxyCredential(rr, req)
		if rr.Code != http.StatusBadGateway || !strings.HasPrefix(rr.Body.String(), "upstream: ") {
			t.Errorf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
}

// ─── InjiProxyStatusList ───────────────────────────────────────────────────────

func TestInjiProxyStatusList(t *testing.T) {
	t.Run("missing id -> 400", func(t *testing.T) {
		rr := httptest.NewRecorder()
		(&H{}).InjiProxyStatusList(rr, httptest.NewRequest(http.MethodGet, "/inji-proxy/status-list/", nil))
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "missing id") {
			t.Errorf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("forwards GET and remembers kid on success", func(t *testing.T) {
		up := &proxyUpstream{respCT: "application/ld+json", resp: `{"proof":{"verificationMethod":"did:web:issuer.example#status-kid"}}`}
		srv := up.start(t)
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", srv.URL)
		req := httptest.NewRequest(http.MethodGet, "/inji-proxy/status-list/list-7", nil)
		req.SetPathValue("id", "list-7")
		rr := httptest.NewRecorder()
		(&H{}).InjiProxyStatusList(rr, req)
		if rr.Code != 200 || rr.Header().Get("Content-Type") != "application/ld+json" || !strings.Contains(rr.Body.String(), "status-kid") {
			t.Errorf("status=%d ct=%q body=%s", rr.Code, rr.Header().Get("Content-Type"), rr.Body.String())
		}
		if up.method != http.MethodGet || up.path != "/v1/certify/credentials/status-list/list-7" {
			t.Errorf("forwarded %s %s", up.method, up.path)
		}
		found := false
		for _, k := range injidid.Primary.Snapshot() {
			if k == "status-kid" {
				found = true
			}
		}
		if !found {
			t.Error("status-list kid not remembered")
		}
	})
	t.Run("upstream 404 relayed, no header synthesised", func(t *testing.T) {
		up := &proxyUpstream{status: 404, resp: "nope"}
		srv := up.start(t)
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", srv.URL)
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.SetPathValue("id", "missing")
		rr := httptest.NewRecorder()
		(&H{}).InjiProxyStatusList(rr, req)
		if rr.Code != 404 || rr.Body.String() != "nope" {
			t.Errorf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("bad upstream URL -> 500; unreachable -> 502", func(t *testing.T) {
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", "http://bad host")
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.SetPathValue("id", "a")
		rr := httptest.NewRecorder()
		(&H{}).InjiProxyStatusList(rr, req)
		if rr.Code != http.StatusInternalServerError {
			t.Errorf("bad URL status=%d", rr.Code)
		}
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", "http://127.0.0.1:1")
		rr = httptest.NewRecorder()
		(&H{}).InjiProxyStatusList(rr, req)
		if rr.Code != http.StatusBadGateway || !strings.HasPrefix(rr.Body.String(), "upstream: ") {
			t.Errorf("unreachable status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
}

// ─── InjiProxyWellKnown ────────────────────────────────────────────────────────

func TestInjiProxyWellKnown(t *testing.T) {
	t.Run("pass-through with upstream content type", func(t *testing.T) {
		up := &proxyUpstream{respCT: "application/json; charset=utf-8", resp: `{"credential_issuer":"https://issuer.example"}`}
		srv := up.start(t)
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", srv.URL)
		rr := httptest.NewRecorder()
		(&H{}).InjiProxyWellKnown(rr, httptest.NewRequest(http.MethodGet, "/inji-proxy/.well-known/openid-credential-issuer", nil))
		if rr.Code != 200 || rr.Header().Get("Content-Type") != "application/json; charset=utf-8" {
			t.Errorf("status=%d ct=%q", rr.Code, rr.Header().Get("Content-Type"))
		}
		if up.path != "/v1/certify/.well-known/openid-credential-issuer" || !strings.Contains(rr.Body.String(), "issuer.example") {
			t.Errorf("path=%s body=%s", up.path, rr.Body.String())
		}
	})
	t.Run("upstream error status relayed; missing content type defaults to JSON", func(t *testing.T) {
		up := &proxyUpstream{status: 503, resp: "down"}
		srv := up.start(t)
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", srv.URL)
		rr := httptest.NewRecorder()
		(&H{}).InjiProxyWellKnown(rr, httptest.NewRequest(http.MethodGet, "/x", nil))
		if rr.Code != 503 || rr.Body.String() != "down" {
			t.Errorf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		// httptest's default handler sniffs text/plain for "down"; force the
		// empty-CT branch with a server that strips the header.
		srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header()["Content-Type"] = nil
			_, _ = io.WriteString(w, `{}`)
		}))
		defer srv2.Close()
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", srv2.URL)
		rr = httptest.NewRecorder()
		(&H{}).InjiProxyWellKnown(rr, httptest.NewRequest(http.MethodGet, "/x", nil))
		if rr.Header().Get("Content-Type") != "application/json" {
			t.Errorf("default ct = %q", rr.Header().Get("Content-Type"))
		}
	})
	t.Run("bad URL -> 500; unreachable -> 502", func(t *testing.T) {
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", "http://bad host")
		rr := httptest.NewRecorder()
		(&H{}).InjiProxyWellKnown(rr, httptest.NewRequest(http.MethodGet, "/x", nil))
		if rr.Code != http.StatusInternalServerError {
			t.Errorf("bad URL status=%d", rr.Code)
		}
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", "http://127.0.0.1:1")
		rr = httptest.NewRecorder()
		(&H{}).InjiProxyWellKnown(rr, httptest.NewRequest(http.MethodGet, "/x", nil))
		if rr.Code != http.StatusBadGateway {
			t.Errorf("unreachable status=%d", rr.Code)
		}
	})
}

// ─── did.json handlers + fetchDidJSON ──────────────────────────────────────────

func proxyDidJSONServer(t *testing.T, did string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/certify/.well-known/did.json" {
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":                 did,
			"assertionMethod":    []any{did},
			"verificationMethod": []any{map[string]any{"id": did + "#k1", "publicKeyMultibase": "z6MkExample"}},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestInjiProxyPrimaryDidJSON(t *testing.T) {
	t.Run("patches observed primary kids into the upstream doc", func(t *testing.T) {
		srv := proxyDidJSONServer(t, "did:web:primary.example")
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", srv.URL)
		injidid.Primary.Add("primary-extra-kid")
		rr := httptest.NewRecorder()
		(&H{}).InjiProxyPrimaryDidJSON(rr, httptest.NewRequest(http.MethodGet, "/inji-proxy/.well-known/did.json", nil))
		if rr.Code != 200 || rr.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("status=%d ct=%q", rr.Code, rr.Header().Get("Content-Type"))
		}
		var doc map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		ids := asStrings(doc["assertionMethod"])
		if !reflect.DeepEqual(ids[:1], []string{"did:web:primary.example#k1"}) {
			t.Errorf("assertionMethod = %v", ids)
		}
		if !strings.Contains(rr.Body.String(), "did:web:primary.example#primary-extra-kid") {
			t.Errorf("extra kid not patched: %s", rr.Body.String())
		}
	})
	t.Run("upstream failure -> 502", func(t *testing.T) {
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", "http://127.0.0.1:1")
		rr := httptest.NewRecorder()
		(&H{}).InjiProxyPrimaryDidJSON(rr, httptest.NewRequest(http.MethodGet, "/x", nil))
		if rr.Code != http.StatusBadGateway {
			t.Errorf("status=%d", rr.Code)
		}
	})
}

func TestInjiProxyPreauthDidJSON(t *testing.T) {
	t.Run("uses the pre-auth upstream and observer only", func(t *testing.T) {
		srv := proxyDidJSONServer(t, "did:web:preauth.example")
		t.Setenv("INJI_CERTIFY_PREAUTH_UPSTREAM_URL", srv.URL)
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", "http://127.0.0.1:1") // must NOT be used
		injidid.Preauth.Add("preauth-extra-kid")
		rr := httptest.NewRecorder()
		(&H{}).InjiProxyPreauthDidJSON(rr, httptest.NewRequest(http.MethodGet, "/inji-proxy-preauth/.well-known/did.json", nil))
		if rr.Code != 200 {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		body := rr.Body.String()
		if !strings.Contains(body, "did:web:preauth.example#preauth-extra-kid") {
			t.Errorf("preauth kid not patched: %s", body)
		}
		if strings.Contains(body, "primary-extra-kid") {
			t.Errorf("primary observer leaked into the pre-auth doc: %s", body)
		}
	})
	t.Run("upstream non-200 -> 502", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
		defer srv.Close()
		t.Setenv("INJI_CERTIFY_PREAUTH_UPSTREAM_URL", srv.URL)
		rr := httptest.NewRecorder()
		(&H{}).InjiProxyPreauthDidJSON(rr, httptest.NewRequest(http.MethodGet, "/x", nil))
		if rr.Code != http.StatusBadGateway {
			t.Errorf("status=%d", rr.Code)
		}
	})
}

func TestFetchDidJSON(t *testing.T) {
	ctx := context.Background()
	t.Run("ok", func(t *testing.T) {
		srv := proxyDidJSONServer(t, "did:web:issuer.example")
		doc, status, err := fetchDidJSON(ctx, srv.URL+"/v1/certify/.well-known/did.json")
		if err != nil || status != 200 || doc["id"] != "did:web:issuer.example" {
			t.Errorf("doc=%v status=%d err=%v", doc, status, err)
		}
	})
	t.Run("non-200 returns status without error", func(t *testing.T) {
		srv := proxyDidJSONServer(t, "x")
		doc, status, err := fetchDidJSON(ctx, srv.URL+"/other")
		if err != nil || status != 404 || doc != nil {
			t.Errorf("doc=%v status=%d err=%v", doc, status, err)
		}
	})
	t.Run("invalid JSON -> error with status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "{") }))
		defer srv.Close()
		_, status, err := fetchDidJSON(ctx, srv.URL)
		if err == nil || status != 200 {
			t.Errorf("status=%d err=%v", status, err)
		}
	})
	t.Run("bad URL and unreachable host", func(t *testing.T) {
		if _, status, err := fetchDidJSON(ctx, "http://bad host"); err == nil || status != 0 {
			t.Errorf("bad URL: status=%d err=%v", status, err)
		}
		if _, status, err := fetchDidJSON(ctx, "http://127.0.0.1:1"); err == nil || status != 0 {
			t.Errorf("unreachable: status=%d err=%v", status, err)
		}
	})
}

// ─── certifyIssuerDID ──────────────────────────────────────────────────────────

func TestCertifyIssuerDID(t *testing.T) {
	t.Run("did.json id wins on first attempt", func(t *testing.T) {
		srv := proxyDidJSONServer(t, "did:web:issuer.example")
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", srv.URL)
		t.Setenv("CERTIFY_ISSUER_DID", "did:web:env.example")
		if got := certifyIssuerDID(context.Background()); got != "did:web:issuer.example" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("retries a transient miss (blank id) then succeeds", func(t *testing.T) {
		calls := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			if calls == 1 {
				_, _ = io.WriteString(w, `{"id":"  "}`)
				return
			}
			_, _ = io.WriteString(w, `{"id":"did:web:issuer.example"}`)
		}))
		defer srv.Close()
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", srv.URL)
		start := time.Now()
		got := certifyIssuerDID(context.Background())
		if got != "did:web:issuer.example" || calls != 2 {
			t.Errorf("got %q after %d calls", got, calls)
		}
		if d := time.Since(start); d < 400*time.Millisecond {
			t.Errorf("retry back-off not applied (took %v)", d)
		}
	})
	t.Run("all attempts fail -> CERTIFY_ISSUER_DID env fallback", func(t *testing.T) {
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", "http://127.0.0.1:1")
		t.Setenv("CERTIFY_ISSUER_DID", " did:web:env.example ")
		if got := certifyIssuerDID(context.Background()); got != "did:web:env.example" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("all attempts fail and env is the docker-internal DID -> last resort", func(t *testing.T) {
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", "http://127.0.0.1:1")
		t.Setenv("CERTIFY_ISSUER_DID", "did:web:certify-nginx")
		if got := certifyIssuerDID(context.Background()); got != "did:web:certify-nginx" {
			t.Errorf("got %q", got)
		}
	})
}

// ─── patchedDidDoc edge cases ──────────────────────────────────────────────────

func TestPatchedDidDoc_EdgeCases(t *testing.T) {
	t.Run("missing id -> untouched", func(t *testing.T) {
		doc := map[string]any{"verificationMethod": []any{map[string]any{"id": "did:web:ex#k1"}}}
		patchedDidDoc(doc, []string{"k2"})
		if vms, _ := doc["verificationMethod"].([]any); len(vms) != 1 {
			t.Errorf("doc without id must not be patched: %v", doc)
		}
	})
	t.Run("first method not an object -> untouched", func(t *testing.T) {
		doc := map[string]any{"id": "did:web:ex", "verificationMethod": []any{"garbage"}}
		patchedDidDoc(doc, []string{"k2"})
		if _, ok := doc["assertionMethod"]; ok {
			t.Error("assertionMethod must not be synthesised without a template method")
		}
	})
	t.Run("empty kid is skipped, object-less methods tolerated", func(t *testing.T) {
		doc := didDocWith("did:web:ex#k1")
		doc["verificationMethod"] = append(doc["verificationMethod"].([]any), "not-an-object")
		patchedDidDoc(doc, []string{"", "k2"})
		vms, _ := doc["verificationMethod"].([]any)
		if len(vms) != 3 { // k1, "not-an-object", k2
			t.Errorf("verificationMethod len = %d, want 3", len(vms))
		}
		want := []string{"did:web:ex#k1", "did:web:ex#k2"}
		if got := asStrings(doc["assertionMethod"]); !reflect.DeepEqual(got, want) {
			t.Errorf("assertionMethod = %v, want %v", got, want)
		}
	})
}

// ─── injectCredentialContext / truncateForLog ──────────────────────────────────

func TestInjectCredentialContext(t *testing.T) {
	t.Run("adds @context when missing", func(t *testing.T) {
		out, ok := injectCredentialContext([]byte(`{"credential_definition":{"type":["VerifiableCredential"]}}`))
		if !ok || !strings.Contains(string(out), `"@context":["https://www.w3.org/ns/credentials/v2"]`) {
			t.Errorf("ok=%v out=%s", ok, out)
		}
	})
	for name, in := range map[string]string{
		"invalid JSON":             `{`,
		"no credential_definition": `{"format":"ldp_vc"}`,
		"@context already present": `{"credential_definition":{"@context":["x"]}}`,
	} {
		t.Run(name+" -> unchanged", func(t *testing.T) {
			out, ok := injectCredentialContext([]byte(in))
			if ok || string(out) != in {
				t.Errorf("ok=%v out=%s", ok, out)
			}
		})
	}
}

func TestTruncateForLog(t *testing.T) {
	if got := truncateForLog("short", 10); got != "short" {
		t.Errorf("short = %q", got)
	}
	if got := truncateForLog("abcdefghij", 4); got != "abcd…(6 more)" {
		t.Errorf("long = %q", got)
	}
}
