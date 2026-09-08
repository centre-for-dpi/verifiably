package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/internal/trust"
)

// trustFakeRegistry is an in-memory trust.Registry that records Add/Remove
// calls and can be told to fail.
type trustFakeRegistry struct {
	issuers []trust.TrustedIssuer
	listErr error
	addErr  error
	rmErr   error
	added   []trust.TrustedIssuer
	removed []string
}

func (f *trustFakeRegistry) IsTrusted(context.Context, string, string) error { return nil }
func (f *trustFakeRegistry) TrustedIssuers(context.Context) ([]trust.TrustedIssuer, error) {
	return f.issuers, f.listErr
}
func (f *trustFakeRegistry) Add(_ context.Context, e trust.TrustedIssuer) error {
	if f.addErr != nil {
		return f.addErr
	}
	f.added = append(f.added, e)
	f.issuers = append(f.issuers, e)
	return nil
}
func (f *trustFakeRegistry) Remove(_ context.Context, did string) error {
	if f.rmErr != nil {
		return f.rmErr
	}
	f.removed = append(f.removed, did)
	return nil
}

func trustNewH(t *testing.T, reg trust.Registry) *H {
	t.Helper()
	return &H{Sessions: NewStore(), Templates: loadPageTemplates(t, "admin_trust"), TrustRegistry: reg}
}

func trustAdminCookies(t *testing.T, h *H) []*http.Cookie {
	t.Helper()
	return seedSession(t, h, func(s *Session) { s.IsAdmin = true })
}

func trustGet(path string, cookies ...*http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

func TestServeTrustRegistry(t *testing.T) {
	issuers := []trust.TrustedIssuer{{DID: "did:web:issuer.example", DisplayName: "Example Authority"}}

	t.Run("not configured → 503", func(t *testing.T) {
		h := &H{}
		rr := httptest.NewRecorder()
		h.ServeTrustRegistry(rr, trustGet("/trust-registry"))
		if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "trust registry not configured") {
			t.Fatalf("got %d %q", rr.Code, rr.Body.String())
		}
	})
	t.Run("list error → 500", func(t *testing.T) {
		h := &H{TrustRegistry: &trustFakeRegistry{listErr: errors.New("db down")}}
		rr := httptest.NewRecorder()
		h.ServeTrustRegistry(rr, trustGet("/trust-registry"))
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d", rr.Code)
		}
	})
	t.Run("HS256 fallback with default issuer id", func(t *testing.T) {
		secret := []byte("dev-secret")
		h := &H{TrustRegistry: &trustFakeRegistry{issuers: issuers}, TrustJWTSecret: secret}
		rr := httptest.NewRecorder()
		h.ServeTrustRegistry(rr, trustGet("/trust-registry"))
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d", rr.Code)
		}
		if ct := rr.Header().Get("Content-Type"); ct != "application/jwt" {
			t.Errorf("Content-Type = %q", ct)
		}
		if cc := rr.Header().Get("Cache-Control"); cc != "public, max-age=3600" {
			t.Errorf("Cache-Control = %q", cc)
		}
		claims, err := trust.VerifyJWT(rr.Body.String(), secret)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if claims["iss"] != "verifiably-go" {
			t.Errorf("iss = %v, want verifiably-go", claims["iss"])
		}
		list, _ := claims["issuers"].([]any)
		if len(list) != 1 {
			t.Fatalf("issuers = %v", claims["issuers"])
		}
		if first, _ := list[0].(map[string]any); first["did"] != "did:web:issuer.example" {
			t.Errorf("issuer[0] = %v", list[0])
		}
	})
	t.Run("ES256 when a signing key is set, custom issuer id", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		h := &H{TrustRegistry: &trustFakeRegistry{issuers: issuers}, TrustSigningKey: key, TrustJWTIssuer: "hub.example"}
		rr := httptest.NewRecorder()
		h.ServeTrustRegistry(rr, trustGet("/trust-registry"))
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d", rr.Code)
		}
		parts := strings.Split(rr.Body.String(), ".")
		if len(parts) != 3 {
			t.Fatalf("not a compact JWT: %q", rr.Body.String())
		}
		hdr := trustDecodeSegment(t, parts[0])
		if hdr["alg"] != "ES256" {
			t.Errorf("alg = %v, want ES256", hdr["alg"])
		}
		if payload := trustDecodeSegment(t, parts[1]); payload["iss"] != "hub.example" {
			t.Errorf("iss = %v", payload["iss"])
		}
	})
	t.Run("signing failure → 500", func(t *testing.T) {
		// A P-256 key with an out-of-range scalar makes ecdsa.Sign fail.
		bad := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}, D: big.NewInt(0)}
		h := &H{TrustRegistry: &trustFakeRegistry{issuers: issuers}, TrustSigningKey: bad}
		rr := httptest.NewRecorder()
		h.ServeTrustRegistry(rr, trustGet("/trust-registry"))
		if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "internal error") {
			t.Fatalf("got %d %q", rr.Code, rr.Body.String())
		}
	})
}

func trustDecodeSegment(t *testing.T, seg string) map[string]any {
	t.Helper()
	// base64url without padding.
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatalf("decode segment: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("segment json: %v", err)
	}
	return m
}

func TestServeJWKS(t *testing.T) {
	t.Run("no key → 404", func(t *testing.T) {
		rr := httptest.NewRecorder()
		(&H{}).ServeJWKS(rr, trustGet("/.well-known/jwks.json"))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d", rr.Code)
		}
	})
	t.Run("publishes the EC public key", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		rr := httptest.NewRecorder()
		(&H{TrustSigningKey: key}).ServeJWKS(rr, trustGet("/.well-known/jwks.json"))
		if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("got %d %q", rr.Code, rr.Header().Get("Content-Type"))
		}
		var jwks struct {
			Keys []map[string]any `json:"keys"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &jwks); err != nil {
			t.Fatal(err)
		}
		if len(jwks.Keys) != 1 || jwks.Keys[0]["kty"] != "EC" || jwks.Keys[0]["crv"] != "P-256" || jwks.Keys[0]["alg"] != "ES256" {
			t.Errorf("jwks = %+v", jwks.Keys)
		}
		want := trust.PublicKeyToJWK(&key.PublicKey)
		if jwks.Keys[0]["x"] != want["x"] || jwks.Keys[0]["y"] != want["y"] {
			t.Errorf("x/y mismatch: %v vs %v", jwks.Keys[0], want)
		}
	})
}

func TestShowTrustRegistry(t *testing.T) {
	t.Run("non-admin → redirect to login", func(t *testing.T) {
		h := trustNewH(t, &trustFakeRegistry{})
		rr := httptest.NewRecorder()
		h.ShowTrustRegistry(rr, trustGet("/admin/trust"))
		if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/admin/login" {
			t.Fatalf("got %d Location=%q", rr.Code, rr.Header().Get("Location"))
		}
	})
	t.Run("admin but no registry → 503", func(t *testing.T) {
		h := trustNewH(t, nil)
		rr := httptest.NewRecorder()
		h.ShowTrustRegistry(rr, trustGet("/admin/trust", trustAdminCookies(t, h)...))
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d", rr.Code)
		}
	})
	t.Run("list error → toast (non-HTMX 422)", func(t *testing.T) {
		h := trustNewH(t, &trustFakeRegistry{listErr: errors.New("db down")})
		rr := httptest.NewRecorder()
		h.ShowTrustRegistry(rr, trustGet("/admin/trust", trustAdminCookies(t, h)...))
		if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "Could not load trust registry: db down") {
			t.Fatalf("got %d %q", rr.Code, rr.Body.String())
		}
	})
	t.Run("renders the issuer table (HTMX + full page)", func(t *testing.T) {
		reg := &trustFakeRegistry{issuers: []trust.TrustedIssuer{{DID: "did:web:issuer.example", Schemas: []string{"PersonCredential"}}}}
		h := trustNewH(t, reg)
		cookies := trustAdminCookies(t, h)

		req := htmxMainRequest(http.MethodGet, "/admin/trust")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		h.ShowTrustRegistry(rr, req)
		body := rr.Body.String()
		if rr.Code != http.StatusOK || !strings.Contains(body, "did:web:issuer.example") || !strings.Contains(body, "PersonCredential") {
			t.Fatalf("htmx: got %d %q", rr.Code, body)
		}
		if strings.Contains(body, "<!DOCTYPE") {
			t.Error("htmx swap should not include the layout")
		}

		rr = httptest.NewRecorder()
		h.ShowTrustRegistry(rr, trustGet("/admin/trust", cookies...))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "<html") || !strings.Contains(rr.Body.String(), "did:web:issuer.example") {
			t.Fatalf("full page: got %d", rr.Code)
		}
	})
}

func TestAddTrustedIssuer(t *testing.T) {
	post := func(body, ct string, cookies ...*http.Cookie) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/admin/trust", strings.NewReader(body))
		req.Header.Set("Content-Type", ct)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		return req
	}

	t.Run("non-admin → 401", func(t *testing.T) {
		h := trustNewH(t, &trustFakeRegistry{})
		rr := httptest.NewRecorder()
		h.AddTrustedIssuer(rr, post("did=x", "application/x-www-form-urlencoded"))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d", rr.Code)
		}
	})
	t.Run("no registry → 503", func(t *testing.T) {
		h := trustNewH(t, nil)
		rr := httptest.NewRecorder()
		h.AddTrustedIssuer(rr, post("did=x", "application/x-www-form-urlencoded", trustAdminCookies(t, h)...))
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d", rr.Code)
		}
	})
	t.Run("invalid JSON → 400", func(t *testing.T) {
		h := trustNewH(t, &trustFakeRegistry{})
		rr := httptest.NewRecorder()
		h.AddTrustedIssuer(rr, post("{not json", "application/json", trustAdminCookies(t, h)...))
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid JSON") {
			t.Fatalf("got %d %q", rr.Code, rr.Body.String())
		}
	})
	t.Run("JSON body adds and redirects (non-HTMX)", func(t *testing.T) {
		reg := &trustFakeRegistry{}
		h := trustNewH(t, reg)
		rr := httptest.NewRecorder()
		h.AddTrustedIssuer(rr, post(`{"did":"did:web:issuer.example","display_name":"Example","schemas":["A"]}`, "application/json", trustAdminCookies(t, h)...))
		if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/admin/trust" {
			t.Fatalf("got %d Location=%q", rr.Code, rr.Header().Get("Location"))
		}
		if len(reg.added) != 1 || reg.added[0].DID != "did:web:issuer.example" || reg.added[0].Schemas[0] != "A" {
			t.Errorf("added = %+v", reg.added)
		}
	})
	t.Run("bad valid_until → 400", func(t *testing.T) {
		h := trustNewH(t, &trustFakeRegistry{})
		rr := httptest.NewRecorder()
		form := url.Values{"did": {"did:web:issuer.example"}, "valid_until": {"31/12/2030"}}
		h.AddTrustedIssuer(rr, post(form.Encode(), "application/x-www-form-urlencoded", trustAdminCookies(t, h)...))
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "valid_until must be YYYY-MM-DD") {
			t.Fatalf("got %d %q", rr.Code, rr.Body.String())
		}
	})
	t.Run("missing DID → toast", func(t *testing.T) {
		h := trustNewH(t, &trustFakeRegistry{})
		rr := httptest.NewRecorder()
		h.AddTrustedIssuer(rr, post("did=+&display_name=x", "application/x-www-form-urlencoded", trustAdminCookies(t, h)...))
		if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "DID is required") {
			t.Fatalf("got %d %q", rr.Code, rr.Body.String())
		}
	})
	t.Run("registry Add error → toast", func(t *testing.T) {
		h := trustNewH(t, &trustFakeRegistry{addErr: errors.New("duplicate")})
		rr := httptest.NewRecorder()
		h.AddTrustedIssuer(rr, post("did=did:web:issuer.example", "application/x-www-form-urlencoded", trustAdminCookies(t, h)...))
		if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "Could not add issuer: duplicate") {
			t.Fatalf("got %d %q", rr.Code, rr.Body.String())
		}
	})
	t.Run("form + HTMX parses schemas/valid_until and re-renders the list", func(t *testing.T) {
		reg := &trustFakeRegistry{}
		h := trustNewH(t, reg)
		form := url.Values{
			"did":          {" did:web:issuer.example "},
			"display_name": {"Example Authority"},
			"schemas":      {"PersonCredential, , DegreeCredential"},
			"valid_until":  {"2030-06-30"},
		}
		req := formPost("/admin/trust", form, trustAdminCookies(t, h)...)
		rr := httptest.NewRecorder()
		h.AddTrustedIssuer(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d body=%q", rr.Code, rr.Body.String())
		}
		if len(reg.added) != 1 {
			t.Fatalf("added = %+v", reg.added)
		}
		e := reg.added[0]
		if e.DID != "did:web:issuer.example" || e.DisplayName != "Example Authority" {
			t.Errorf("entry = %+v", e)
		}
		if len(e.Schemas) != 2 || e.Schemas[0] != "PersonCredential" || e.Schemas[1] != "DegreeCredential" {
			t.Errorf("schemas = %v", e.Schemas)
		}
		if e.ValidUntil.Format("2006-01-02") != "2030-06-30" {
			t.Errorf("valid_until = %v", e.ValidUntil)
		}
		body := rr.Body.String()
		if !strings.Contains(body, "<table") || !strings.Contains(body, "Example Authority") || strings.Contains(body, "<html") {
			t.Errorf("fragment body = %q", body)
		}
	})
}

func TestDeleteTrustedIssuer(t *testing.T) {
	del := func(did string, htmx bool, cookies ...*http.Cookie) *http.Request {
		req := httptest.NewRequest(http.MethodDelete, "/admin/trust/"+did, nil)
		req.SetPathValue("did", did)
		if htmx {
			req.Header.Set("HX-Request", "true")
		}
		for _, c := range cookies {
			req.AddCookie(c)
		}
		return req
	}
	t.Run("non-admin → 401", func(t *testing.T) {
		h := trustNewH(t, &trustFakeRegistry{})
		rr := httptest.NewRecorder()
		h.DeleteTrustedIssuer(rr, del("did:web:issuer.example", false))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d", rr.Code)
		}
	})
	t.Run("no registry → 503", func(t *testing.T) {
		h := trustNewH(t, nil)
		rr := httptest.NewRecorder()
		h.DeleteTrustedIssuer(rr, del("did:web:issuer.example", false, trustAdminCookies(t, h)...))
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d", rr.Code)
		}
	})
	t.Run("empty did → 400", func(t *testing.T) {
		h := trustNewH(t, &trustFakeRegistry{})
		rr := httptest.NewRecorder()
		h.DeleteTrustedIssuer(rr, del("", false, trustAdminCookies(t, h)...))
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "did is required") {
			t.Fatalf("got %d %q", rr.Code, rr.Body.String())
		}
	})
	t.Run("Remove error → toast (HTMX header)", func(t *testing.T) {
		h := trustNewH(t, &trustFakeRegistry{rmErr: errors.New("nope")})
		rr := httptest.NewRecorder()
		h.DeleteTrustedIssuer(rr, del("did:web:issuer.example", true, trustAdminCookies(t, h)...))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Header().Get("HX-Trigger"), "Could not remove issuer: nope") {
			t.Fatalf("got %d HX-Trigger=%q", rr.Code, rr.Header().Get("HX-Trigger"))
		}
	})
	t.Run("HTMX delete re-renders list; plain delete redirects", func(t *testing.T) {
		reg := &trustFakeRegistry{}
		h := trustNewH(t, reg)
		cookies := trustAdminCookies(t, h)
		rr := httptest.NewRecorder()
		h.DeleteTrustedIssuer(rr, del("did:web:issuer.example", true, cookies...))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "No trusted issuers configured") {
			t.Fatalf("htmx: got %d %q", rr.Code, rr.Body.String())
		}
		rr = httptest.NewRecorder()
		h.DeleteTrustedIssuer(rr, del("did:web:other.example", false, cookies...))
		if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/admin/trust" {
			t.Fatalf("plain: got %d", rr.Code)
		}
		if len(reg.removed) != 2 || reg.removed[0] != "did:web:issuer.example" || reg.removed[1] != "did:web:other.example" {
			t.Errorf("removed = %v", reg.removed)
		}
	})
}
