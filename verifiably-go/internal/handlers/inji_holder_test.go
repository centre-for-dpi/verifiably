package handlers

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
