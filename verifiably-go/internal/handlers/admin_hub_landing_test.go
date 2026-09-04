package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestShowAdminHub_RedirectsAnonymousToLogin(t *testing.T) {
	h := &H{Sessions: NewStore(), Templates: loadPageTemplates(t, "admin_hub_landing")}
	rec := httptest.NewRecorder()
	h.ShowAdminHub(rec, httptest.NewRequest(http.MethodGet, "/admin", nil))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/admin/login" {
		t.Errorf("Location = %q, want /admin/login", loc)
	}
}

func TestShowAdminHub_RendersCardsForAdmin(t *testing.T) {
	h := &H{
		Sessions:          NewStore(),
		Templates:         loadPageTemplates(t, "admin_hub_landing"),
		IssuerAPIKeyStore: newMockAPIKeyStore(),
		GrafanaURL:        "https://grafana.example/d/overview",
		IsHub:             true,
	}
	cookies := seedSession(t, h, func(s *Session) { s.IsAdmin = true })

	// HTMX swap of <main>: only the content block renders.
	req := htmxMainRequest(http.MethodGet, "/admin")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ShowAdminHub(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"Hub administration panel", "/admin/federation/members", "/admin/auth-providers", "/registrar/identities"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	if strings.Contains(body, "<!DOCTYPE html>") {
		t.Error("HTMX render should not include the full layout")
	}

	// Full page load: the layout wraps the same content.
	req = httptest.NewRequest(http.MethodGet, "/admin", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	h.ShowAdminHub(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("full page status = %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "<!DOCTYPE html>") || !strings.Contains(rec.Body.String(), "Hub administration panel") {
		t.Error("full page render should include layout and hub content")
	}
}
