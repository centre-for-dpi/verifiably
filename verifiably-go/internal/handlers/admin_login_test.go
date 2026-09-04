package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdminCredentials_DefaultsAndEnvOverrides(t *testing.T) {
	t.Setenv("VERIFIABLY_ADMIN_USER", "")
	t.Setenv("VERIFIABLY_ADMIN_PASSWORD", "")
	if u, p := adminCredentials(); u != "admin" || p != "admin" {
		t.Errorf("defaults = %q/%q, want admin/admin", u, p)
	}
	t.Setenv("VERIFIABLY_ADMIN_USER", "  ops ")
	t.Setenv("VERIFIABLY_ADMIN_PASSWORD", "s3cret")
	if u, p := adminCredentials(); u != "ops" || p != "s3cret" {
		t.Errorf("env = %q/%q, want ops/s3cret", u, p)
	}
}

func TestShowAdminLogin_OffMode404s(t *testing.T) {
	h := &H{Sessions: NewStore(), AuthAdminMode: "off"}
	rec := httptest.NewRecorder()
	h.ShowAdminLogin(rec, httptest.NewRequest(http.MethodGet, "/admin/login", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestShowAdminLogin_AdminAlreadySignedInRedirects(t *testing.T) {
	h := &H{Sessions: NewStore(), AuthAdminMode: "rw", IsHub: true}
	cookies := seedSession(t, h, func(s *Session) { s.IsAdmin = true })
	req := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	req.AddCookie(cookies[0])
	rec := httptest.NewRecorder()
	h.ShowAdminLogin(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin" {
		t.Fatalf("status = %d Location = %q, want 303 /admin (hub landing)", rec.Code, rec.Header().Get("Location"))
	}
}

func TestShowAdminLogin_RendersFormAndErrorBanner(t *testing.T) {
	h := &H{Sessions: NewStore(), AuthAdminMode: "ro", Templates: loadPageTemplates(t, "admin_login")}

	rec := httptest.NewRecorder()
	h.ShowAdminLogin(rec, htmxMainRequest(http.MethodGet, "/admin/login"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Sign in as admin") || !strings.Contains(body, `name="username"`) {
		t.Errorf("login form not rendered: %s", body)
	}
	if strings.Contains(body, "Wrong admin credentials.") {
		t.Error("error banner should not show without ?err=1")
	}

	rec = httptest.NewRecorder()
	h.ShowAdminLogin(rec, htmxMainRequest(http.MethodGet, "/admin/login?err=1"))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Wrong admin credentials.") {
		t.Errorf("?err=1 should render the banner (status %d): %s", rec.Code, rec.Body.String())
	}
}

func TestAdminLogin_OffMode404s(t *testing.T) {
	h := &H{Sessions: NewStore(), AuthAdminMode: "off"}
	rec := httptest.NewRecorder()
	h.AdminLogin(rec, httptest.NewRequest(http.MethodPost, "/admin/login", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestAdminLanding_HubVsStandalone(t *testing.T) {
	if got := (&H{IsHub: true}).adminLanding(); got != "/admin" {
		t.Errorf("hub landing = %q", got)
	}
	if got := (&H{}).adminLanding(); got != "/admin/auth-providers" {
		t.Errorf("standalone landing = %q", got)
	}
}

func TestAdminLogout_ClearsFlagAndRedirects(t *testing.T) {
	h := &H{Sessions: NewStore()}
	cookies := seedSession(t, h, func(s *Session) { s.IsAdmin = true })
	req := httptest.NewRequest(http.MethodPost, "/admin/logout", nil)
	req.AddCookie(cookies[0])
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	h.AdminLogout(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("HX-Redirect") != "/" {
		t.Fatalf("status = %d HX-Redirect = %q, want 200 /", rec.Code, rec.Header().Get("HX-Redirect"))
	}
	if h.Sessions.Get(req).IsAdmin {
		t.Error("IsAdmin should be cleared")
	}
}
