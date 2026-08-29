package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/internal/auth"
)

// TestAdminAuthProviders_OffMode404s pins the "off" lockdown: with
// VERIFIABLY_AUTH_ADMIN=off the page route must 404, hiding the surface
// entirely from any operator probing for the URL.
func TestAdminAuthProviders_OffMode404s(t *testing.T) {
	h := &H{
		Sessions:      NewStore(),
		AuthAdminMode: "off",
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/auth-providers", nil)
	h.ShowAuthProvidersAdmin(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("off mode should 404, got %d", rec.Code)
	}
}

// TestAddFormVisible_DrivenByMode pins the mode→add-form mapping:
// the form on /auth is visible ONLY in `rw`. `ro` hides it because the
// admin curates the list; `off` hides it because there's no UI for
// provider management at all in that mode. The FirstRun bypass that
// keeps fresh installs from locking out lives in the Auth handler, not
// in this helper, so it's tested separately at the page-render level.
func TestAddFormVisible_DrivenByMode(t *testing.T) {
	cases := map[string]bool{
		"":    true, // unset → defaults to rw
		"rw":  true,
		"ro":  false,
		"off": false,
	}
	for mode, want := range cases {
		h := &H{AuthAdminMode: mode}
		if got := h.addFormVisible(); got != want {
			t.Errorf("addFormVisible() with mode=%q = %v, want %v", mode, got, want)
		}
	}
}

// TestAdminAuthProviders_ROModeAllowsDelete pins the new ro semantics:
// `ro` only hides the +Add form on /auth — admins still curate the list
// (login + delete still work). Only `off` 404s the surface entirely.
func TestAdminAuthProviders_ROModeAllowsDelete(t *testing.T) {
	reg := auth.NewRegistry()
	reg.Register(stubProv{id: "k", source: auth.SourceUser})
	sessions := NewStore()
	h := &H{
		Sessions:      sessions,
		AuthReg:       reg,
		AuthStore:     auth.NewUserStore(filepath.Join(t.TempDir(), "user.json")),
		AuthAdminMode: "ro",
	}
	bootRec := httptest.NewRecorder()
	bootReq := httptest.NewRequest("GET", "/", nil)
	sess := sessions.MustGet(bootRec, bootReq)
	sess.IsAdmin = true

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/auth-providers/k/delete", nil)
	req.AddCookie(bootRec.Result().Cookies()[0])
	req.SetPathValue("id", "k")
	h.DeleteAuthProvider(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("ro mode delete should redirect (success), got %d (%s)", rec.Code, rec.Body.String())
	}
	if reg.Lookup("k") != nil {
		t.Error("provider should be removed in ro mode (delete is allowed)")
	}
}

// TestAdminAuthProviders_RequiresAdminSession pins the gate change: the
// admin auth-providers page is no longer reachable from a regular OIDC
// session — only a standalone admin login (sess.IsAdmin) gets in.
// Anonymous (or merely OIDC-signed-in) requests redirect to /admin/login.
func TestAdminAuthProviders_RequiresAdminSession(t *testing.T) {
	h := &H{
		Sessions:      NewStore(),
		AuthReg:       auth.NewRegistry(),
		AuthAdminMode: "rw",
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/auth-providers", nil)
	h.ShowAuthProvidersAdmin(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("anon GET should redirect to /admin/login, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/admin/login" {
		t.Errorf("redirect target = %q, want /admin/login", loc)
	}
}

// TestAdminAuthProviders_DeleteAllowsSystemRow pins the new behaviour:
// admins (the standalone admin role) can delete ANY row including
// system/env-source ones. Those will reappear on the next deploy.sh /
// container restart, but during admin iteration that's the desired
// flow — no lockout for "managed externally".
func TestAdminAuthProviders_DeleteAllowsSystemRow(t *testing.T) {
	reg := auth.NewRegistry()
	reg.Register(stubProv{id: "keycloak", source: auth.SourceSystem})
	store := auth.NewUserStore(filepath.Join(t.TempDir(), "user.json"))
	sessions := NewStore()

	h := &H{
		Sessions:      sessions,
		AuthReg:       reg,
		AuthStore:     store,
		AuthAdminMode: "rw",
	}

	// Mint an admin session and attach its cookie to the test request.
	bootRec := httptest.NewRecorder()
	bootReq := httptest.NewRequest("GET", "/", nil)
	sess := sessions.MustGet(bootRec, bootReq)
	sess.IsAdmin = true
	cookie := bootRec.Result().Cookies()[0]

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/auth-providers/keycloak/delete", nil)
	req.AddCookie(cookie)
	req.SetPathValue("id", "keycloak")

	h.DeleteAuthProvider(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("admin delete should redirect, got %d (%s)", rec.Code, rec.Body.String())
	}
	if reg.Lookup("keycloak") != nil {
		t.Error("system row should be removed from registry after admin delete")
	}
}

// TestAdminLogin_RejectsWrongCreds pins the constant-time check: only
// the configured user/pass pair flips the IsAdmin flag.
func TestAdminLogin_RejectsWrongCreds(t *testing.T) {
	h := &H{Sessions: NewStore(), AuthAdminMode: "rw"}
	t.Setenv("VERIFIABLY_ADMIN_PASSWORD", "topsecret")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/login", nil)
	req.PostForm = map[string][]string{
		"username": {"admin"},
		"password": {"hunter2"},
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.AdminLogin(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("wrong creds should redirect to /admin/login?err=1, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/admin/login?err=1" {
		t.Errorf("redirect target = %q, want /admin/login?err=1", loc)
	}
	// Verify the session isn't promoted: pull it back via the cookie.
	sess := h.Sessions.MustGet(httptest.NewRecorder(),
		mustReqWithCookie(t, h.Sessions, rec))
	if sess.IsAdmin {
		t.Error("wrong password should not have set IsAdmin")
	}
}

// TestAdminLogin_AcceptsCorrectCreds is the positive path.
func TestAdminLogin_AcceptsCorrectCreds(t *testing.T) {
	h := &H{Sessions: NewStore(), AuthAdminMode: "rw"}
	t.Setenv("VERIFIABLY_ADMIN_USER", "ops")
	t.Setenv("VERIFIABLY_ADMIN_PASSWORD", "topsecret")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/login", nil)
	req.PostForm = map[string][]string{
		"username": {"ops"},
		"password": {"topsecret"},
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.AdminLogin(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d (%s)", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/admin/auth-providers" {
		t.Errorf("redirect target = %q, want /admin/auth-providers", loc)
	}
}

// mustReqWithCookie threads the session cookie minted by `from` onto a
// fresh request, so a follow-up handler call sees the same Session.
func mustReqWithCookie(t *testing.T, _ SessionStore, from *httptest.ResponseRecorder) *http.Request {
	t.Helper()
	r := httptest.NewRequest("GET", "/", nil)
	for _, c := range from.Result().Cookies() {
		r.AddCookie(c)
	}
	return r
}

// stubProv is a minimal auth.Provider for tests in the handlers package.
type stubProv struct {
	id     string
	source string
}

func (s stubProv) ID() string          { return s.id }
func (s stubProv) DisplayName() string { return s.id }
func (s stubProv) Kind() string        { return "OIDC" }
func (s stubProv) Source() string      { return s.source }
func (s stubProv) AuthorizeURL(_ context.Context, _, _, _ string) (string, error) {
	return "", nil
}
func (s stubProv) Exchange(_ context.Context, _, _, _ string) (auth.Token, error) {
	return auth.Token{}, nil
}
func (s stubProv) Refresh(_ context.Context, _ string) (auth.Token, error) {
	return auth.Token{}, nil
}
func (s stubProv) UserInfo(_ context.Context, _ string) (auth.UserInfo, error) {
	return auth.UserInfo{}, nil
}
func (s stubProv) VerifyToken(_ context.Context, _ string) (map[string]string, error) {
	return nil, nil
}

func adminAuthProvidersReq(t *testing.T, h *H, method, path string) *http.Request {
	t.Helper()
	cookies := seedSession(t, h, func(s *Session) { s.IsAdmin = true })
	req := httptest.NewRequest(method, path, nil)
	req.AddCookie(cookies[0])
	return req
}

func TestShowAuthProvidersAdmin_RendersProvidersAndStorePath(t *testing.T) {
	reg := auth.NewRegistry()
	reg.Register(stubProv{id: "corp-idp", source: auth.SourceUser})
	reg.Register(stubProv{id: "sys-idp", source: auth.SourceSystem})
	store := auth.NewUserStore(filepath.Join(t.TempDir(), "user.json"))
	h := &H{
		Sessions:      NewStore(),
		AuthReg:       reg,
		AuthStore:     store,
		AuthAdminMode: "ro",
		Templates:     loadPageTemplates(t, "admin_auth_providers"),
	}
	req := adminAuthProvidersReq(t, h, "GET", "/admin/auth-providers")
	req.Header.Set("HX-Request", "true")
	req.Header.Set("HX-Target", "main")
	rec := httptest.NewRecorder()
	h.ShowAuthProvidersAdmin(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"corp-idp", "sys-idp", store.Path(), "/admin/auth-providers/corp-idp/delete", "Read-only mode"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}

	// No registry / no store: renders the empty state without a path hint.
	h2 := &H{Sessions: NewStore(), AuthAdminMode: "rw", Templates: h.Templates}
	req = adminAuthProvidersReq(t, h2, "GET", "/admin/auth-providers")
	req.Header.Set("HX-Request", "true")
	req.Header.Set("HX-Target", "main")
	rec = httptest.NewRecorder()
	h2.ShowAuthProvidersAdmin(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "No providers configured.") {
		t.Errorf("empty state: status = %d body = %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "persist to") {
		t.Error("store path hint should be absent without an AuthStore")
	}
}

func TestAuthStorePath(t *testing.T) {
	if got := (&H{}).authStorePath(); got != "" {
		t.Errorf("nil store path = %q, want empty", got)
	}
	p := filepath.Join(t.TempDir(), "user.json")
	if got := (&H{AuthStore: auth.NewUserStore(p)}).authStorePath(); got != p {
		t.Errorf("path = %q, want %q", got, p)
	}
}

func TestDeleteAuthProvider_Guards(t *testing.T) {
	t.Run("off mode 404s", func(t *testing.T) {
		h := &H{Sessions: NewStore(), AuthAdminMode: "off"}
		rec := httptest.NewRecorder()
		h.DeleteAuthProvider(rec, httptest.NewRequest("POST", "/admin/auth-providers/x/delete", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
	t.Run("anonymous redirects to login", func(t *testing.T) {
		h := &H{Sessions: NewStore(), AuthAdminMode: "rw"}
		rec := httptest.NewRecorder()
		h.DeleteAuthProvider(rec, httptest.NewRequest("POST", "/admin/auth-providers/x/delete", nil))
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/login" {
			t.Fatalf("status = %d Location = %q", rec.Code, rec.Header().Get("Location"))
		}
	})
	t.Run("missing id is 400", func(t *testing.T) {
		h := &H{Sessions: NewStore(), AuthAdminMode: "rw"}
		req := adminAuthProvidersReq(t, h, "POST", "/admin/auth-providers//delete")
		req.SetPathValue("id", "  ")
		rec := httptest.NewRecorder()
		h.DeleteAuthProvider(rec, req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "missing id") {
			t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("no registry wired still redirects", func(t *testing.T) {
		h := &H{Sessions: NewStore(), AuthAdminMode: "rw"}
		req := adminAuthProvidersReq(t, h, "POST", "/admin/auth-providers/x/delete")
		req.SetPathValue("id", "x")
		rec := httptest.NewRecorder()
		h.DeleteAuthProvider(rec, req)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/auth-providers" {
			t.Fatalf("status = %d Location = %q", rec.Code, rec.Header().Get("Location"))
		}
	})
}

// A user-source row whose persisted file cannot be read surfaces the store
// error as a toast and leaves the registry untouched.
func TestDeleteAuthProvider_StoreErrorToast(t *testing.T) {
	reg := auth.NewRegistry()
	reg.Register(stubProv{id: "corp-idp", source: auth.SourceUser})
	// Point the store at a directory: os.ReadFile fails with a non-ENOENT error.
	store := auth.NewUserStore(t.TempDir())
	h := &H{Sessions: NewStore(), AuthReg: reg, AuthStore: store, AuthAdminMode: "rw"}
	req := adminAuthProvidersReq(t, h, "POST", "/admin/auth-providers/corp-idp/delete")
	req.SetPathValue("id", "corp-idp")
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	h.DeleteAuthProvider(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if trig := rec.Header().Get("HX-Trigger"); !strings.Contains(trig, "Could not remove provider: read ") {
		t.Errorf("HX-Trigger = %q, want store error toast", trig)
	}
	if reg.Lookup("corp-idp") == nil {
		t.Error("registry row must survive a failed store removal")
	}
}
