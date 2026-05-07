package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
		"":    true,  // unset → defaults to rw
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
func mustReqWithCookie(t *testing.T, _ *Store, from *httptest.ResponseRecorder) *http.Request {
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
