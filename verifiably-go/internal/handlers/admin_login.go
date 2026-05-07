package handlers

import (
	"crypto/subtle"
	"net/http"
	"os"
	"strings"
)

// adminCredentials returns the username + password the standalone admin
// login compares against. Defaults to "admin" / "admin" so a fresh
// install boots with a working admin path; override either via env var.
//
// Important: this is intentionally a single shared credential, not a
// user database — the admin role exists solely to manage OIDC providers
// (the very thing that would otherwise be your IdP). A directory of
// admin users would re-introduce the chicken-and-egg problem.
func adminCredentials() (user, pass string) {
	user = strings.TrimSpace(os.Getenv("VERIFIABLY_ADMIN_USER"))
	if user == "" {
		user = "admin"
	}
	pass = os.Getenv("VERIFIABLY_ADMIN_PASSWORD")
	if pass == "" {
		pass = "admin"
	}
	return user, pass
}

// ShowAdminLogin renders the standalone admin login page. Visible to
// anyone (no role/session gate); successful POST sets sess.IsAdmin and
// redirects to /admin/auth-providers. Returns 404 when admin mode is
// "off" so the path is fully hidden on locked-down deployments.
//
// The ?err=1 query param surfaces a "wrong credentials" banner — set
// by AdminLogin's failure path. Kept as a query param (not a flash
// cookie) because the flow is single-roundtrip and a stale banner on
// a copy-pasted URL is harmless.
func (h *H) ShowAdminLogin(w http.ResponseWriter, r *http.Request) {
	if h.AuthAdminMode == "off" {
		http.NotFound(w, r)
		return
	}
	sess := h.Sessions.MustGet(w, r)
	// Already an admin? Skip the form entirely.
	if sess.IsAdmin {
		h.redirect(w, r, "/admin/auth-providers")
		return
	}
	body := map[string]any{"Mode": h.adminModeOrDefault()}
	if r.URL.Query().Get("err") == "1" {
		body["Error"] = "Wrong admin credentials."
	}
	h.render(w, r, "admin_login", h.pageData(sess, body))
}

// AdminLogin handles POST /admin/login. Compares submitted creds with
// constant-time equality (so a timing channel can't enumerate the
// admin username), then flips sess.IsAdmin on success. On failure, a
// red toast surfaces — same UX as the OIDC error path.
func (h *H) AdminLogin(w http.ResponseWriter, r *http.Request) {
	if h.AuthAdminMode == "off" {
		http.NotFound(w, r)
		return
	}
	sess := h.Sessions.MustGet(w, r)
	_ = r.ParseForm()
	user := strings.TrimSpace(r.FormValue("username"))
	pass := r.FormValue("password")

	wantUser, wantPass := adminCredentials()
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(wantUser)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(wantPass)) == 1
	if !userOK || !passOK {
		// Round-trip back to the login page with ?err=1 so the GET
		// handler renders an inline banner. Avoids errorToast (which
		// would 500 on a non-HTMX plain-form post) without coupling
		// this handler to template rendering at the failure path.
		h.redirect(w, r, "/admin/login?err=1")
		return
	}
	sess.IsAdmin = true
	h.redirect(w, r, "/admin/auth-providers")
}

// AdminLogout clears the admin flag and redirects to the public landing.
// Independent of /auth/logout so an operator can drop the admin context
// without losing their OIDC sign-in (or vice versa).
func (h *H) AdminLogout(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	sess.IsAdmin = false
	h.redirect(w, r, "/")
}
