package handlers

import (
	"net/http"
	"strings"

	"github.com/verifiably/verifiably-go/internal/auth"
)

// ShowAuthProvidersAdmin lists configured OIDC providers and offers
// per-row delete. Reachable only to a standalone admin session
// (sess.IsAdmin) — independent of the OIDC issuer/holder/verifier
// flow so an unauth'd visitor sees the admin login form instead.
//
// New OIDC providers are registered via /auth/custom (same form on the
// regular auth page); this page is purely for management of what's
// already there. The form's visibility on /auth is mode-driven (ro
// hides it, rw / off show it) — see addFormVisible in handlers.go.
func (h *H) ShowAuthProvidersAdmin(w http.ResponseWriter, r *http.Request) {
	if h.AuthAdminMode == "off" {
		http.NotFound(w, r)
		return
	}
	sess := h.Sessions.MustGet(w, r)
	if !sess.IsAdmin {
		h.redirect(w, r, "/admin/login")
		return
	}
	var descriptors []auth.Descriptor
	if h.AuthReg != nil {
		descriptors = h.AuthReg.Descriptors()
	}
	h.render(w, r, "admin_auth_providers", h.pageData(sess, map[string]any{
		"Providers":      descriptors,
		"Mode":           h.adminModeOrDefault(),
		"StorePath":      h.authStorePath(),
		"AddFormVisible": h.addFormVisible(),
	}))
}

// DeleteAuthProvider handles POST /admin/auth-providers/{id}/delete.
// Removes the provider from the in-memory registry and, when the row
// came from the persisted user file, from disk. System and env-source
// rows can also be deleted from the registry — they'll come back on
// the next deploy.sh / container restart, which is the desired behaviour
// when an admin is iterating on bootstrap config.
//
// Allowed in both rw and ro modes — `ro` only hides the +Add form on
// /auth (per the admin's own scope: "users can pick from what I've
// curated"); deleting providers is still part of curation. `off` mode
// 404s the entire admin surface.
func (h *H) DeleteAuthProvider(w http.ResponseWriter, r *http.Request) {
	if h.AuthAdminMode == "off" {
		http.NotFound(w, r)
		return
	}
	sess := h.Sessions.MustGet(w, r)
	if !sess.IsAdmin {
		h.redirect(w, r, "/admin/login")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	// Decide whether the store also needs touching. User-file rows must
	// be removed there too or they'd just reload on next boot; system /
	// env rows live elsewhere (deploy.sh's file, env vars), so removing
	// from the registry is sufficient and the row will reappear on the
	// next deploy.sh / container restart.
	if h.AuthReg != nil {
		if p := h.AuthReg.Lookup(id); p != nil && p.Source() == auth.SourceUser && h.AuthStore != nil {
			if _, _, err := h.AuthStore.Remove(id); err != nil {
				h.errorToast(w, r, "Could not remove provider: "+err.Error())
				return
			}
		}
	}
	if h.AuthReg != nil {
		h.AuthReg.Remove(id)
	}
	h.redirect(w, r, "/admin/auth-providers")
}

// adminModeOrDefault normalises an unset/unknown AuthAdminMode to "rw".
func (h *H) adminModeOrDefault() string {
	switch h.AuthAdminMode {
	case "ro", "off":
		return h.AuthAdminMode
	default:
		return "rw"
	}
}

// authStorePath returns the user-store path for the admin page's "where
// state lives" hint. Empty when no store is wired (test scaffolding).
func (h *H) authStorePath() string {
	if h.AuthStore == nil {
		return ""
	}
	return h.AuthStore.Path()
}
