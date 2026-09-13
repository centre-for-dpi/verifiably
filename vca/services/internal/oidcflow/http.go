// SPDX-License-Identifier: Apache-2.0

package oidcflow

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Cookie describes the session cookie a service sets at the callback.
type Cookie struct {
	// Name is the cookie name.
	Name string
	// Secure sets the Secure attribute. Turn it off only on localhost.
	Secure bool
	// Path is the cookie path. Empty selects "/".
	Path string
}

// Set writes the session cookie with HttpOnly and SameSite=Lax.
func (c Cookie) Set(w http.ResponseWriter, token string, exp time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     c.Name,
		Value:    token,
		Path:     c.path(),
		Expires:  exp,
		HttpOnly: true,
		Secure:   c.Secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// Clear removes the session cookie.
func (c Cookie) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     c.Name,
		Value:    "",
		Path:     c.path(),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   c.Secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (c Cookie) path() string {
	if c.Path == "" {
		return "/"
	}
	return c.Path
}

// TokenFromRequest reads the session token from the Authorization header
// (Bearer) or from the cookie. It never reads the query string
// (RFC 9700 section 4.3.2).
func TokenFromRequest(r *http.Request, cookieName string) string {
	if auth := r.Header.Get("Authorization"); len(auth) > 7 && strings.EqualFold(auth[:7], "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	if cookieName != "" {
		if c, err := r.Cookie(cookieName); err == nil {
			return c.Value
		}
	}
	return ""
}

// RejectQueryTokens returns 400 when a request carries a token in the
// query string (RFC 9700 section 4.3.2 forbids bearer tokens in URLs).
func RejectQueryTokens(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Has("access_token") || q.Has("session_token") || q.Has("id_token") {
			WriteError(w, http.StatusBadRequest, "invalid_request", "tokens are not accepted in the query string")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// WriteJSON writes v as JSON with status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes an OAuth 2.0 style error body.
func WriteError(w http.ResponseWriter, status int, code, description string) {
	WriteJSON(w, status, map[string]string{"error": code, "error_description": description})
}

// Logins is what a service gives the shared HTTP handlers.
type Logins interface {
	// Start creates a pending login and returns the authorization URL.
	Start(ctx context.Context, providerID, returnTo string) (authorizationURL string, err error)
	// Complete ends a login and returns the session token and claims.
	Complete(ctx context.Context, state, code, providerError string) (token string, claims Claims, returnTo string, err error)
	// End revokes a session and returns the provider logout URL, or "".
	End(ctx context.Context, token string) (providerLogoutURL string, err error)
	// Session checks a token and returns its claims.
	Session(ctx context.Context, token string) (Claims, error)
}

// Handlers are the plain HTTP login endpoints of ADR-003 decision 7.
type Handlers struct {
	Logins Logins
	Cookie Cookie
	CSRF   CSRF
	// LogoutRedirect is where the browser goes after logout when the
	// provider has no end session endpoint. Empty returns JSON instead.
	LogoutRedirect string
}

// Mount registers the endpoints on mux under prefix, for example
// "/auth" gives /auth/login, /auth/callback, /auth/logout, /auth/session.
func (h Handlers) Mount(mux *http.ServeMux, prefix string) {
	prefix = strings.TrimRight(prefix, "/")
	mux.Handle("GET "+prefix+"/login", RejectQueryTokens(http.HandlerFunc(h.Login)))
	mux.Handle("GET "+prefix+"/callback", RejectQueryTokens(http.HandlerFunc(h.Callback)))
	mux.Handle("POST "+prefix+"/logout", RejectQueryTokens(http.HandlerFunc(h.Logout)))
	mux.Handle("GET "+prefix+"/session", RejectQueryTokens(http.HandlerFunc(h.Session)))
}

// Login handles GET /login?provider=<id>&return_to=<path> with a 302
// to the provider.
func (h Handlers) Login(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	u, err := h.Logins.Start(r.Context(), q.Get("provider"), q.Get("return_to"))
	if err != nil {
		h.fail(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, u, http.StatusFound)
}

// Callback handles GET /callback?state=&code= from the provider. It sets
// the session cookie, then redirects to return_to when the login named
// one, else returns the session token as JSON.
func (h Handlers) Callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	token, claims, returnTo, err := h.Logins.Complete(r.Context(), q.Get("state"), q.Get("code"), q.Get("error"))
	if err != nil {
		h.fail(w, err)
		return
	}
	h.Cookie.Set(w, token, claims.Expiry())
	if returnTo != "" {
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, returnTo, http.StatusSeeOther)
		return
	}
	WriteJSON(w, http.StatusOK, h.sessionBody(token, claims))
}

// Logout handles POST /logout. It needs the session and a synchronizer
// token. It clears the cookie and redirects to the provider logout URL
// when the provider has one.
func (h Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	token := TokenFromRequest(r, h.Cookie.Name)
	claims, err := h.Logins.Session(r.Context(), token)
	if err != nil {
		h.fail(w, err)
		return
	}
	if !h.CSRF.Check(claims.SID, CSRFFromRequest(r)) {
		h.fail(w, ErrCSRF)
		return
	}
	logoutURL, err := h.Logins.End(r.Context(), token)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.Cookie.Clear(w)
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case logoutURL != "":
		http.Redirect(w, r, logoutURL, http.StatusSeeOther)
	case h.LogoutRedirect != "":
		http.Redirect(w, r, h.LogoutRedirect, http.StatusSeeOther)
	default:
		WriteJSON(w, http.StatusOK, map[string]any{"logged_out": true})
	}
}

// Session handles GET /session: it returns the claims of the current
// session and a fresh synchronizer token for the next POST.
func (h Handlers) Session(w http.ResponseWriter, r *http.Request) {
	token := TokenFromRequest(r, h.Cookie.Name)
	claims, err := h.Logins.Session(r.Context(), token)
	if err != nil {
		h.fail(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, h.sessionBody(token, claims))
}

func (h Handlers) sessionBody(token string, claims Claims) map[string]any {
	return map[string]any{
		"session_token": token,
		"csrf_token":    h.CSRF.Token(claims.SID),
		"claims":        claims,
		"expires_at":    claims.Expiry().UTC().Format(time.RFC3339),
	}
}

func (h Handlers) fail(w http.ResponseWriter, err error) {
	status := HTTPStatus(err)
	code := "invalid_request"
	switch status {
	case http.StatusUnauthorized:
		code = "invalid_token"
	case http.StatusForbidden:
		code = "access_denied"
	case http.StatusNotFound:
		code = "not_found"
	case http.StatusBadGateway:
		code = "temporarily_unavailable"
	case http.StatusInternalServerError:
		code = "server_error"
	}
	WriteError(w, status, code, err.Error())
}
