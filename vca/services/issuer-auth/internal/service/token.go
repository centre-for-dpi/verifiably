// SPDX-License-Identifier: Apache-2.0

package service

import (
	"net/http"
	"net/url"

	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
)

// TokenHandler serves POST /token with the OAuth 2.0 client credentials
// grant (RFC 6749 section 4.4) for registered machine clients
// (ADR-012 decision 4). The response is a service JWT with roles.
func (s *Service) TokenHandler() http.Handler {
	return oidcflow.RejectQueryTokens(http.HandlerFunc(s.token))
}

func (s *Service) token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		oidcflow.WriteError(w, http.StatusMethodNotAllowed, "invalid_request", "use POST")
		return
	}
	if err := r.ParseForm(); err != nil {
		oidcflow.WriteError(w, http.StatusBadRequest, "invalid_request", "form body is not valid")
		return
	}
	if r.PostForm.Get("grant_type") != "client_credentials" {
		oidcflow.WriteError(w, http.StatusBadRequest, "unsupported_grant_type", "only client_credentials is supported")
		return
	}
	id, secret := clientCredentials(r)
	if id == "" || secret == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="issuer-auth"`)
		oidcflow.WriteError(w, http.StatusUnauthorized, "invalid_client", "client authentication is required")
		return
	}
	c, err := s.d.Clients.Authenticate(id, secret)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="issuer-auth"`)
		oidcflow.WriteError(w, http.StatusUnauthorized, "invalid_client", "client id or secret is wrong, or the client is not active")
		return
	}
	token, claims, err := s.d.Signer.Issue(oidcflow.Claims{
		Subject:   "client:" + c.ID,
		Roles:     c.Roles,
		ClientID:  c.ID,
		Tenant:    c.TenantID,
		ExpiresAt: s.d.Now().Add(s.cfg.MachineTokenTTL).Unix(),
	})
	if err != nil {
		oidcflow.WriteError(w, http.StatusInternalServerError, "server_error", "cannot sign the token")
		return
	}
	oidcflow.WriteJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   claims.ExpiresAt - s.d.Now().Unix(),
		"roles":        c.Roles,
	})
}

// clientCredentials reads the client id and secret from HTTP Basic
// (RFC 6749 section 2.3.1) or from the form body.
func clientCredentials(r *http.Request) (string, string) {
	if id, secret, ok := r.BasicAuth(); ok {
		uid, err1 := url.QueryUnescape(id)
		usec, err2 := url.QueryUnescape(secret)
		if err1 == nil && err2 == nil {
			return uid, usec
		}
		return id, secret
	}
	return r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
}
