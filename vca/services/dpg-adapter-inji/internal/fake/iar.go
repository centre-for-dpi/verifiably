// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// The interactive authorization of Certify 0.14.0: presentation during
// issuance (testdata/doc/SOURCE.md).
const (
	// ASMetadataPath serves the authorization server metadata.
	ASMetadataPath = "/v1/certify/.well-known/oauth-authorization-server"
	// IARPath is the interactive authorization endpoint.
	IARPath = "/v1/certify/oauth/iar"
	// tokenPath is the token endpoint of both grants.
	tokenPath = "/v1/certify/oauth/token" //nolint:gosec // G101: a URL path, not a credential
	// recordedHost is the host of the recorded answers. The fake puts
	// its own address in its place.
	recordedHost = "http://certify.inji.example"
	// AuthSession is the session id of the recorded answer.
	AuthSession = "3f6b2c1e-8d4a-4f0b-9e7c-5a2d1b0c9e8f"
)

// serveIAR answers the authorization server metadata, the interactive
// authorization endpoint, and the authorization code grant of the token
// endpoint. It reports false for any other call.
func (f *Server) serveIAR(w http.ResponseWriter, r *http.Request, body []byte) bool {
	switch {
	case r.URL.Path == ASMetadataPath && r.Method == http.MethodGet:
		f.sendHosted(w, http.StatusOK, "doc/oauth-authorization-server.json")
	case r.URL.Path == IARPath && r.Method == http.MethodPost:
		f.interactive(w, body)
	case r.URL.Path == tokenPath && r.Method == http.MethodPost:
		form, err := url.ParseQuery(string(body))
		if err != nil || form.Get("grant_type") != "authorization_code" {
			return false
		}
		f.codeToken(w, form)
	default:
		return false
	}
	return true
}

// interactive answers the first call with the presentation request of
// the stack, and the second call with an authorization code when it
// carries a presentation.
func (f *Server) interactive(w http.ResponseWriter, body []byte) {
	form, err := url.ParseQuery(string(body))
	if err != nil {
		f.sendError(w, "invalid_request")
		return
	}
	if session := form.Get("auth_session"); session != "" {
		var answer struct {
			VPToken json.RawMessage `json:"vp_token"`
		}
		if session != AuthSession || json.Unmarshal([]byte(form.Get("openid4vp_response")), &answer) != nil ||
			len(answer.VPToken) == 0 || string(answer.VPToken) == `""` {
			f.sendHosted(w, http.StatusOK, "doc/iar-error.json")
			return
		}
		f.sendHosted(w, http.StatusOK, "doc/iar-ok.json")
		return
	}
	var details []struct {
		Type string `json:"type"`
		ID   string `json:"credential_configuration_id"`
	}
	ok := form.Get("response_type") == "code" && form.Get("client_id") != "" && form.Get("code_challenge") != "" &&
		form.Get("code_challenge_method") == "S256" &&
		slices.Contains(strings.Fields(strings.ReplaceAll(form.Get("interaction_types_supported"), ",", " ")), "openid4vp_presentation") &&
		json.Unmarshal([]byte(form.Get("authorization_details")), &details) == nil && len(details) > 0 &&
		details[0].Type == "openid_credential" && details[0].ID != ""
	if !ok {
		f.sendError(w, "invalid_request")
		return
	}
	f.mu.Lock()
	f.challenge = form.Get("code_challenge")
	f.mu.Unlock()
	f.sendHosted(w, http.StatusOK, "doc/iar-require-interaction.json")
}

// codeToken redeems an authorization code of the interactive endpoint
// when the PKCE verifier matches the challenge.
func (f *Server) codeToken(w http.ResponseWriter, form url.Values) {
	sum := sha256.Sum256([]byte(form.Get("code_verifier")))
	f.mu.Lock()
	challenge := f.challenge
	f.mu.Unlock()
	if !strings.HasPrefix(form.Get("code"), "iar_auth_") || challenge == "" ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
		f.sendError(w, "invalid_grant")
		return
	}
	f.sendHosted(w, http.StatusOK, "doc/token-iar.json")
}

// sendHosted writes a recorded answer with the address of the fake in
// place of the recorded host.
func (f *Server) sendHosted(w http.ResponseWriter, status int, name string) {
	raw, err := os.ReadFile(filepath.Join(f.dir, name)) //nolint:gosec // G304: the name is one of the fixed answers
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write([]byte(strings.ReplaceAll(string(raw), recordedHost, f.URL()))); err != nil {
		return
	}
}

// sendError writes an OAuth error with the status 400.
func (f *Server) sendError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	f.sendJSON(w, map[string]string{"error": code})
}
