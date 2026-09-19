// SPDX-License-Identifier: Apache-2.0

package login

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/onboard"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
)

// DeviceGrant is the grant type of the device authorization grant
// (RFC 8628 section 3.4).
const DeviceGrant = "urn:ietf:params:oauth:grant-type:device_code"

// CodeTTL is how long a loopback code waits for the CLI to exchange it.
const CodeTTL = 2 * time.Minute

// maxBody caps a provider response.
const maxBody = 1 << 20

// MountCLI registers the endpoints the vca admin CLI uses to log in
// (ADR-010 decision 6): the device authorization grant when the IdP
// supports it, else the loopback redirect helper.
func (s *Service) MountCLI(mux *http.ServeMux) {
	mux.Handle("POST /device_authorization", oidcflow.RejectQueryTokens(http.HandlerFunc(s.DeviceAuthorization)))
	mux.Handle("POST /token", oidcflow.RejectQueryTokens(http.HandlerFunc(s.Token)))
	mux.Handle("POST /cli/login", oidcflow.RejectQueryTokens(http.HandlerFunc(s.LoopbackStart)))
	mux.Handle("POST /cli/token", oidcflow.RejectQueryTokens(http.HandlerFunc(s.LoopbackToken)))
}

// DeviceAuthorization proxies POST /device_authorization to the device
// authorization endpoint of the provider (RFC 8628 section 3.1). The
// admin service adds the client id, so the CLI holds no client secret.
func (s *Service) DeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, meta, err := s.providerMetadata(ctx, r.PostFormValue("provider"))
	if err != nil {
		s.failOAuth(w, err)
		return
	}
	if !meta.SupportsDeviceGrant() {
		oidcflow.WriteError(w, http.StatusBadRequest, "unsupported_grant_type",
			"the provider supports no device grant, use the loopback helper at /cli/login")
		return
	}
	form := url.Values{
		"client_id": {p.ClientID},
		"scope":     {strings.Join(p.EffectiveScopes(), " ")},
	}
	body, status, err := s.post(ctx, meta.DeviceAuthorizationEndpoint, form, p)
	if err != nil {
		s.failOAuth(w, err)
		return
	}
	answer := map[string]any{}
	if err := json.Unmarshal(body, &answer); err != nil {
		oidcflow.WriteError(w, http.StatusBadGateway, "temporarily_unavailable", "the provider answer is not JSON")
		return
	}
	answer["provider"] = p.ID
	oidcflow.WriteJSON(w, status, answer)
}

// Token proxies POST /token with the device code grant. On a success it
// checks the ID token, binds or checks the super admin role, and
// returns an admin session token. The CLI never sees a provider token.
func (s *Service) Token(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if grant := r.PostFormValue("grant_type"); grant != DeviceGrant {
		oidcflow.WriteError(w, http.StatusBadRequest, "unsupported_grant_type", "only the device code grant is supported here")
		return
	}
	deviceCode := r.PostFormValue("device_code")
	if deviceCode == "" {
		oidcflow.WriteError(w, http.StatusBadRequest, "invalid_request", "device_code is required")
		return
	}
	p, meta, err := s.providerMetadata(ctx, r.PostFormValue("provider"))
	if err != nil {
		s.failOAuth(w, err)
		return
	}
	form := url.Values{
		"grant_type":  {DeviceGrant},
		"device_code": {deviceCode},
		"client_id":   {p.ClientID},
	}
	body, status, err := s.post(ctx, meta.TokenEndpoint, form, p)
	if err != nil {
		s.failOAuth(w, err)
		return
	}
	var answer struct {
		IDToken   string `json:"id_token"`
		ExpiresIn int64  `json:"expires_in"`
		Error     string `json:"error"`
	}
	if err := json.Unmarshal(body, &answer); err != nil {
		oidcflow.WriteError(w, http.StatusBadGateway, "temporarily_unavailable", "the provider answer is not JSON")
		return
	}
	if answer.Error != "" || status != http.StatusOK {
		// authorization_pending and slow_down reach the CLI unchanged.
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_, _ = w.Write(body)
		return
	}
	if answer.IDToken == "" {
		oidcflow.WriteError(w, http.StatusBadGateway, "temporarily_unavailable", "the provider returned no id_token")
		return
	}
	claims, err := s.VerifyIDToken(ctx, p, answer.IDToken)
	if err != nil {
		s.failOAuth(w, err)
		return
	}
	issuer, _ := claims["iss"].(string)
	subject, _ := claims["sub"].(string)
	token, session, err := s.session(ctx, p, issuer, subject, name(claims), r.PostFormValue(BootstrapField), answer.IDToken)
	if err != nil {
		s.failOAuth(w, err)
		return
	}
	oidcflow.WriteJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int64(time.Until(session.Expiry()).Seconds()),
		"csrf_token":   s.d.CSRF.Token(session.SID),
	})
}

// LoopbackStart answers POST /cli/login with the authorization URL of a
// login whose result goes to a loopback port (RFC 8252 section 7.3).
// The CLI opens the URL and waits on http://127.0.0.1:<port>/.
func (s *Service) LoopbackStart(w http.ResponseWriter, r *http.Request) {
	port := strings.TrimSpace(r.PostFormValue("port"))
	if !ValidPort(port) {
		oidcflow.WriteError(w, http.StatusBadRequest, "invalid_request", "port must be a number from 1024 to 65535")
		return
	}
	_, u, err := s.begin(r.Context(), r.PostFormValue("provider"), "", r.PostFormValue(BootstrapField), port)
	if err != nil {
		s.failOAuth(w, err)
		return
	}
	oidcflow.WriteJSON(w, http.StatusOK, map[string]any{
		"authorization_url": u,
		"redirect_uri":      LoopbackURL(port, ""),
	})
}

// LoopbackToken answers POST /cli/token: it exchanges the one time code
// of a loopback login for the admin session token.
func (s *Service) LoopbackToken(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.PostFormValue("code"))
	token, claims, ok := s.takeCode(code)
	if !ok {
		oidcflow.WriteError(w, http.StatusBadRequest, "invalid_grant", "the code is not valid or it expired")
		return
	}
	oidcflow.WriteJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int64(time.Until(claims.Expiry()).Seconds()),
		"csrf_token":   s.d.CSRF.Token(claims.SID),
	})
}

// Callback handles GET /auth/callback. A browser login goes to the
// shared handler. A CLI login gets a one time code on the loopback
// address, so no token travels in a URL (RFC 9700 section 4.3.2).
func (s *Service) Callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	port, ok := s.takeLoopback(state)
	if !ok {
		s.Handlers().Callback(w, r)
		return
	}
	token, claims, _, err := s.Complete(r.Context(), state, q.Get("code"), q.Get("error"))
	if err != nil {
		http.Error(w, "the login failed, see the terminal", oidcflow.HTTPStatus(err))
		return
	}
	code := s.putCode(token, claims)
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, LoopbackURL(port, code), http.StatusSeeOther)
}

// Login handles GET /auth/login. It accepts a bootstrap token in the
// query, so the first super admin binds the role with one login
// (ADR-010 decision 4).
func (s *Service) Login(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	_, u, err := s.begin(r.Context(), q.Get("provider"), q.Get("return_to"), q.Get(BootstrapField), "")
	if err != nil {
		s.failOAuth(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, u, http.StatusFound)
}

// newCode returns a one time loopback code.
func newCode() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ValidPort reports whether raw is a loopback port the CLI may use.
func ValidPort(raw string) bool {
	n, err := strconv.Atoi(raw)
	return err == nil && n >= 1024 && n <= 65535
}

// LoopbackURL returns the loopback address of the CLI. An empty code
// returns the address without a query.
func LoopbackURL(port, code string) string {
	u := "http://127.0.0.1:" + port + "/callback"
	if code == "" {
		return u
	}
	return u + "?code=" + url.QueryEscape(code)
}

// providerMetadata returns one provider and its metadata, including the
// endpoints that the shared library does not carry.
func (s *Service) providerMetadata(ctx context.Context, providerID string) (oidcflow.Provider, onboard.Metadata, error) {
	p, err := s.provider(ctx, providerID)
	if err != nil {
		return oidcflow.Provider{}, onboard.Metadata{}, err
	}
	if !p.Enabled {
		return oidcflow.Provider{}, onboard.Metadata{}, oidcflow.ErrProviderDisabled
	}
	meta, err := onboard.Discover(ctx, s.d.Client, p.DiscoveryURL)
	if err != nil {
		return oidcflow.Provider{}, onboard.Metadata{}, err
	}
	return p, meta, nil
}

// post sends a form to one provider endpoint. A confidential client
// authenticates with HTTP Basic (RFC 6749 section 2.3.1).
func (s *Service) post(ctx context.Context, endpoint string, form url.Values, p oidcflow.Provider) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, oidcflow.ErrUpstream
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	secret, err := s.secret(p.ClientSecret)
	if err != nil {
		return nil, 0, err
	}
	if secret != "" {
		req.SetBasicAuth(url.QueryEscape(p.ClientID), url.QueryEscape(secret))
	}
	resp, err := s.d.Client.Do(req)
	if err != nil {
		return nil, 0, oidcflow.ErrUpstream
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, 0, oidcflow.ErrUpstream
	}
	return body, resp.StatusCode, nil
}

// secret resolves a client secret reference with the flow resolver.
func (s *Service) secret(ref oidcflow.SecretRef) (string, error) {
	if s.d.Flow.Secrets != nil {
		return s.d.Flow.Secrets(ref)
	}
	return oidcflow.EnvFileSecrets(ref)
}

// failOAuth writes an OAuth 2.0 error body for an error of the flow.
func (s *Service) failOAuth(w http.ResponseWriter, err error) {
	status := oidcflow.HTTPStatus(err)
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
	oidcflow.WriteError(w, status, code, err.Error())
}

func (s *Service) putCode(token string, claims oidcflow.Claims) string {
	code := newCode()
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.d.Now()
	for k, v := range s.codes {
		if now.After(v.expires) {
			delete(s.codes, k)
		}
	}
	s.codes[code] = issuedCode{token: token, claims: claims, expires: now.Add(CodeTTL)}
	return code
}

func (s *Service) takeCode(code string) (string, oidcflow.Claims, bool) {
	if code == "" {
		return "", oidcflow.Claims{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.codes[code]
	delete(s.codes, code)
	if !ok || s.d.Now().After(v.expires) {
		return "", oidcflow.Claims{}, false
	}
	return v.token, v.claims, true
}

func (s *Service) takeLoopback(state string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.d.Now()
	for k, v := range s.loopbacks {
		if now.After(v.expires) {
			delete(s.loopbacks, k)
		}
	}
	v, ok := s.loopbacks[state]
	delete(s.loopbacks, state)
	if !ok || now.After(v.expires) {
		return "", false
	}
	return v.port, true
}
