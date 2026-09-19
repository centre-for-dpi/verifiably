// SPDX-License-Identifier: Apache-2.0

package oidcflow

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/oidc"
)

// DefaultPendingTTL is how long a started login waits for the callback.
const DefaultPendingTTL = 10 * time.Minute

// Pending is one started login that waits for the provider callback.
type Pending struct {
	ProviderID  string    `json:"provider_id"`
	State       string    `json:"state"`
	Nonce       string    `json:"nonce"`
	Verifier    string    `json:"verifier"`
	RedirectURI string    `json:"redirect_uri"`
	ReturnTo    string    `json:"return_to,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// Result is what a completed login yields.
type Result struct {
	// Claims are the verified ID token claims.
	Claims map[string]any
	// Issuer and Subject are the iss and sub claims.
	Issuer  string
	Subject string
	// IDToken is the raw ID token, for id_token_hint at logout.
	IDToken string
	// AccessToken is the provider access token, when the provider gave one.
	AccessToken string
	// RefreshToken is the provider refresh token, when any.
	RefreshToken string
	// TokenExpiresAt is when the access token stops working.
	TokenExpiresAt time.Time
}

// Flow runs the authorization code flow with PKCE against a provider.
type Flow struct {
	// Cache holds metadata and key sets. Required.
	Cache *Cache
	// Client makes the token request. Nil selects a 10 second client.
	Client *http.Client
	// Secrets resolves client secret references. Nil selects EnvFileSecrets.
	Secrets SecretResolver
	// Now returns the current time. Nil selects time.Now.
	Now func() time.Time
	// PendingTTL bounds a started login. Zero selects DefaultPendingTTL.
	PendingTTL time.Duration
}

func (f *Flow) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func (f *Flow) client() *http.Client {
	if f.Client != nil {
		return f.Client
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (f *Flow) secrets() SecretResolver {
	if f.Secrets != nil {
		return f.Secrets
	}
	return EnvFileSecrets
}

// Metadata returns the provider metadata with the internal rebase applied.
func (f *Flow) Metadata(ctx context.Context, p Provider) (Metadata, error) {
	m, err := f.Cache.Metadata(ctx, p.DiscoveryURL)
	if err != nil {
		return Metadata{}, err
	}
	return m.Rebase(p.InternalAuthority), nil
}

// Begin creates a pending login and the authorization URL for the browser.
// The response type is always code (RFC 9700 forbids the implicit flow).
func (f *Flow) Begin(ctx context.Context, p Provider, redirectURI, returnTo string) (Pending, string, error) {
	if !p.Enabled {
		return Pending{}, "", ErrProviderDisabled
	}
	if returnTo != "" && !ValidReturnTo(returnTo) {
		return Pending{}, "", ErrReturnTo
	}
	m, err := f.Metadata(ctx, p)
	if err != nil {
		return Pending{}, "", err
	}
	ttl := f.PendingTTL
	if ttl <= 0 {
		ttl = DefaultPendingTTL
	}
	pend := Pending{
		ProviderID:  p.ID,
		State:       oidc.NewState(),
		Nonce:       oidc.NewState(),
		Verifier:    oidc.NewVerifier(),
		RedirectURI: redirectURI,
		ReturnTo:    returnTo,
		ExpiresAt:   f.now().Add(ttl),
	}
	u := AuthorizeURL(m.AuthorizationEndpoint, p.ClientID, redirectURI, pend.State, pend.Nonce, pend.Verifier, p.EffectiveScopes())
	return pend, u, nil
}

// AuthorizeURL builds the authorization request URL with PKCE S256,
// state, and nonce (OIDC Core 1.0 section 3.1.2.1).
func AuthorizeURL(endpoint, clientID, redirectURI, state, nonce, verifier string, scopes []string) string {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {oidc.Challenge(verifier)},
		"code_challenge_method": {"S256"},
	}
	sep := "?"
	if strings.Contains(endpoint, "?") {
		sep = "&"
	}
	return endpoint + sep + q.Encode()
}

// Complete exchanges the code at the token endpoint and verifies the ID
// token: signature against the provider JWKS, iss, aud, exp, and nonce.
func (f *Flow) Complete(ctx context.Context, p Provider, pend Pending, code string) (Result, error) {
	if f.now().After(pend.ExpiresAt) {
		return Result{}, wrap(ErrStateUnknown, "login expired")
	}
	if strings.TrimSpace(code) == "" {
		return Result{}, wrap(ErrProviderError, "no authorization code")
	}
	m, err := f.Metadata(ctx, p)
	if err != nil {
		return Result{}, err
	}
	tok, err := f.exchange(ctx, p, m, pend, code)
	if err != nil {
		return Result{}, err
	}
	claims, err := f.verifyIDToken(ctx, p, m, tok.IDToken)
	if err != nil {
		return Result{}, err
	}
	if nonce := anyval.As[string](claims["nonce"]); nonce != pend.Nonce {
		return Result{}, ErrNonce
	}
	res := Result{
		Claims:       claims,
		IDToken:      tok.IDToken,
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
	}
	res.Issuer = anyval.As[string](claims["iss"])
	res.Subject = anyval.As[string](claims["sub"])
	if tok.ExpiresIn > 0 {
		res.TokenExpiresAt = f.now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	}
	return res, nil
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	IDToken          string `json:"id_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int64  `json:"expires_in"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// exchange posts the code to the token endpoint (RFC 6749 section 4.1.3).
// A confidential client authenticates with HTTP Basic (section 2.3.1).
func (f *Flow) exchange(ctx context.Context, p Provider, m Metadata, pend Pending, code string) (tokenResponse, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {pend.RedirectURI},
		"client_id":     {p.ClientID},
		"code_verifier": {pend.Verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, wrap(ErrUpstream, "build token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	secret, err := f.secrets()(p.ClientSecret)
	if err != nil {
		return tokenResponse{}, err
	}
	if secret != "" {
		req.SetBasicAuth(url.QueryEscape(p.ClientID), url.QueryEscape(secret))
	}
	res, err := f.client().Do(req)
	if err != nil {
		return tokenResponse{}, wrap(ErrUpstream, "token endpoint: %v", err)
	}
	defer func() { anyval.Discard(res.Body.Close()) }()
	// A read failure leaves the body empty, which the caller reports.
	body := anyval.OrZero(io.ReadAll(io.LimitReader(res.Body, maxBody)))
	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return tokenResponse{}, wrap(ErrUpstream, "token endpoint returned %d with a body that is not JSON", res.StatusCode)
	}
	if tok.Error != "" || res.StatusCode != http.StatusOK {
		return tokenResponse{}, wrap(ErrProviderError, "token endpoint: %d %s %s", res.StatusCode, tok.Error, tok.ErrorDescription)
	}
	if tok.IDToken == "" {
		return tokenResponse{}, wrap(ErrProviderError, "token response has no id_token")
	}
	return tok, nil
}

// verifyIDToken checks the token against the provider JWKS. On a missing
// key it fetches the JWKS once more, which covers key rotation.
func (f *Flow) verifyIDToken(ctx context.Context, p Provider, m Metadata, idToken string) (map[string]any, error) {
	opts := oidc.TokenOptions{Issuers: []string{m.Issuer}, ClientID: p.ClientID, Now: f.now()}
	keys, err := f.Cache.JWKS(ctx, m.JWKSURI, false)
	if err != nil {
		return nil, err
	}
	claims, err := oidc.VerifyToken(idToken, keys, opts)
	if errors.Is(err, jose.ErrNoKey) {
		if keys, err = f.Cache.JWKS(ctx, m.JWKSURI, true); err != nil {
			return nil, err
		}
		claims, err = oidc.VerifyToken(idToken, keys, opts)
	}
	if err != nil {
		return nil, wrap(ErrSessionInvalid, "id token: %v", err)
	}
	return claims, nil
}

// LogoutURL returns the RP initiated logout URL (OIDC RP-Initiated Logout
// 1.0), or "" when the provider advertises no end_session_endpoint.
func (f *Flow) LogoutURL(ctx context.Context, p Provider, idTokenHint, postLogoutRedirect string) (string, error) {
	m, err := f.Metadata(ctx, p)
	if err != nil {
		return "", err
	}
	return EndSessionURL(m.EndSessionEndpoint, p.ClientID, idTokenHint, postLogoutRedirect), nil
}

// EndSessionURL builds the RP initiated logout URL. It returns "" when
// endpoint is empty.
func EndSessionURL(endpoint, clientID, idTokenHint, postLogoutRedirect string) string {
	if endpoint == "" {
		return ""
	}
	q := url.Values{"client_id": {clientID}}
	if idTokenHint != "" {
		q.Set("id_token_hint", idTokenHint)
	}
	if postLogoutRedirect != "" {
		q.Set("post_logout_redirect_uri", postLogoutRedirect)
	}
	sep := "?"
	if strings.Contains(endpoint, "?") {
		sep = "&"
	}
	return endpoint + sep + q.Encode()
}

// ValidReturnTo reports whether s is a relative path inside the portal:
// it starts with one slash and carries no scheme or host.
func ValidReturnTo(s string) bool {
	if s == "" || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.HasPrefix(s, "/\\") {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "" && u.Host == "" && !strings.ContainsAny(s, "\r\n")
}
