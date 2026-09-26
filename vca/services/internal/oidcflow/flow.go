// SPDX-License-Identifier: Apache-2.0

package oidcflow

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
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
	// Register marks a login whose first step was the register action
	// of the provider. The audit log names it a registration.
	Register bool `json:"register,omitempty"`
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
	pend, m, err := f.begin(ctx, p, redirectURI, returnTo)
	if err != nil {
		return Pending{}, "", err
	}
	u := AuthorizeURL(m.AuthorizationEndpoint, p.ClientID, redirectURI, pend.State, pend.Nonce, pend.Verifier, p.EffectiveScopes())
	return pend, u, nil
}

// BeginRegister creates a pending login and the URL that lets a new user
// register at the provider (ADR-035 decision 3). The registration ends
// at the same redirect URI as a login, so Complete finishes it. A
// provider with no register action gives ErrRegisterUnsupported.
func (f *Flow) BeginRegister(ctx context.Context, p Provider, redirectURI, returnTo string) (Pending, string, error) {
	pend, m, err := f.begin(ctx, p, redirectURI, returnTo)
	if err != nil {
		return Pending{}, "", err
	}
	u := RegisterURL(m, p, redirectURI, pend.State, pend.Nonce, pend.Verifier, p.EffectiveScopes())
	if u == "" {
		return Pending{}, "", ErrRegisterUnsupported
	}
	return pend, u, nil
}

// begin checks the provider and the return path, reads the metadata,
// and makes the pending login.
func (f *Flow) begin(ctx context.Context, p Provider, redirectURI, returnTo string) (Pending, Metadata, error) {
	if !p.Enabled {
		return Pending{}, Metadata{}, ErrProviderDisabled
	}
	if returnTo != "" && !ValidReturnTo(returnTo) {
		return Pending{}, Metadata{}, ErrReturnTo
	}
	m, err := f.Metadata(ctx, p)
	if err != nil {
		return Pending{}, Metadata{}, err
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
	return pend, m, nil
}

// AuthorizeURL builds the authorization request URL with PKCE S256,
// state, and nonce (OIDC Core 1.0 section 3.1.2.1).
func AuthorizeURL(endpoint, clientID, redirectURI, state, nonce, verifier string, scopes []string) string {
	return withQuery(endpoint, authorizeQuery(clientID, redirectURI, state, nonce, verifier, scopes))
}

// RegisterURL builds the URL of the register action of a provider
// (ADR-035 decision 3): the authorization request with prompt=create
// when the provider supports it, the registration endpoint of a
// Keycloak realm with the same parameters as the fallback of kind
// keycloak, and "" when the provider offers neither.
func RegisterURL(m Metadata, p Provider, redirectURI, state, nonce, verifier string, scopes []string) string {
	q := authorizeQuery(p.ClientID, redirectURI, state, nonce, verifier, scopes)
	switch p.EffectiveRegistration(m) {
	case RegistrationPromptCreate:
		q.Set("prompt", "create")
		return withQuery(m.AuthorizationEndpoint, q)
	case RegistrationKeycloakEndpoint:
		return withQuery(strings.TrimRight(m.Issuer, "/")+keycloakRegistrationPath, q)
	}
	return ""
}

// keycloakRegistrationPath is the registration endpoint of a Keycloak
// realm, under the issuer of the realm. It takes the parameters of an
// authorization request.
const keycloakRegistrationPath = "/protocol/openid-connect/registrations"

func authorizeQuery(clientID, redirectURI, state, nonce, verifier string, scopes []string) url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {oidc.Challenge(verifier)},
		"code_challenge_method": {"S256"},
	}
}

func withQuery(endpoint string, q url.Values) string {
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
// A confidential client authenticates with the method of the record:
// HTTP Basic or the form body (section 2.3.1), or a signed client
// assertion (RFC 7523 section 2.2) (ADR-035 decision 4).
func (f *Flow) exchange(ctx context.Context, p Provider, m Metadata, pend Pending, code string) (tokenResponse, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {pend.RedirectURI},
		"client_id":     {p.ClientID},
		"code_verifier": {pend.Verifier},
	}
	basic := ""
	switch p.EffectiveTokenAuth() {
	case TokenAuthClientSecretBasic, TokenAuthClientSecretPost:
		secret, err := f.secrets()(p.ClientSecret)
		if err != nil {
			return tokenResponse{}, err
		}
		if p.EffectiveTokenAuth() == TokenAuthClientSecretPost {
			form.Set("client_secret", secret)
		} else {
			basic = secret
		}
	case TokenAuthPrivateKeyJWT:
		assertion, err := f.clientAssertion(p, m.TokenEndpoint)
		if err != nil {
			return tokenResponse{}, err
		}
		form.Set("client_assertion_type", ClientAssertionType)
		form.Set("client_assertion", assertion)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, wrap(ErrUpstream, "build token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if basic != "" {
		req.SetBasicAuth(url.QueryEscape(p.ClientID), url.QueryEscape(basic))
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

// ClientAssertionType is the client_assertion_type of a JWT client
// assertion (RFC 7523 section 2.2).
const ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// clientAssertionTTL bounds a client assertion. One request needs it.
const clientAssertionTTL = time.Minute

// clientAssertion signs the client assertion of private_key_jwt with
// the key behind the private_key reference of the record. The claims
// follow RFC 7523 section 3: iss and sub are the client id, aud is the
// token endpoint, jti is unique, exp is one minute away. A P-256 key
// signs with ES256 and an Ed25519 key with EdDSA (ADR-011 decision 5).
// An RSA key signs with RS256, for a provider such as eSignet that takes
// RS256 only.
func (f *Flow) clientAssertion(p Provider, tokenEndpoint string) (string, error) {
	pemBytes, err := f.secrets()(p.PrivateKey)
	if err != nil {
		return "", err
	}
	key, err := ParseClientKeyPEM([]byte(pemBytes))
	if err != nil {
		return "", wrap(ErrSecret, "private_key of %s: %v", p.ID, err)
	}
	pub, err := jose.PublicJWK(key, "")
	if err != nil {
		return "", wrap(ErrSecret, "private_key of %s: %v", p.ID, err)
	}
	kid, err := jose.Thumbprint(pub)
	if err != nil {
		return "", wrap(ErrSecret, "private_key of %s: %v", p.ID, err)
	}
	now := f.now()
	claims := map[string]any{
		"iss": p.ClientID,
		"sub": p.ClientID,
		"aud": tokenEndpoint,
		"jti": oidc.NewState(),
		"iat": now.Unix(),
		"exp": now.Add(clientAssertionTTL).Unix(),
	}
	var token string
	if rsaKey, isRSA := key.(*rsa.PrivateKey); isRSA {
		token, err = jose.SignRS256(rsaKey, kid, "JWT", claims)
	} else {
		token, err = jose.Sign(key, kid, "JWT", claims)
	}
	if err != nil {
		return "", wrap(ErrSecret, "sign the client assertion of %s: %v", p.ID, err)
	}
	return token, nil
}

// ParseClientKeyPEM reads the private key of a client assertion: an EC
// key, an RSA key in PKCS #1, or a PKCS #8 key of either type or of
// Ed25519.
func ParseClientKeyPEM(raw []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("oidcflow: no PEM block in the client key")
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("oidcflow: parse the client key: %w", err)
	}
	return k, nil
}

// PeekAssertion returns the claims of a client assertion without
// verification, for a test or a log line.
func PeekAssertion(token string) (map[string]any, error) {
	return jose.PeekPayload(token)
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
