// Package oidc is a tiny OIDC Authorization Code + PKCE provider shared by
// every concrete identity-provider in verifiably-go. Both Keycloak and
// WSO2IS speak OIDC; the only per-vendor differences are base URLs and
// TLS verification defaults, which this package surfaces as Config fields.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/internal/auth"
	"github.com/verifiably/verifiably-go/internal/httpx"
)

// Config describes one OIDC provider instance.
type Config struct {
	// ID is the stable key used in URL paths and provider lookups.
	ID string
	// DisplayName and Kind render on the auth page button.
	DisplayName string
	Kind        string
	// Source labels where the config came from (system file, user file,
	// env, or runtime add-form). See auth.Source* constants. The Provider
	// surfaces this verbatim via Source() so the admin UI can refuse to
	// edit system-managed entries. Optional; an unset value reads as
	// SourceRuntime to callers.
	Source string

	// IssuerURL is the base of the OIDC issuer used for SERVER-SIDE work:
	// fetching the .well-known/openid-configuration document and calling
	// the token endpoint. When running inside Docker this is typically a
	// container hostname (e.g. http://keycloak:8180/realms/...).
	IssuerURL string

	// PublicIssuerURL is the browser-facing URL the authorize_endpoint
	// should resolve against. When empty, falls back to IssuerURL. Set this
	// to the URL the end-user's browser can reach (http://localhost:8180/...).
	PublicIssuerURL string

	// ClientID and ClientSecret are the OIDC client credentials.
	// ClientSecret is optional when PKCE + a public client are in play.
	ClientID     string
	ClientSecret string

	// Scopes sent to the authorize endpoint. Defaults to "openid profile email".
	Scopes []string

	// InsecureSkipVerify disables TLS cert verification. Set true for
	// self-signed demos (e.g. WSO2IS on localhost:9443). Production should
	// leave this false and install the CA cert.
	InsecureSkipVerify bool
}

// Provider implements auth.Provider for any OIDC backend.
type Provider struct {
	cfg    Config
	client *httpx.Client
	meta   *discoveryMeta
}

type discoveryMeta struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	ScopesSupported       []string `json:"scopes_supported"`
}

// New constructs a Provider from Config. Discovery happens lazily on first
// AuthorizeURL / Exchange / UserInfo call so constructor stays non-blocking.
func New(cfg Config) (*Provider, error) {
	if cfg.ID == "" || cfg.IssuerURL == "" {
		return nil, fmt.Errorf("oidc: ID and IssuerURL are required")
	}
	if cfg.DisplayName == "" {
		cfg.DisplayName = cfg.ID
	}
	if cfg.Kind == "" {
		cfg.Kind = "OIDC"
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}
	c := httpx.New("")
	if cfg.InsecureSkipVerify {
		if os.Getenv("VERIFIABLY_ENV") == "production" {
			return nil, fmt.Errorf("oidc: InsecureSkipVerify is not allowed when VERIFIABLY_ENV=production")
		}
		slog.Warn("oidc: TLS certificate verification disabled — for demo/dev environments only",
			"provider_id", cfg.ID, "issuer", cfg.IssuerURL)
		c.HTTP = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			},
		}
	}
	return &Provider{cfg: cfg, client: c}, nil
}

func (p *Provider) ID() string          { return p.cfg.ID }
func (p *Provider) DisplayName() string { return p.cfg.DisplayName }
func (p *Provider) Kind() string        { return p.cfg.Kind }
func (p *Provider) Source() string      { return p.cfg.Source }
func (p *Provider) Config() Config      { return p.cfg }

func (p *Provider) discover(ctx context.Context) (*discoveryMeta, error) {
	if p.meta != nil {
		return p.meta, nil
	}
	u := strings.TrimRight(p.cfg.IssuerURL, "/") + "/.well-known/openid-configuration"
	var m discoveryMeta
	if err := p.client.DoJSON(ctx, http.MethodGet, u, nil, &m, nil); err != nil {
		return nil, fmt.Errorf("discover %s: %w", u, err)
	}
	if m.AuthorizationEndpoint == "" || m.TokenEndpoint == "" {
		return nil, fmt.Errorf("discover: missing endpoints in %s", u)
	}
	// Most IdPs return endpoint URLs built from their OWN advertised base
	// (e.g. WSO2IS hard-codes https://localhost:9443). When the server
	// talks to them via a different hostname (https://wso2is:9443), those
	// advertised URLs are unreachable from our process. Rewrite every
	// endpoint's authority (scheme://host:port) to match IssuerURL so
	// server-side calls hit the right container. AuthorizeURL() flips
	// back to PublicIssuerURL's authority when sending the URL to the
	// browser.
	//
	// The old code tried a string-replace against PublicIssuerURL, which
	// failed whenever the IdP advertised a THIRD variant (localhost) that
	// matched neither Public nor Internal. Authority-level rewriting
	// catches that case since it doesn't depend on the discovered URL
	// sharing any prefix with what we configured.
	internalAuthority := urlAuthority(p.cfg.IssuerURL)
	if internalAuthority != "" {
		m.AuthorizationEndpoint = swapAuthority(m.AuthorizationEndpoint, internalAuthority)
		m.TokenEndpoint = swapAuthority(m.TokenEndpoint, internalAuthority)
		m.UserinfoEndpoint = swapAuthority(m.UserinfoEndpoint, internalAuthority)
		m.JWKSURI = swapAuthority(m.JWKSURI, internalAuthority)
	}
	p.meta = &m
	return p.meta, nil
}

// AuthorizeURL returns the full /authorize URL the browser should redirect to.
// pkceVerifier is the random high-entropy string the caller must store on the
// session and replay into Exchange — it's used to compute the S256 challenge.
//
// When the provider is configured with PublicIssuerURL, we flip the
// authorize endpoint's authority (scheme://host:port) to the browser-reachable
// form even though server-side discovery went through the docker-internal one.
func (p *Provider) AuthorizeURL(ctx context.Context, state, pkceVerifier, redirectURI string) (string, error) {
	m, err := p.discover(ctx)
	if err != nil {
		return "", err
	}
	authorize := m.AuthorizationEndpoint
	if publicAuthority := urlAuthority(p.cfg.PublicIssuerURL); publicAuthority != "" {
		authorize = swapAuthority(authorize, publicAuthority)
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.cfg.ClientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {strings.Join(p.cfg.Scopes, " ")},
		"state":                 {state},
		"code_challenge":        {s256(pkceVerifier)},
		"code_challenge_method": {"S256"},
		// Force the IdP to re-show its login form every time so the user
		// can consciously pick between configured providers — without this,
		// Keycloak/WSO2 short-circuit via their own SSO cookie and auto-log
		// the returning user in, skipping the verifiably-go provider picker
		// entirely on the second round-trip.
		"prompt": {"login"},
	}
	sep := "?"
	if strings.Contains(authorize, "?") {
		sep = "&"
	}
	return authorize + sep + q.Encode(), nil
}

// Exchange swaps an authorization code for tokens at the token endpoint.
func (p *Provider) Exchange(ctx context.Context, code, pkceVerifier, redirectURI string) (auth.Token, error) {
	m, err := p.discover(ctx)
	if err != nil {
		return auth.Token{}, err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {p.cfg.ClientID},
		"code_verifier": {pkceVerifier},
	}
	if p.cfg.ClientSecret != "" {
		form.Set("client_secret", p.cfg.ClientSecret)
	}
	var resp tokenResponse
	if err := p.client.DoForm(ctx, http.MethodPost, m.TokenEndpoint, form, &resp, nil); err != nil {
		return auth.Token{}, err
	}
	return auth.Token{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		IDToken:      resp.IDToken,
		TokenType:    resp.TokenType,
		ExpiresIn:    resp.ExpiresIn,
		Scope:        resp.Scope,
	}, nil
}

// Refresh swaps a refresh token for a new access token.
func (p *Provider) Refresh(ctx context.Context, refreshToken string) (auth.Token, error) {
	m, err := p.discover(ctx)
	if err != nil {
		return auth.Token{}, err
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {p.cfg.ClientID},
	}
	if p.cfg.ClientSecret != "" {
		form.Set("client_secret", p.cfg.ClientSecret)
	}
	var resp tokenResponse
	if err := p.client.DoForm(ctx, http.MethodPost, m.TokenEndpoint, form, &resp, nil); err != nil {
		return auth.Token{}, err
	}
	return auth.Token{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		IDToken:      resp.IDToken,
		TokenType:    resp.TokenType,
		ExpiresIn:    resp.ExpiresIn,
		Scope:        resp.Scope,
	}, nil
}

// UserInfo fetches the profile for an access token.
func (p *Provider) UserInfo(ctx context.Context, accessToken string) (auth.UserInfo, error) {
	m, err := p.discover(ctx)
	if err != nil {
		return auth.UserInfo{}, err
	}
	if m.UserinfoEndpoint == "" {
		return auth.UserInfo{}, nil
	}
	var raw map[string]json.RawMessage
	if err := p.client.DoJSON(httpx.WithToken(ctx, accessToken), http.MethodGet,
		m.UserinfoEndpoint, nil, &raw, nil); err != nil {
		return auth.UserInfo{}, err
	}
	ui := auth.UserInfo{Claims: make(map[string]string, len(raw))}
	// Capture every string-valued claim verbatim so National ID issuance can
	// prefill arbitrary attributes (cedula, nationality, …). Numeric/boolean/
	// object claims are skipped — issuance form fields are text.
	for k := range raw {
		if s, ok := decodeString(raw, k); ok {
			ui.Claims[k] = s
		}
	}
	ui.Subject = ui.Claims["sub"]
	ui.Email = ui.Claims["email"]
	ui.Name = ui.Claims["name"]
	ui.GivenName = ui.Claims["given_name"]
	ui.FamilyName = ui.Claims["family_name"]
	ui.Birthdate = ui.Claims["birthdate"]
	return ui, nil
}

// Compile-time check.
var _ auth.Provider = (*Provider)(nil)

// tokenResponse is the shape of a standard OIDC token endpoint reply.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// --- helpers ---

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// NewPKCEVerifier returns a cryptographically-random high-entropy string
// suitable for use as a PKCE code_verifier.
func NewPKCEVerifier() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// NewState returns a random state value for CSRF protection on the auth
// round-trip.
func NewState() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// urlAuthority extracts "scheme://host:port" from a URL, discarding the path
// and query. Returns "" on parse failure. Used for the discovery-rewrite
// dance where we only want to change which host serves an endpoint, not
// which realm path the endpoint sits under.
func urlAuthority(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// swapAuthority replaces the scheme+host+port of endpoint with the given
// authority, preserving the path and query. Returns endpoint unchanged on
// parse failure or when authority is empty. This lets us rebase a
// discovered URL (https://localhost:9443/oauth2/token?a=b) onto a different
// host (https://wso2is:9443/oauth2/token?a=b) without caring what the
// original authority was — works against localhost, 127.0.0.1, or any
// other host the IdP might advertise.
func swapAuthority(endpoint, authority string) string {
	if endpoint == "" || authority == "" {
		return endpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return endpoint
	}
	a, err := url.Parse(authority)
	if err != nil || a.Scheme == "" || a.Host == "" {
		return endpoint
	}
	u.Scheme = a.Scheme
	u.Host = a.Host
	return u.String()
}

func decodeString(m map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := m[key]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}
