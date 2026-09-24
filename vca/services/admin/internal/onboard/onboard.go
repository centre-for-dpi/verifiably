// SPDX-License-Identifier: Apache-2.0

// Package onboard adds an OpenID Connect provider to the admin service
// (ADR-010 decision 3). It reads the provider metadata with OpenID
// Connect Discovery 1.0. When the metadata names a registration
// endpoint, it registers a client with OAuth 2.0 Dynamic Client
// Registration (RFC 7591). When the metadata names no registration
// endpoint, the caller must supply a client id and a secret reference.
//
// The package also holds the Vault, which keeps a client secret out of
// the provider record. A record stores a reference only (ADR-015).
package onboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
)

// Errors of the package.
var (
	// ErrDiscovery reports a metadata document that cannot be used.
	ErrDiscovery = errors.New("onboard: the provider metadata cannot be used")
	// ErrRegistration reports a failed dynamic client registration.
	ErrRegistration = errors.New("onboard: dynamic client registration failed")
	// ErrClientID reports a provider without a client id and without a
	// registration endpoint.
	ErrClientID = errors.New("onboard: the provider needs a client id")
	// ErrSecret reports a secret that cannot be stored or read.
	ErrSecret = errors.New("onboard: the client secret is not available")
)

// maxBody caps a provider response.
const maxBody = 1 << 20

// EnvPrefix names the memory secrets of the vault. The name goes into
// the provider record as an environment reference.
const EnvPrefix = "VCA_ADMIN_CLIENT_SECRET_"

// Metadata is the part of a provider metadata document that onboarding
// needs. It adds the endpoints that core/oidc does not carry.
type Metadata struct {
	Issuer                      string   `json:"issuer"`
	AuthorizationEndpoint       string   `json:"authorization_endpoint"`
	TokenEndpoint               string   `json:"token_endpoint"`
	JWKSURI                     string   `json:"jwks_uri"`
	RegistrationEndpoint        string   `json:"registration_endpoint"`
	DeviceAuthorizationEndpoint string   `json:"device_authorization_endpoint"`
	EndSessionEndpoint          string   `json:"end_session_endpoint"`
	ScopesSupported             []string `json:"scopes_supported"`
	GrantTypesSupported         []string `json:"grant_types_supported"`
	CodeChallengeMethods        []string `json:"code_challenge_methods_supported"`
}

// SupportsDynamicRegistration reports whether the provider advertises a
// registration endpoint (RFC 7591).
func (m Metadata) SupportsDynamicRegistration() bool { return m.RegistrationEndpoint != "" }

// SupportsDeviceGrant reports whether the provider advertises the device
// authorization endpoint (RFC 8628, ADR-010 decision 6).
func (m Metadata) SupportsDeviceGrant() bool { return m.DeviceAuthorizationEndpoint != "" }

// ParseMetadata decodes and checks a metadata document. The issuer, the
// authorization endpoint, the token endpoint, and the JWKS URI are
// required. Every endpoint must be an absolute http or https URL.
func ParseMetadata(raw []byte) (Metadata, error) {
	var m Metadata
	if err := json.Unmarshal(raw, &m); err != nil {
		return Metadata{}, fmt.Errorf("%w: the document is not JSON", ErrDiscovery)
	}
	required := map[string]string{
		"issuer":                 m.Issuer,
		"authorization_endpoint": m.AuthorizationEndpoint,
		"token_endpoint":         m.TokenEndpoint,
		"jwks_uri":               m.JWKSURI,
	}
	for name, value := range required {
		if !absoluteHTTP(value) {
			return Metadata{}, fmt.Errorf("%w: %s must be an absolute http or https URL", ErrDiscovery, name)
		}
	}
	optional := map[string]string{
		"registration_endpoint":         m.RegistrationEndpoint,
		"device_authorization_endpoint": m.DeviceAuthorizationEndpoint,
		"end_session_endpoint":          m.EndSessionEndpoint,
	}
	for name, value := range optional {
		if value != "" && !absoluteHTTP(value) {
			return Metadata{}, fmt.Errorf("%w: %s must be an absolute http or https URL", ErrDiscovery, name)
		}
	}
	return m, nil
}

// DiscoveryURL returns the metadata URL of an issuer. An input that
// already ends with a well known path is returned unchanged.
func DiscoveryURL(issuer string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(issuer), "/")
	if strings.Contains(trimmed, "/.well-known/") {
		return trimmed
	}
	return trimmed + "/.well-known/openid-configuration"
}

// Fetcher does one HTTP request. The http.Client of the service
// satisfies it, and a test supplies a fake.
type Fetcher interface {
	Do(req *http.Request) (*http.Response, error)
}

// Discover reads and checks the metadata at discoveryURL.
func Discover(ctx context.Context, client Fetcher, discoveryURL string) (Metadata, error) {
	if !absoluteHTTP(discoveryURL) {
		return Metadata{}, fmt.Errorf("%w: the discovery URL must be an absolute http or https URL", ErrDiscovery)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return Metadata{}, fmt.Errorf("%w: %w", ErrDiscovery, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return Metadata{}, fmt.Errorf("%w: the provider could not be reached", ErrDiscovery)
	}
	// Nothing can act on a close fault of a response body.
	defer func() { ignored := resp.Body.Close(); _ = ignored }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return Metadata{}, fmt.Errorf("%w: the document could not be read", ErrDiscovery)
	}
	if resp.StatusCode != http.StatusOK {
		return Metadata{}, fmt.Errorf("%w: the provider returned status %d", ErrDiscovery, resp.StatusCode)
	}
	return ParseMetadata(body)
}

// RegisterRequest is the client metadata of a registration request
// (RFC 7591 section 2).
type RegisterRequest struct {
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	ApplicationType         string   `json:"application_type,omitempty"`
}

// RegisterResponse is the client information of a registration response
// (RFC 7591 section 3.2.1).
type RegisterResponse struct {
	ClientID                string `json:"client_id"`
	ClientSecret            string `json:"client_secret"`
	RegistrationAccessToken string `json:"registration_access_token"`
	RegistrationClientURI   string `json:"registration_client_uri"`
	Error                   string `json:"error"`
	ErrorDescription        string `json:"error_description"`
}

// Register posts a registration request to the registration endpoint.
// The request asks for the authorization code grant only, because
// RFC 9700 forbids the implicit flow.
func Register(ctx context.Context, client Fetcher, endpoint string, body RegisterRequest, initialToken string) (RegisterResponse, error) {
	if !absoluteHTTP(endpoint) {
		return RegisterResponse{}, fmt.Errorf("%w: the registration endpoint is not an absolute URL", ErrRegistration)
	}
	if len(body.RedirectURIs) == 0 {
		return RegisterResponse{}, fmt.Errorf("%w: a redirect URI is required", ErrRegistration)
	}
	if len(body.GrantTypes) == 0 {
		body.GrantTypes = []string{"authorization_code"}
	}
	if len(body.ResponseTypes) == 0 {
		body.ResponseTypes = []string{"code"}
	}
	if body.ApplicationType == "" {
		body.ApplicationType = "web"
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return RegisterResponse{}, fmt.Errorf("%w: %w", ErrRegistration, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(raw)))
	if err != nil {
		return RegisterResponse{}, fmt.Errorf("%w: %w", ErrRegistration, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if initialToken != "" {
		req.Header.Set("Authorization", "Bearer "+initialToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return RegisterResponse{}, fmt.Errorf("%w: the provider could not be reached", ErrRegistration)
	}
	// Nothing can act on a close fault of a response body.
	defer func() { ignored := resp.Body.Close(); _ = ignored }()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return RegisterResponse{}, fmt.Errorf("%w: the response could not be read", ErrRegistration)
	}
	var out RegisterResponse
	if err := json.Unmarshal(answer, &out); err != nil {
		return RegisterResponse{}, fmt.Errorf("%w: the response is not JSON", ErrRegistration)
	}
	if out.Error != "" {
		return RegisterResponse{}, fmt.Errorf("%w: %s %s", ErrRegistration, out.Error, out.ErrorDescription)
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return RegisterResponse{}, fmt.Errorf("%w: the provider returned status %d", ErrRegistration, resp.StatusCode)
	}
	if out.ClientID == "" {
		return RegisterResponse{}, fmt.Errorf("%w: the response has no client_id", ErrRegistration)
	}
	return out, nil
}

// Vault keeps a client secret out of the provider record. With a
// directory it writes one file for each secret. Without a directory it
// keeps the value in process memory, so the secret is lost at a restart.
type Vault struct {
	dir string
	mu  sync.RWMutex
	mem map[string]string
}

// NewVault returns a vault. An empty dir selects memory only.
func NewVault(dir string) *Vault { return &Vault{dir: dir, mem: map[string]string{}} }

// Store keeps the secret of one provider and returns its reference.
// An empty secret returns an empty reference, which marks a public
// client.
func (v *Vault) Store(providerID, secret string) (oidcflow.SecretRef, error) {
	if secret == "" {
		return oidcflow.SecretRef{}, nil
	}
	if strings.TrimSpace(providerID) == "" {
		return oidcflow.SecretRef{}, fmt.Errorf("%w: the provider id is required", ErrSecret)
	}
	if v.dir == "" {
		name := EnvPrefix + SafeName(providerID)
		v.mu.Lock()
		v.mem[name] = secret
		v.mu.Unlock()
		return oidcflow.SecretRef{Store: oidcflow.SecretEnv, Name: name}, nil
	}
	if err := os.MkdirAll(v.dir, 0o700); err != nil {
		return oidcflow.SecretRef{}, fmt.Errorf("%w: %w", ErrSecret, err)
	}
	path := filepath.Join(v.dir, "client_secret_"+SafeName(providerID))
	if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
		return oidcflow.SecretRef{}, fmt.Errorf("%w: %w", ErrSecret, err)
	}
	return oidcflow.SecretRef{Store: oidcflow.SecretFile, Name: path}, nil
}

// Resolve reads the value behind a reference. It looks in memory first,
// then in the environment and the file system.
func (v *Vault) Resolve(ref oidcflow.SecretRef) (string, error) {
	v.mu.RLock()
	value, ok := v.mem[ref.Name]
	v.mu.RUnlock()
	if ok {
		return value, nil
	}
	return oidcflow.EnvFileSecrets(ref)
}

// SafeName returns an upper case name of letters, digits, and
// underscores, so it is safe in a file name and in an environment
// variable name.
func SafeName(raw string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(raw) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

// Options describe one onboarding.
type Options struct {
	// ID is the provider id. It is required, because the secret
	// reference carries it.
	ID string
	// DisplayName is shown on the login page.
	DisplayName string
	// DiscoveryURL or Issuer names the provider. An issuer becomes a
	// discovery URL.
	DiscoveryURL string
	// ClientID is the client id at the provider. It is used when the
	// provider supports no dynamic registration.
	ClientID string
	// ClientSecret is a reference the caller already holds.
	ClientSecret oidcflow.SecretRef
	// Dynamic asks for dynamic client registration.
	Dynamic bool
	// InitialAccessToken authenticates the registration request, when
	// the provider needs one.
	InitialAccessToken string
	// RedirectURI is the exact redirect URI of the admin portal.
	RedirectURI string
	// Scopes are the scopes of a login. Empty selects the defaults.
	Scopes []string
	// RolesClaimPath is the dot path of the claim that carries roles.
	RolesClaimPath string
	// Roles are the deployment roles this provider may grant.
	Roles []string
	// Enabled says whether the provider accepts logins.
	Enabled bool
	// Profile describes the provider beyond its endpoints: the kind,
	// the realm, the registration mode, the console, the stacks, and the
	// token endpoint authentication (ADR-035 decision 2).
	Profile oidcflow.Profile
}

// Result is the outcome of one onboarding.
type Result struct {
	// Provider is the record to store in the registry.
	Provider oidcflow.Provider
	// Metadata is the provider metadata that the onboarding read.
	Metadata Metadata
	// Registered reports whether dynamic client registration ran.
	Registered bool
}

// Run performs the onboarding: discovery, then dynamic client
// registration when the provider supports it and the caller asked for
// it. The secret goes into the vault, never into the record.
func Run(ctx context.Context, client Fetcher, vault *Vault, o Options) (Result, error) {
	if strings.TrimSpace(o.ID) == "" {
		return Result{}, fmt.Errorf("%w: the provider id is required", ErrDiscovery)
	}
	discovery := o.DiscoveryURL
	if discovery != "" && !strings.Contains(discovery, "/.well-known/") {
		discovery = DiscoveryURL(discovery)
	}
	meta, err := Discover(ctx, client, discovery)
	if err != nil {
		return Result{}, err
	}
	p := oidcflow.Provider{
		ID:             o.ID,
		DisplayName:    o.DisplayName,
		DiscoveryURL:   discovery,
		ClientID:       o.ClientID,
		ClientSecret:   o.ClientSecret,
		Scopes:         o.Scopes,
		RolesClaimPath: o.RolesClaimPath,
		Roles:          o.Roles,
		Enabled:        o.Enabled,
		Profile:        o.Profile,
	}
	res := Result{Metadata: meta}
	if o.Dynamic {
		if !meta.SupportsDynamicRegistration() {
			return Result{}, fmt.Errorf("%w: the provider advertises no registration_endpoint", ErrRegistration)
		}
		reg, err := Register(ctx, client, meta.RegistrationEndpoint, RegisterRequest{
			ClientName:              o.DisplayName,
			RedirectURIs:            []string{o.RedirectURI},
			Scope:                   strings.Join(p.EffectiveScopes(), " "),
			TokenEndpointAuthMethod: "client_secret_basic",
		}, o.InitialAccessToken)
		if err != nil {
			return Result{}, err
		}
		ref, err := vault.Store(o.ID, reg.ClientSecret)
		if err != nil {
			return Result{}, err
		}
		p.ClientID = reg.ClientID
		p.ClientSecret = ref
		res.Registered = true
	}
	if strings.TrimSpace(p.ClientID) == "" {
		return Result{}, ErrClientID
	}
	if err := p.Validate(); err != nil {
		return Result{}, err
	}
	res.Provider = p
	return res, nil
}

func absoluteHTTP(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}
