// Package auth defines the provider-agnostic interface for OIDC identity
// providers. Concrete providers (keycloak, wso2is) live in sub-packages.
// Handlers consume this package by interface only; vendor names stay inside
// the sub-packages and backends.json.
package auth

import (
	"context"
	"sync"
)

// Source labels how a provider entered the registry. Used by the admin
// UI to refuse destructive edits on system-managed providers and by
// tests to assert layered-merge precedence. Free-form string so future
// loaders can introduce new sources without expanding an enum.
//
// Conventions:
//   - "system"  — written by deploy.sh into auth-providers.system.json
//   - "user"    — written by the admin UI into auth-providers.user.json
//   - "env"     — VERIFIABLY_OIDC_PROVIDERS env or per-field env overrides
//   - "runtime" — added via legacy POST /auth/custom (in-memory only)
const (
	SourceSystem  = "system"
	SourceUser    = "user"
	SourceEnv     = "env"
	SourceRuntime = "runtime"
)

// Provider describes one configured identity provider.
type Provider interface {
	// ID is the stable key (lower-case, hyphen-free) used in URL paths and on
	// session records. Not shown to users.
	ID() string
	// DisplayName is what renders on the auth page button.
	DisplayName() string
	// Kind is a short protocol/subtitle hint, e.g. "OIDC".
	Kind() string
	// Source is "system" | "user" | "env" | "runtime"; see the Source*
	// constants. The admin UI uses it to decide whether the row is
	// editable/deletable. Providers built before sources were tracked
	// return "" — treat that as equivalent to SourceRuntime.
	Source() string
	// AuthorizeURL returns the full URL to redirect the browser to, including
	// state and PKCE verifier (which it must track per-session).
	AuthorizeURL(ctx context.Context, state, pkceVerifier, redirectURI string) (string, error)
	// Exchange swaps an authorization code for tokens.
	Exchange(ctx context.Context, code, pkceVerifier, redirectURI string) (Token, error)
	// Refresh swaps a refresh token for a new access token.
	Refresh(ctx context.Context, refreshToken string) (Token, error)
	// UserInfo fetches the profile for an access token.
	UserInfo(ctx context.Context, accessToken string) (UserInfo, error)
	// VerifyToken verifies a JWT issued by this provider against its published
	// JWKS (signature, issuer, expiry) and returns the token's string-valued
	// claims. Callers that don't know which provider issued a token can try
	// each in turn and treat any error as "not this provider / invalid". This
	// is the trust anchor for accepting a citizen's OIDC token from an external
	// caller (e.g. self-service eligibility) instead of trusting raw claims.
	VerifyToken(ctx context.Context, rawToken string) (map[string]string, error)
}

// Token is the bag of strings returned by a provider's token endpoint.
type Token struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	TokenType    string
	ExpiresIn    int
	Scope        string
}

// UserInfo is the profile a provider returns for an access token.
//
// Subject/Email/Name are the minimal fields the UI has always needed. The
// remaining standard OIDC claims plus the Claims catch-all support National ID
// issuance: when a citizen authenticates with their organismo's IdP, the
// issuance form can be pre-filled with their verified identity attributes
// instead of an operator re-typing them. See docs/credential-delivery.md
// (identity-bound quadrant).
type UserInfo struct {
	Subject    string
	Email      string
	Name       string
	GivenName  string
	FamilyName string
	// Birthdate is the OIDC `birthdate` claim (ISO 8601 / RFC 3339 full-date).
	Birthdate string
	// Claims holds every string-valued claim from the userinfo response, keyed
	// by its raw OIDC claim name (e.g. "cedula", "national_id", "nationality").
	// Lets the issuance form prefill arbitrary national-id attributes without
	// this package needing to know each schema's field names. Never nil after
	// a successful UserInfo call (may be empty).
	Claims map[string]string
}

// ProviderConfig is the per-provider config shape read from backends.json
// under "authProviders". Kept vendor-agnostic: a "type" key selects a concrete
// implementation (currently just "oidc") and the rest is passed straight to it.
type ProviderConfig struct {
	ID                 string   `json:"id"`
	Type               string   `json:"type"`
	DisplayName        string   `json:"displayName"`
	Kind               string   `json:"kind"`
	IssuerURL          string   `json:"issuerUrl"`
	// PublicIssuerURL, if set, is the browser-facing form of IssuerURL. The
	// server fetches /.well-known/openid-configuration via IssuerURL (usually
	// a docker-internal hostname when verifiably-go runs in a container), but
	// the authorize redirect we hand back to the browser is rewritten to
	// PublicIssuerURL so the user's browser can actually reach it.
	PublicIssuerURL    string   `json:"publicIssuerUrl,omitempty"`
	ClientID           string   `json:"clientId"`
	ClientSecret       string   `json:"clientSecret,omitempty"`
	Scopes             []string `json:"scopes,omitempty"`
	InsecureSkipVerify bool     `json:"insecureSkipVerify,omitempty"`
	// Source is set by the loader, never persisted. JSON tag deliberately
	// "-" so a hand-edited user.json that contains "source":"system" can't
	// trick the loader into mis-labelling itself.
	Source string `json:"-"`
}

// Registry is the set of configured providers. Thread-safe — startup
// registers from auth-providers.json, but the /auth/custom UI form lets
// the operator register additional providers at runtime, so concurrent
// reads (Lookup, Descriptors) and writes (Register) need a mutex.
type Registry struct {
	mu    sync.RWMutex
	items []Provider
}

// NewRegistry constructs an empty provider registry.
func NewRegistry() *Registry { return &Registry{} }

// Register adds a provider. Call order determines display order. If a
// provider with the same ID already exists it is REPLACED — that's how
// the /auth/custom form lets the operator iteratively tweak a custom
// provider without restart-thrash.
func (r *Registry) Register(p Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, existing := range r.items {
		if existing.ID() == p.ID() {
			r.items[i] = p
			return
		}
	}
	r.items = append(r.items, p)
}

// All returns all registered providers in insertion order. Returns a
// snapshot so callers can iterate without holding the lock.
func (r *Registry) All() []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Provider, len(r.items))
	copy(out, r.items)
	return out
}

// Lookup returns the provider with the given ID, or nil.
func (r *Registry) Lookup(id string) Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range r.items {
		if p.ID() == id {
			return p
		}
	}
	return nil
}

// Descriptor is the flat shape templates render from — pure data, no methods.
type Descriptor struct {
	ID     string
	Name   string
	Kind   string
	Source string
}

// Descriptors returns templated-render-safe copies of each provider.
func (r *Registry) Descriptors() []Descriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Descriptor, 0, len(r.items))
	for _, p := range r.items {
		out = append(out, Descriptor{
			ID: p.ID(), Name: p.DisplayName(), Kind: p.Kind(), Source: p.Source(),
		})
	}
	return out
}

// Remove deletes the provider with the given ID. Returns true if a row
// was removed, false if no provider matched. Idempotent — callers can
// safely retry.
func (r *Registry) Remove(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, p := range r.items {
		if p.ID() == id {
			r.items = append(r.items[:i], r.items[i+1:]...)
			return true
		}
	}
	return false
}
