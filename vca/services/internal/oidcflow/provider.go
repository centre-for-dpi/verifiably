// SPDX-License-Identifier: Apache-2.0

package oidcflow

import (
	"net/url"
	"os"
	"strings"
	"time"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// DefaultScopes are the scopes a provider gets when the record names none.
var DefaultScopes = []string{"openid", "profile", "email"}

// SecretStore names where a client secret lives (vca.common.v1.SecretRef).
type SecretStore string

// Secret stores.
const (
	SecretNone SecretStore = ""
	SecretEnv  SecretStore = "env"
	SecretFile SecretStore = "file"
	SecretKMS  SecretStore = "kms"
)

// SecretRef points at a client secret. A record never holds the value.
type SecretRef struct {
	Store SecretStore `json:"store,omitempty"`
	Name  string      `json:"name,omitempty"`
}

// IsZero reports whether the reference names no secret (a public client).
func (s SecretRef) IsZero() bool { return s.Store == SecretNone || s.Name == "" }

// SecretResolver reads the value behind a reference.
type SecretResolver func(SecretRef) (string, error)

// EnvFileSecrets resolves env and file references with the process
// environment and the file system. It returns "" for an empty reference.
func EnvFileSecrets(ref SecretRef) (string, error) {
	switch {
	case ref.IsZero():
		return "", nil
	case ref.Store == SecretEnv:
		v, ok := os.LookupEnv(ref.Name)
		if !ok {
			return "", wrap(ErrSecret, "environment variable %s is not set", ref.Name)
		}
		return v, nil
	case ref.Store == SecretFile:
		b, err := os.ReadFile(ref.Name)
		if err != nil {
			return "", wrap(ErrSecret, "read %s: %v", ref.Name, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return "", wrap(ErrSecret, "store %q is not supported", ref.Store)
}

// Provider is one registered OpenID Connect provider.
type Provider struct {
	// ID is the record id. The service assigns it on create.
	ID string `json:"id"`
	// DisplayName is shown on the login page.
	DisplayName string `json:"display_name"`
	// DiscoveryURL is the URL of the OpenID Provider metadata document.
	DiscoveryURL string `json:"discovery_url"`
	// ClientID is the OAuth 2.0 client id at the provider.
	ClientID string `json:"client_id"`
	// ClientSecret points at the client secret. Empty for public clients.
	ClientSecret SecretRef `json:"client_secret"`
	// Scopes are the scopes of the authorization request.
	Scopes []string `json:"scopes,omitempty"`
	// RolesClaimPath is the dot path of the claim that carries roles.
	RolesClaimPath string `json:"roles_claim_path,omitempty"`
	// Roles are the deployment roles that can log in with this provider.
	Roles []string `json:"roles,omitempty"`
	// Enabled says whether the provider accepts logins.
	Enabled bool `json:"enabled"`
	// LogoURI is an optional logo for the login page.
	LogoURI string `json:"logo_uri,omitempty"`
	// InternalAuthority, when set, replaces scheme://host of the token,
	// userinfo, and JWKS endpoints. The browser still uses the public
	// authorization endpoint (ADR-012 decision 6).
	InternalAuthority string `json:"internal_authority,omitempty"`
	// CreatedAt is the creation time.
	CreatedAt time.Time `json:"created_at"`
}

// Validate checks the fields that a login needs.
func (p Provider) Validate() error {
	if strings.TrimSpace(p.ID) == "" {
		return wrap(ErrInvalidProvider, "id is required")
	}
	if strings.TrimSpace(p.ClientID) == "" {
		return wrap(ErrInvalidProvider, "client_id is required")
	}
	if !isAbsoluteHTTP(p.DiscoveryURL) {
		return wrap(ErrInvalidProvider, "discovery_url must be an absolute http or https URL")
	}
	if p.InternalAuthority != "" && !isAbsoluteHTTP(p.InternalAuthority) {
		return wrap(ErrInvalidProvider, "internal_authority must be an absolute http or https URL")
	}
	return nil
}

// EffectiveScopes returns the scopes, or DefaultScopes when none are set.
// The openid scope is always present.
func (p Provider) EffectiveScopes() []string {
	if len(p.Scopes) == 0 {
		return DefaultScopes
	}
	for _, s := range p.Scopes {
		if s == "openid" {
			return p.Scopes
		}
	}
	return append([]string{"openid"}, p.Scopes...)
}

func isAbsoluteHTTP(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// FromAdminProto converts an admin AuthProvider message into a Provider.
func FromAdminProto(m *adminv1.AuthProvider) Provider {
	p := Provider{
		ID:             m.GetId(),
		DisplayName:    m.GetDisplayName(),
		DiscoveryURL:   m.GetDiscoveryUrl(),
		ClientID:       m.GetClientId(),
		RolesClaimPath: m.GetRolesClaimPath(),
		Enabled:        m.GetEnabled(),
	}
	if ref := m.GetClientSecret(); ref != nil {
		p.ClientSecret = SecretRef{Store: secretStoreFromProto(ref.GetStore()), Name: ref.GetName()}
	}
	for _, r := range m.GetRoles() {
		p.Roles = append(p.Roles, roleName(r))
	}
	if m.GetCreatedAt() != nil {
		p.CreatedAt = m.GetCreatedAt().AsTime()
	}
	return p
}

// ToAdminProto converts a Provider into an admin AuthProvider message.
func ToAdminProto(p Provider) *adminv1.AuthProvider {
	m := &adminv1.AuthProvider{
		Id:             p.ID,
		DisplayName:    p.DisplayName,
		DiscoveryUrl:   p.DiscoveryURL,
		ClientId:       p.ClientID,
		RolesClaimPath: p.RolesClaimPath,
		Enabled:        p.Enabled,
	}
	if !p.ClientSecret.IsZero() {
		m.ClientSecret = &commonv1.SecretRef{Store: secretStoreToProto(p.ClientSecret.Store), Name: p.ClientSecret.Name}
	}
	for _, r := range p.Roles {
		m.Roles = append(m.Roles, roleValue(r))
	}
	if !p.CreatedAt.IsZero() {
		m.CreatedAt = timestamppb.New(p.CreatedAt)
	}
	return m
}

func secretStoreFromProto(s commonv1.SecretRef_Store) SecretStore {
	switch s {
	case commonv1.SecretRef_STORE_ENV:
		return SecretEnv
	case commonv1.SecretRef_STORE_FILE:
		return SecretFile
	case commonv1.SecretRef_STORE_KMS:
		return SecretKMS
	}
	return SecretNone
}

func secretStoreToProto(s SecretStore) commonv1.SecretRef_Store {
	switch s {
	case SecretEnv:
		return commonv1.SecretRef_STORE_ENV
	case SecretFile:
		return commonv1.SecretRef_STORE_FILE
	case SecretKMS:
		return commonv1.SecretRef_STORE_KMS
	}
	return commonv1.SecretRef_STORE_UNSPECIFIED
}

func roleName(r commonv1.Role) string {
	switch r {
	case commonv1.Role_ROLE_ISSUER:
		return "issuer"
	case commonv1.Role_ROLE_HOLDER:
		return "holder"
	case commonv1.Role_ROLE_VERIFIER:
		return "verifier"
	case commonv1.Role_ROLE_ADMIN:
		return "admin"
	}
	return ""
}

func roleValue(name string) commonv1.Role {
	switch name {
	case "issuer":
		return commonv1.Role_ROLE_ISSUER
	case "holder":
		return commonv1.Role_ROLE_HOLDER
	case "verifier":
		return commonv1.Role_ROLE_VERIFIER
	case "admin":
		return commonv1.Role_ROLE_ADMIN
	}
	return commonv1.Role_ROLE_UNSPECIFIED
}
