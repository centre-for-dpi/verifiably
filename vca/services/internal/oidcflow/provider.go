// SPDX-License-Identifier: Apache-2.0

package oidcflow

import (
	"net/url"
	"os"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/centre-for-dpi/vc-adapters/core/oidc"
	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
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

// Kind names the product behind a provider record. The kind selects a
// fallback, such as the Keycloak registration endpoint, and a label. It
// is never a code dependency (ADR-035 decision 2).
type Kind string

// Provider kinds.
const (
	// KindGeneric is any provider that serves OpenID Connect Discovery.
	KindGeneric Kind = "generic"
	// KindKeycloak is a Keycloak realm.
	KindKeycloak Kind = "keycloak"
	// KindWSO2 is a WSO2 Identity Server tenant.
	KindWSO2 Kind = "wso2"
	// KindESignet is an eSignet deployment.
	KindESignet Kind = "esignet"
)

// Registration says how the login page offers a register action
// (ADR-035 decision 3). The empty value lets the metadata and the kind
// decide, see Provider.EffectiveRegistration.
type Registration string

// Registration modes.
const (
	// RegistrationNone shows no register action.
	RegistrationNone Registration = "none"
	// RegistrationPromptCreate adds prompt=create to the authorization
	// request (OpenID Connect Prompt Create 1.0).
	RegistrationPromptCreate Registration = "prompt_create"
	// RegistrationKeycloakEndpoint sends the browser to the registration
	// endpoint of a Keycloak realm with the same PKCE parameters.
	RegistrationKeycloakEndpoint Registration = "keycloak_endpoint"
)

// TokenAuth is the client authentication method at the token endpoint
// (ADR-035 decision 4). The empty value means client_secret_basic when
// the record names a client secret, and none otherwise.
type TokenAuth string

// Token endpoint authentication methods (RFC 6749 section 2.3.1,
// RFC 7523 section 2.2).
//
//nolint:gosec // G101: the values are method names, not credentials
const (
	TokenAuthClientSecretBasic TokenAuth = "client_secret_basic"
	TokenAuthClientSecretPost  TokenAuth = "client_secret_post"
	TokenAuthPrivateKeyJWT     TokenAuth = "private_key_jwt"
	TokenAuthNone              TokenAuth = "none"
)

// Profile is the part of a provider record that describes the provider
// beyond its endpoints (ADR-035 decision 2): the kind, the realm label,
// the registration mode, the console, the stacks, and the token
// endpoint authentication.
type Profile struct {
	// Kind is the product behind the provider.
	Kind Kind `json:"kind,omitempty"`
	// Realm is the realm or tenant label the login page shows.
	Realm string `json:"realm,omitempty"`
	// Registration is the register action of the login page.
	Registration Registration `json:"registration,omitempty"`
	// ConsoleURL is the administration console of the provider.
	ConsoleURL string `json:"console_url,omitempty"`
	// Stacks lists the stacks whose pairs use the provider, by the short
	// name of the Dpg value. Empty means every stack.
	Stacks []string `json:"stacks,omitempty"`
	// TokenAuthMethod is the client authentication at the token endpoint.
	TokenAuthMethod TokenAuth `json:"token_auth_method,omitempty"`
	// PrivateKey points at the key that signs the client assertion of
	// private_key_jwt. The record never holds the key.
	PrivateKey SecretRef `json:"private_key,omitempty"`
	// IsDefault marks the provider that the setup CLI seeded.
	IsDefault bool `json:"is_default,omitempty"`
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
	// Profile describes the provider beyond its endpoints.
	Profile
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
	if p.TokenAuthMethod == TokenAuthPrivateKeyJWT && p.PrivateKey.IsZero() {
		return wrap(ErrInvalidProvider, "private_key_jwt needs a private_key reference")
	}
	return nil
}

// EffectiveTokenAuth returns the token endpoint authentication method
// of the record: the named method, else HTTP Basic when the record has a
// client secret, else none.
func (p Provider) EffectiveTokenAuth() TokenAuth {
	switch {
	case p.TokenAuthMethod != "":
		return p.TokenAuthMethod
	case !p.ClientSecret.IsZero():
		return TokenAuthClientSecretBasic
	}
	return TokenAuthNone
}

// EffectiveRegistration returns the register action of the record for
// the given metadata (ADR-035 decision 3): the named mode, else
// prompt=create when the metadata lists it, else the Keycloak endpoint
// for a record of kind keycloak, else none.
func (p Provider) EffectiveRegistration(m Metadata) Registration {
	if p.Registration != "" {
		return p.Registration
	}
	for _, v := range m.PromptValuesSupported {
		if v == "create" {
			return RegistrationPromptCreate
		}
	}
	if p.Kind == KindKeycloak {
		return RegistrationKeycloakEndpoint
	}
	return RegistrationNone
}

// KeycloakRealmOf returns the realm name of a Keycloak discovery URL,
// which has the shape <base>/realms/<realm>/.well-known/openid-configuration.
// Any other URL gives false.
func KeycloakRealmOf(discoveryURL string) (string, bool) {
	u, err := url.Parse(discoveryURL)
	if err != nil || u.Host == "" {
		return "", false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	for i := 0; i+2 < len(parts); i++ {
		if parts[i] == "realms" && parts[i+1] != "" && parts[i+2] == ".well-known" {
			return parts[i+1], true
		}
	}
	return "", false
}

// SeedID is the id of the provider that the setup CLI seeds.
const SeedID = "default"

// Seed is the provider that the setup CLI writes to the environment of
// an auth service. The service registers it once under SeedID.
type Seed struct {
	// DiscoveryURL is the discovery document of the provider.
	DiscoveryURL string
	// ClientID is the client id at the provider.
	ClientID string
	// ClientSecretEnv names the environment variable that holds the
	// client secret. Empty means a public client. The record keeps the
	// name, never the value.
	ClientSecretEnv string
	// PublicURL is the base URL a browser uses to reach the provider.
	// Empty selects the authority of the discovery URL.
	PublicURL string
	// RolesClaimPath is the claim path of the roles.
	RolesClaimPath string
	// Roles are the deployment roles the provider may grant.
	Roles []string
	// Scopes are the scopes of a login. Empty selects the defaults.
	Scopes []string
	// InternalAuthority moves the server side endpoints to a container
	// network host (ADR-012 decision 6).
	InternalAuthority string
}

// SeedProvider builds the seeded provider record (ADR-035 decision 2).
// A discovery URL of a Keycloak realm gives a record of kind keycloak
// with that realm, the console of the realm, and the product name as
// its display name; any other URL gives a generic record. The
// registration mode stays open, so the metadata of the provider decides
// at login time.
func SeedProvider(s Seed) Provider {
	p := Provider{
		ID:                SeedID,
		DisplayName:       "Sign in",
		DiscoveryURL:      s.DiscoveryURL,
		ClientID:          s.ClientID,
		Scopes:            s.Scopes,
		RolesClaimPath:    s.RolesClaimPath,
		Roles:             s.Roles,
		Enabled:           true,
		InternalAuthority: s.InternalAuthority,
		Profile:           Profile{Kind: KindGeneric, IsDefault: true},
	}
	if s.ClientSecretEnv != "" {
		p.ClientSecret = SecretRef{Store: SecretEnv, Name: s.ClientSecretEnv}
	}
	realm, ok := KeycloakRealmOf(s.DiscoveryURL)
	if !ok {
		return p
	}
	base := strings.TrimRight(s.PublicURL, "/")
	if base == "" {
		base = oidc.Authority(s.DiscoveryURL)
	}
	p.Kind = KindKeycloak
	p.DisplayName = "Keycloak"
	p.Realm = realm
	p.ConsoleURL = base + "/admin/" + realm + "/console/"
	return p
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
		Profile: Profile{
			Kind:            kindFromProto(m.GetKind()),
			Realm:           m.GetRealm(),
			Registration:    registrationFromProto(m.GetRegistration()),
			ConsoleURL:      m.GetConsoleUrl(),
			TokenAuthMethod: tokenAuthFromProto(m.GetTokenAuthMethod()),
			IsDefault:       m.GetIsDefault(),
		},
	}
	if ref := m.GetClientSecret(); ref != nil {
		p.ClientSecret = SecretRef{Store: secretStoreFromProto(ref.GetStore()), Name: ref.GetName()}
	}
	if ref := m.GetPrivateKey(); ref != nil {
		p.PrivateKey = SecretRef{Store: secretStoreFromProto(ref.GetStore()), Name: ref.GetName()}
	}
	for _, r := range m.GetRoles() {
		p.Roles = append(p.Roles, roleName(r))
	}
	for _, d := range m.GetStacks() {
		if name := stackName(d); name != "" {
			p.Stacks = append(p.Stacks, name)
		}
	}
	if m.GetCreatedAt() != nil {
		p.CreatedAt = m.GetCreatedAt().AsTime()
	}
	return p
}

// ToAdminProto converts a Provider into an admin AuthProvider message.
func ToAdminProto(p Provider) *adminv1.AuthProvider {
	m := &adminv1.AuthProvider{
		Id:              p.ID,
		DisplayName:     p.DisplayName,
		DiscoveryUrl:    p.DiscoveryURL,
		ClientId:        p.ClientID,
		RolesClaimPath:  p.RolesClaimPath,
		Enabled:         p.Enabled,
		Kind:            kindToProto(p.Kind),
		Realm:           p.Realm,
		Registration:    registrationToProto(p.Registration),
		ConsoleUrl:      p.ConsoleURL,
		TokenAuthMethod: tokenAuthToProto(p.TokenAuthMethod),
		IsDefault:       p.IsDefault,
	}
	if !p.ClientSecret.IsZero() {
		m.ClientSecret = &commonv1.SecretRef{Store: secretStoreToProto(p.ClientSecret.Store), Name: p.ClientSecret.Name}
	}
	if !p.PrivateKey.IsZero() {
		m.PrivateKey = &commonv1.SecretRef{Store: secretStoreToProto(p.PrivateKey.Store), Name: p.PrivateKey.Name}
	}
	for _, r := range p.Roles {
		m.Roles = append(m.Roles, roleValue(r))
	}
	for _, name := range p.Stacks {
		if d := stackValue(name); d != configv1.Dpg_DPG_UNSPECIFIED {
			m.Stacks = append(m.Stacks, d)
		}
	}
	if !p.CreatedAt.IsZero() {
		m.CreatedAt = timestamppb.New(p.CreatedAt)
	}
	return m
}

// The enum names carry the string values: PROVIDER_KIND_KEYCLOAK is
// keycloak, REGISTRATION_PROMPT_CREATE is prompt_create, and so on. The
// unspecified value is the empty string both ways.

func kindFromProto(k adminv1.ProviderKind) Kind {
	return Kind(enumName(k.String(), "PROVIDER_KIND_"))
}

func kindToProto(k Kind) adminv1.ProviderKind {
	return adminv1.ProviderKind(enumValue(adminv1.ProviderKind_value, "PROVIDER_KIND_", string(k)))
}

func registrationFromProto(r adminv1.Registration) Registration {
	return Registration(enumName(r.String(), "REGISTRATION_"))
}

func registrationToProto(r Registration) adminv1.Registration {
	return adminv1.Registration(enumValue(adminv1.Registration_value, "REGISTRATION_", string(r)))
}

func tokenAuthFromProto(t adminv1.TokenAuth) TokenAuth {
	return TokenAuth(enumName(t.String(), "TOKEN_AUTH_"))
}

func tokenAuthToProto(t TokenAuth) adminv1.TokenAuth {
	return adminv1.TokenAuth(enumValue(adminv1.TokenAuth_value, "TOKEN_AUTH_", string(t)))
}

// stackName returns the short name of a Dpg value, for example waltid
// for DPG_WALTID, or "" for the unspecified value.
func stackName(d configv1.Dpg) string {
	return enumName(d.String(), "DPG_")
}

// stackValue returns the Dpg value of a short name.
func stackValue(name string) configv1.Dpg {
	return configv1.Dpg(enumValue(configv1.Dpg_value, "DPG_", name))
}

// enumName returns the lower case name of an enum value without its
// prefix, or "" for the unspecified value.
func enumName(name, prefix string) string {
	short := strings.ToLower(strings.TrimPrefix(name, prefix))
	if short == "unspecified" || short == name {
		return ""
	}
	return short
}

// enumValue returns the number of an enum value from its lower case
// name, or 0 when the name is unknown.
func enumValue(values map[string]int32, prefix, name string) int32 {
	if name == "" {
		return 0
	}
	return values[prefix+strings.ToUpper(name)]
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
