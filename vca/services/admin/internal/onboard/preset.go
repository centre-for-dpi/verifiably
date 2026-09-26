// SPDX-License-Identifier: Apache-2.0

package onboard

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/fetchguard"
	"github.com/centre-for-dpi/vc-adapters/core/oidc"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
)

// Preset holds the defaults of one provider kind (ADR-035 decisions 2
// and 4). The provider form offers one preset per kind. A preset fills
// only the fields the operator left empty.
type Preset struct {
	// Kind is the provider kind the preset describes.
	Kind oidcflow.Kind
	// Label is the name of the kind on the form.
	Label string
	// RolesClaimPath is the claim that carries the roles of a user.
	RolesClaimPath string
	// Scopes are the scopes of a login. Empty keeps the defaults.
	Scopes []string
	// TokenAuthMethod is the client authentication at the token endpoint.
	TokenAuthMethod oidcflow.TokenAuth
	// Hint is one sentence on the form about the kind.
	Hint string
}

// Presets lists the presets in the order of the form: Keycloak first,
// because the setup CLI seeds it, then WSO2 Identity Server, eSignet,
// and any other OpenID Connect provider.
func Presets() []Preset {
	return []Preset{
		{Kind: oidcflow.KindKeycloak, Label: "Keycloak", RolesClaimPath: "realm_access.roles",
			TokenAuthMethod: oidcflow.TokenAuthClientSecretBasic,
			Hint:            "One realm per role. The realm and its console come from the discovery URL."},
		{Kind: oidcflow.KindWSO2, Label: "WSO2 Identity Server", RolesClaimPath: "groups",
			Scopes:          []string{"openid", "profile", "email", "groups"},
			TokenAuthMethod: oidcflow.TokenAuthClientSecretBasic,
			Hint:            "Roles come from the groups claim behind the groups scope."},
		{Kind: oidcflow.KindESignet, Label: "eSignet",
			Scopes:          []string{"openid", "profile"},
			TokenAuthMethod: oidcflow.TokenAuthPrivateKeyJWT,
			Hint:            "The token endpoint takes an RS256 client assertion from an RSA key. The command vca dpg bootstrap registers the client and writes the key file."},
		{Kind: oidcflow.KindGeneric, Label: "Generic OpenID Connect",
			TokenAuthMethod: oidcflow.TokenAuthClientSecretBasic,
			Hint:            "Any provider that serves OpenID Connect Discovery."},
	}
}

// PresetFor returns the preset of a kind. An unknown kind gives the
// generic preset and false.
func PresetFor(kind oidcflow.Kind) (Preset, bool) {
	var generic Preset
	for _, p := range Presets() {
		if p.Kind == kind {
			return p, true
		}
		if p.Kind == oidcflow.KindGeneric {
			generic = p
		}
	}
	return generic, false
}

// Apply fills the empty fields of a record from the preset: the kind,
// the roles claim path, the scopes, and the token endpoint method. For
// Keycloak it also reads the realm and the console out of the discovery
// URL. A value the operator typed stays.
func (p Preset) Apply(record *oidcflow.Provider) {
	record.Kind = p.Kind
	if record.RolesClaimPath == "" {
		record.RolesClaimPath = p.RolesClaimPath
	}
	if len(record.Scopes) == 0 && len(p.Scopes) > 0 {
		record.Scopes = append([]string(nil), p.Scopes...)
	}
	if record.TokenAuthMethod == "" {
		record.TokenAuthMethod = p.TokenAuthMethod
	}
	if p.Kind != oidcflow.KindKeycloak {
		return
	}
	realm, ok := oidcflow.KeycloakRealmOf(record.DiscoveryURL)
	if !ok {
		return
	}
	if record.Realm == "" {
		record.Realm = realm
	}
	if record.ConsoleURL == "" {
		record.ConsoleURL = oidc.Authority(record.DiscoveryURL) + "/admin/" + realm + "/console/"
	}
}

// ProbeResult is what the "Test discovery" action of the provider form
// learned from the metadata document of a provider.
type ProbeResult struct {
	// DiscoveryURL is the document the probe read.
	DiscoveryURL string
	// Metadata is the checked document.
	Metadata
	// PromptValuesSupported lists the prompt values the provider accepts.
	PromptValuesSupported []string
	// TokenAuthMethods lists the token endpoint methods the document
	// names. Empty means the document names none.
	TokenAuthMethods []string
}

// SupportsPromptCreate reports whether the provider registers a user
// through prompt=create (OpenID Connect Prompt Create 1.0).
func (r ProbeResult) SupportsPromptCreate() bool {
	for _, v := range r.PromptValuesSupported {
		if v == "create" {
			return true
		}
	}
	return false
}

// EffectiveTokenAuthMethods returns the methods the document names, or
// client_secret_basic, the default of OpenID Connect Discovery 1.0
// section 3, when it names none.
func (r ProbeResult) EffectiveTokenAuthMethods() []string {
	if len(r.TokenAuthMethods) > 0 {
		return r.TokenAuthMethods
	}
	return []string{string(oidcflow.TokenAuthClientSecretBasic)}
}

// Registration returns the register action the sign in page offers for
// a record of the kind with this metadata (ADR-035 decision 3).
func (r ProbeResult) Registration(kind oidcflow.Kind) oidcflow.Registration {
	p := oidcflow.Provider{Profile: oidcflow.Profile{Kind: kind}}
	return p.EffectiveRegistration(oidcflow.Metadata{PromptValuesSupported: r.PromptValuesSupported})
}

// Probe reads the metadata of an issuer or a discovery URL through the
// guarded fetcher, so a form value can never make the service read a
// private address (ADR-022 decision 1). It returns what the form shows:
// the issuer, the endpoints, the registration support, and the token
// endpoint methods.
func Probe(ctx context.Context, fetcher *fetchguard.Fetcher, issuer string) (ProbeResult, error) {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return ProbeResult{}, fmt.Errorf("%w: the issuer URL is required", ErrDiscovery)
	}
	target := DiscoveryURL(issuer)
	doc, err := fetcher.Get(ctx, target)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("%w: %w", ErrDiscovery, err)
	}
	meta, err := ParseMetadata(doc.Body)
	if err != nil {
		return ProbeResult{}, err
	}
	var extra struct {
		PromptValuesSupported []string `json:"prompt_values_supported"`
		TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
	}
	// ParseMetadata read the document, so the optional members decode
	// without a second check.
	anyval.Discard(json.Unmarshal(doc.Body, &extra))
	return ProbeResult{
		DiscoveryURL: target, Metadata: meta,
		PromptValuesSupported: extra.PromptValuesSupported, TokenAuthMethods: extra.TokenAuthMethods,
	}, nil
}
