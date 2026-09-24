// SPDX-License-Identifier: Apache-2.0

package onboard_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/fetchguard"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/onboard"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
)

func TestPresetsCoverEveryKind(t *testing.T) {
	presets := onboard.Presets()
	if len(presets) != 4 {
		t.Fatalf("%d presets, want 4", len(presets))
	}
	for _, kind := range []oidcflow.Kind{oidcflow.KindKeycloak, oidcflow.KindWSO2, oidcflow.KindESignet, oidcflow.KindGeneric} {
		p, ok := onboard.PresetFor(kind)
		if !ok || p.Kind != kind || p.Label == "" {
			t.Errorf("%s: preset %+v, ok %v", kind, p, ok)
		}
	}
	// The generic preset is the fallback of an unknown kind.
	if p, ok := onboard.PresetFor("other"); ok || p.Kind != oidcflow.KindGeneric {
		t.Errorf("unknown kind gives %+v, ok %v", p, ok)
	}
}

func TestPresetWSO2FillsDefaults(t *testing.T) {
	p, _ := onboard.PresetFor(oidcflow.KindWSO2)
	record := oidcflow.Provider{DisplayName: "National IdP", DiscoveryURL: "https://is.example/oauth2/token/.well-known/openid-configuration"}
	p.Apply(&record)
	if record.Kind != oidcflow.KindWSO2 {
		t.Errorf("kind = %q", record.Kind)
	}
	// WSO2 Identity Server carries the groups of a user in the groups
	// claim, behind the groups scope.
	if record.RolesClaimPath != "groups" {
		t.Errorf("roles claim path = %q, want groups", record.RolesClaimPath)
	}
	if got := strings.Join(record.Scopes, " "); got != "openid profile email groups" {
		t.Errorf("scopes = %q", got)
	}
	if record.TokenAuthMethod != oidcflow.TokenAuthClientSecretBasic {
		t.Errorf("token auth = %q", record.TokenAuthMethod)
	}
	// A value the operator typed wins over the preset.
	typed := oidcflow.Provider{RolesClaimPath: "roles", Scopes: []string{"openid"}, Profile: oidcflow.Profile{TokenAuthMethod: oidcflow.TokenAuthClientSecretPost}}
	p.Apply(&typed)
	if typed.RolesClaimPath != "roles" || len(typed.Scopes) != 1 || typed.TokenAuthMethod != oidcflow.TokenAuthClientSecretPost {
		t.Errorf("the preset overrode typed values: %+v", typed)
	}
}

func TestPresetESignetUsesPrivateKeyJWT(t *testing.T) {
	p, _ := onboard.PresetFor(oidcflow.KindESignet)
	record := oidcflow.Provider{}
	p.Apply(&record)
	if record.TokenAuthMethod != oidcflow.TokenAuthPrivateKeyJWT {
		t.Errorf("token auth = %q, want private_key_jwt", record.TokenAuthMethod)
	}
	if record.Kind != oidcflow.KindESignet || record.RolesClaimPath != "" {
		t.Errorf("record = %+v", record)
	}
}

func TestPresetKeycloakFillsRealmAndConsole(t *testing.T) {
	p, _ := onboard.PresetFor(oidcflow.KindKeycloak)
	record := oidcflow.Provider{DiscoveryURL: "https://kc.example/realms/vca-issuer-realm/.well-known/openid-configuration"}
	p.Apply(&record)
	if record.Realm != "vca-issuer-realm" || record.ConsoleURL != "https://kc.example/admin/vca-issuer-realm/console/" {
		t.Errorf("record = %+v", record.Profile)
	}
	if record.RolesClaimPath != "realm_access.roles" {
		t.Errorf("roles claim path = %q", record.RolesClaimPath)
	}
	// A discovery URL that names no realm leaves the realm empty.
	other := oidcflow.Provider{DiscoveryURL: "https://idp.example/.well-known/openid-configuration"}
	p.Apply(&other)
	if other.Realm != "" || other.ConsoleURL != "" {
		t.Errorf("no realm in the URL, got %+v", other.Profile)
	}
}

// discoveryServer serves one metadata document.
func discoveryServer(t *testing.T, extra map[string]any) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		doc := map[string]any{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/jwks",
		}
		for k, v := range extra {
			doc[k] = v
		}
		writeJSON(w, http.StatusOK, doc)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// openGuard reaches the loopback test servers over plain http.
func openGuard() *fetchguard.Fetcher {
	return fetchguard.New(fetchguard.Options{Guard: fetchguard.Guard{AllowPrivateNetwork: true, AllowPlainHTTP: true}})
}

func TestProbeReadsDocument(t *testing.T) {
	srv := discoveryServer(t, map[string]any{
		"registration_endpoint":                 "https://idp.example/register",
		"end_session_endpoint":                  "https://idp.example/logout",
		"prompt_values_supported":               []string{"login", "create"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "private_key_jwt"},
	})
	// An issuer URL works as well as the discovery URL.
	probe, err := onboard.Probe(context.Background(), openGuard(), srv.URL)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if probe.Issuer != srv.URL || probe.DiscoveryURL != srv.URL+"/.well-known/openid-configuration" {
		t.Errorf("probe = %+v", probe)
	}
	if !probe.SupportsDynamicRegistration() || !probe.SupportsPromptCreate() {
		t.Errorf("registration flags of %+v", probe)
	}
	if got := strings.Join(probe.TokenAuthMethods, " "); got != "client_secret_basic private_key_jwt" {
		t.Errorf("token methods = %q", got)
	}
	// The register action of the sign in page follows the kind and the
	// metadata (ADR-035 decision 3).
	if probe.Registration(oidcflow.KindGeneric) != oidcflow.RegistrationPromptCreate {
		t.Error("prompt=create is not the register action")
	}
	plain := discoveryServer(t, nil)
	p2, err := onboard.Probe(context.Background(), openGuard(), plain.URL+"/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	if p2.SupportsDynamicRegistration() || p2.SupportsPromptCreate() || len(p2.TokenAuthMethods) != 0 {
		t.Errorf("plain probe = %+v", p2)
	}
	// Without a list the token endpoint takes client_secret_basic, as
	// OpenID Connect Discovery 1.0 section 3 says.
	if got := strings.Join(p2.EffectiveTokenAuthMethods(), " "); got != "client_secret_basic" {
		t.Errorf("effective methods = %q", got)
	}
	if p2.Registration(oidcflow.KindKeycloak) != oidcflow.RegistrationKeycloakEndpoint || p2.Registration(oidcflow.KindGeneric) != oidcflow.RegistrationNone {
		t.Error("the register action ignores the kind")
	}
}

func TestProbeRejectsPrivateAddress(t *testing.T) {
	srv := discoveryServer(t, nil)
	// The default guard refuses a loopback address and plain http.
	strict := fetchguard.New(fetchguard.Options{})
	_, err := onboard.Probe(context.Background(), strict, srv.URL)
	if !errors.Is(err, fetchguard.ErrRefused) {
		t.Fatalf("err = %v, want the guard refusal", err)
	}
	if !errors.Is(err, onboard.ErrDiscovery) {
		t.Errorf("err = %v, want ErrDiscovery too", err)
	}
	// A document that is not metadata is a discovery error.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"issuer": "x"})
	}))
	t.Cleanup(bad.Close)
	if _, err := onboard.Probe(context.Background(), openGuard(), bad.URL); !errors.Is(err, onboard.ErrDiscovery) {
		t.Errorf("bad document err = %v", err)
	}
	if _, err := onboard.Probe(context.Background(), openGuard(), ""); !errors.Is(err, onboard.ErrDiscovery) {
		t.Errorf("empty issuer err = %v", err)
	}
}
