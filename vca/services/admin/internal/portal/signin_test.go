// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// signInCapability answers GetCapabilities as an adapter with a holder
// authorization server.
type signInCapability struct{}

func (signInCapability) GetCapabilities(context.Context, *connect.Request[backendv1.GetCapabilitiesRequest]) (*connect.Response[backendv1.GetCapabilitiesResponse], error) {
	return connect.NewResponse(&backendv1.GetCapabilitiesResponse{
		Roles:    []commonv1.Role{commonv1.Role_ROLE_ISSUER},
		Features: []backendv1.Feature{backendv1.Feature_FEATURE_HOLDER_SIGN_IN_SOURCE},
		DpgInfo:  &backendv1.DpgInfo{DisplayName: "MOSIP Inji"},
	}), nil
}

// signInPair is a live issuer pair whose adapter runs a holder
// authorization server with one seeded holder provider. Its provider
// RPCs accept what the admin key set signed.
func signInPair(t *testing.T, h *harness) func(*config.Config, *app.Deps) {
	t.Helper()
	ready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mustWrite(t, w, []byte("ready"))
	}))
	t.Cleanup(ready.Close)
	registry, err := oidcflow.NewRegistry(oidcflow.NewMemoryPersister(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Seed(oidcflow.SeedProvider(oidcflow.Seed{
		DiscoveryURL: "http://keycloak.internal:8080/realms/vca-holder-realm/.well-known/openid-configuration",
		ClientID:     "vca-sign-in", Roles: []string{"holder"},
	})); err != nil {
		t.Fatal(err)
	}
	h.signInRegistry = registry
	accept := func(_ context.Context, hdr http.Header) error {
		if h.signInDown {
			return errors.New("the adapter is down")
		}
		_, verr := h.app.Login.Signer().Verify(oidcflow.TokenFromRequest(&http.Request{Header: hdr}, ""))
		return verr
	}
	mux := http.NewServeMux()
	mux.Handle(oidcflow.NewAdminHandler(oidcflow.AdminProviders{Registry: registry, Authorize: accept, Roles: []string{"holder"}, OneDefault: true}))
	mux.Handle(backendv1connect.NewCapabilityServiceHandler(signInCapability{}))
	adapter := httptest.NewServer(mux)
	t.Cleanup(adapter.Close)
	return func(cfg *config.Config, deps *app.Deps) {
		cfg.Peers = []topology.Peer{{
			Pair: "issuer-inji", Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_INJI, PublicURL: "https://issuer-inji.example",
			Services: map[string]string{"issuance": ready.URL, topology.AdapterService(configv1.Dpg_DPG_INJI): adapter.URL},
		}}
		deps.Prober = &topology.Prober{Peers: cfg.Peers, Lookup: func(context.Context, string) ([]string, error) {
			return []string{"127.0.0.1"}, nil
		}}
	}
}

// TestHolderProvidersAreManaged: the admin portal lists the providers of
// the holder authorization server of each issuer stack, and adds,
// edits, turns off and removes them through the provider RPCs of the
// adapter with the admin session. The realm seed stays the default
// until an admin picks another (ADR-052 decision 2).
func TestHolderProvidersAreManaged(t *testing.T) {
	h := newHarnessWith(t, true, signInPair)
	h.signIn(t)
	page := h.page(t, "/admin/providers")
	for _, want := range []string{
		"Holder providers", "MOSIP Inji", "vca-holder-realm", "Public client with PKCE",
		`href="/admin/providers/holders/issuer-inji/new"`, "Add a holder provider",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the providers page lacks %q", want)
		}
	}
	form := h.page(t, "/admin/providers/holders/issuer-inji/new")
	for _, want := range []string{`name="discovery_url"`, `name="client_id"`, `name="token_auth"`, `name="secret_store"`, `name="secret_name"`, `name="verified_claims"`, `name="is_default"`, "MOSIP Inji"} {
		if !strings.Contains(form, want) {
			t.Errorf("the form lacks %q", want)
		}
	}
	seed := h.signInRegistry.List()[0]
	status, page := h.post(t, "/admin/providers/holders/issuer-inji/new", url.Values{
		"kind": {"esignet"}, "display_name": {"eSignet"}, "client_id": {"vca-inji"},
		"discovery_url": {"https://esignet.gov.example/v1/esignet/oidc/.well-known/openid-configuration"},
		"token_auth":    {"private_key_jwt"}, "secret_store": {"env"}, "secret_name": {"VCA_INJI_HOLDER_ESIGNET_CLIENT_KEY"},
		"verified_claims": {" individual_id, individual_id"}, "is_default": {"true"},
	})
	if status != http.StatusOK || !strings.Contains(page, "The holder provider is ready.") {
		t.Fatalf("add = %d\n%s", status, page)
	}
	a11ytest.AssertPage(t, page)
	var added oidcflow.Provider
	for _, p := range h.signInRegistry.List() {
		if p.ID != seed.ID {
			added = p
		}
	}
	if added.Kind != oidcflow.KindESignet || added.ClientID != "vca-inji" || !added.IsDefault || !added.Enabled ||
		added.TokenAuthMethod != oidcflow.TokenAuthPrivateKeyJWT || !added.ClientSecret.IsZero() ||
		added.PrivateKey != (oidcflow.SecretRef{Store: oidcflow.SecretEnv, Name: "VCA_INJI_HOLDER_ESIGNET_CLIENT_KEY"}) ||
		strings.Join(added.VerifiedClaims, ",") != "individual_id" || strings.Join(added.Roles, ",") != "holder" ||
		added.RolesClaimPath != "" {
		t.Fatalf("the adapter holds %+v", added)
	}
	if got := h.mustHolder(t, seed.ID); got.IsDefault {
		t.Error("the realm seed kept the default beside the choice of the admin")
	}
	edit := h.page(t, "/admin/providers/holders/issuer-inji/"+added.ID)
	if !strings.Contains(edit, `value="eSignet"`) || !strings.Contains(edit, "individual_id") || strings.Contains(edit, "VCA_INJI_HOLDER_ESIGNET_CLIENT_KEY") {
		t.Errorf("the edit form does not show the record, or echoes its reference:\n%s", edit)
	}
	// An empty reference keeps the key of the record.
	status, page = h.post(t, "/admin/providers/holders/issuer-inji/"+added.ID, url.Values{
		"kind": {"esignet"}, "display_name": {"eSignet of the registry"}, "client_id": {"vca-inji"},
		"discovery_url": {"https://esignet.gov.example/v1/esignet"},
		"token_auth":    {"private_key_jwt"}, "secret_store": {"env"}, "verified_claims": {"individual_id, birthdate"}, "is_default": {"true"},
	})
	if status != http.StatusOK || !strings.Contains(page, "The adapter holds the new settings of the holder provider.") {
		t.Fatalf("save = %d\n%s", status, page)
	}
	got, err := h.signInRegistry.Get(added.ID)
	if err != nil || got.DisplayName != "eSignet of the registry" || got.PrivateKey != added.PrivateKey ||
		got.DiscoveryURL != "https://esignet.gov.example/v1/esignet/.well-known/openid-configuration" ||
		strings.Join(got.VerifiedClaims, ",") != "individual_id,birthdate" || !got.IsDefault {
		t.Fatalf("the adapter holds %+v %v", got, err)
	}
	// A file reference and a client secret.
	status, page = h.post(t, "/admin/providers/holders/issuer-inji/"+seed.ID, url.Values{
		"kind": {"keycloak"}, "display_name": {"Keycloak"}, "client_id": {"vca-inji-authz"},
		"discovery_url": {seed.DiscoveryURL}, "token_auth": {"client_secret_post"}, "secret_store": {"file"},
		"secret_name": {"/run/secrets/vca-inji-authz"},
	})
	if status != http.StatusOK {
		t.Fatalf("a file reference = %d\n%s", status, page)
	}
	if got = h.mustHolder(t, seed.ID); got.ClientSecret != (oidcflow.SecretRef{Store: oidcflow.SecretFile, Name: "/run/secrets/vca-inji-authz"}) ||
		!got.PrivateKey.IsZero() || got.IsDefault || got.Realm != "vca-holder-realm" {
		t.Fatalf("the seed = %+v", got)
	}
	for name, bad := range map[string]url.Values{
		"a bad claim name":          {"display_name": {"x"}, "client_id": {"x"}, "discovery_url": {"https://id.gov.example"}, "token_auth": {"none"}, "verified_claims": {"national id"}},
		"a secret without its name": {"display_name": {"x"}, "client_id": {"x"}, "discovery_url": {"https://id.gov.example"}, "token_auth": {"client_secret_basic"}, "secret_store": {"env"}},
		"a key without its name":    {"display_name": {"x"}, "client_id": {"x"}, "discovery_url": {"https://id.gov.example"}, "token_auth": {"private_key_jwt"}, "secret_store": {"env"}},
		"an unknown method":         {"display_name": {"x"}, "client_id": {"x"}, "discovery_url": {"https://id.gov.example"}, "token_auth": {"magic"}},
		"an unknown store":          {"display_name": {"x"}, "client_id": {"x"}, "discovery_url": {"https://id.gov.example"}, "token_auth": {"client_secret_basic"}, "secret_store": {"kms"}, "secret_name": {"k"}},
		"no client":                 {"display_name": {"x"}, "discovery_url": {"https://id.gov.example"}, "token_auth": {"none"}},
		"no discovery URL":          {"display_name": {"x"}, "client_id": {"x"}, "token_auth": {"none"}},
		"no name":                   {"client_id": {"x"}, "discovery_url": {"https://id.gov.example"}, "token_auth": {"none"}},
	} {
		if status, page = h.post(t, "/admin/providers/holders/issuer-inji/new", bad); status != http.StatusBadRequest {
			t.Errorf("%s = %d\n%s", name, status, page)
		}
	}
	// A secret method on an edit keeps no key as its secret.
	if status, _ = h.post(t, "/admin/providers/holders/issuer-inji/"+added.ID, url.Values{
		"display_name": {"eSignet"}, "client_id": {"vca-inji"}, "discovery_url": {"https://esignet.gov.example/v1/esignet"},
		"token_auth": {"client_secret_basic"}, "secret_store": {"env"},
	}); status != http.StatusBadRequest {
		t.Errorf("a secret method that kept the key = %d", status)
	}
	// Turn off, turn on, remove.
	if status, _ = h.post(t, "/admin/providers/holders/issuer-inji/"+added.ID+"/enable", url.Values{"enabled": {"false"}}); status != http.StatusSeeOther {
		t.Fatalf("turn off = %d", status)
	}
	if got = h.mustHolder(t, added.ID); got.Enabled {
		t.Fatal("the provider is still on")
	}
	if page = h.pageOf(t, "/admin/providers?notice=holder-provider-disabled"); !strings.Contains(page, "New holder sign ins with it fail.") {
		t.Error("the page does not say the provider is off")
	}
	if status, _ = h.post(t, "/admin/providers/holders/issuer-inji/"+added.ID+"/enable", url.Values{"enabled": {"true"}}); status != http.StatusSeeOther {
		t.Fatalf("turn on = %d", status)
	}
	if got = h.mustHolder(t, added.ID); !got.Enabled {
		t.Fatal("the provider is still off")
	}
	if status, _ = h.post(t, "/admin/providers/holders/issuer-inji/"+added.ID+"/delete", nil); status != http.StatusSeeOther {
		t.Fatalf("remove = %d", status)
	}
	if _, err = h.signInRegistry.Get(added.ID); err == nil {
		t.Fatal("the provider is still there")
	}
	// A pair without a holder authorization server has no such pages.
	for _, path := range []string{"/admin/providers/holders/issuer-waltid/new", "/admin/providers/holders/issuer-waltid/" + seed.ID} {
		if status, _ = h.get(t, path); status != http.StatusNotFound {
			t.Errorf("%s = %d", path, status)
		}
	}
	if status, _ = h.post(t, "/admin/providers/holders/issuer-waltid/new", url.Values{"display_name": {"x"}}); status != http.StatusNotFound {
		t.Errorf("a post to a pair without the server = %d", status)
	}
	if status, _ = h.get(t, "/admin/providers/holders/issuer-inji/missing"); status != http.StatusNotFound {
		t.Errorf("an unknown provider = %d", status)
	}
}

// TestHolderProvidersSayWhenTheAdapterIsDown: a pair whose adapter does
// not answer the provider RPCs gets a note, not a broken page.
func TestHolderProvidersSayWhenTheAdapterIsDown(t *testing.T) {
	h := newHarnessWith(t, true, signInPair)
	h.signIn(t)
	h.signInDown = true
	page := h.page(t, "/admin/providers")
	if !strings.Contains(page, "cannot reach the holder sign in of this stack") {
		t.Fatalf("the page does not say the adapter is down:\n%s", page)
	}
	if status, _ := h.get(t, "/admin/providers/holders/issuer-inji/"+oidcflow.SeedID); status == http.StatusOK {
		t.Error("the edit form opened without the adapter")
	}
}

// pageOf reads a page that must answer 200.
func (h *harness) pageOf(t *testing.T, path string) string {
	t.Helper()
	status, page := h.get(t, path)
	if status != http.StatusOK {
		t.Fatalf("%s = %d", path, status)
	}
	return page
}

// mustHolder reads one holder provider of the adapter that must exist.
func (h *harness) mustHolder(t *testing.T, id string) oidcflow.Provider {
	t.Helper()
	p, err := h.signInRegistry.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
