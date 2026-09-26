// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"context"
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
		DpgInfo:  &backendv1.DpgInfo{DisplayName: "Second stack"},
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
		_, verr := h.app.Login.Signer().Verify(oidcflow.TokenFromRequest(&http.Request{Header: hdr}, ""))
		return verr
	}
	mux := http.NewServeMux()
	mux.Handle(oidcflow.NewAdminHandler(oidcflow.AdminProviders{Registry: registry, Authorize: accept, Roles: []string{"holder"}}))
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

// TestHolderSignInClaimsAreEditable: the admin portal lists the holder
// provider of the holder authorization server of each issuer stack and
// edits the claims it verifies, through the provider RPCs of the adapter
// with the admin session (ADR-056 decision 2).
func TestHolderSignInClaimsAreEditable(t *testing.T) {
	h := newHarnessWith(t, true, signInPair)
	h.signIn(t)
	status, page := h.get(t, "/admin/providers")
	if status != http.StatusOK {
		t.Fatalf("providers = %d\n%s", status, page)
	}
	a11ytest.AssertPage(t, page)
	for _, want := range []string{"Holder sign in claims", "Second stack", "keycloak.internal:8080/realms/vca-holder-realm", `name="verified_claims"`} {
		if !strings.Contains(page, want) {
			t.Errorf("the providers page lacks %q", want)
		}
	}
	id := h.signInRegistry.List()[0].ID
	status, page = h.post(t, "/admin/providers/signin/issuer-inji/"+id, url.Values{"verified_claims": {" national_id, member_no ,national_id"}})
	if status != http.StatusOK || !strings.Contains(page, "The holder sign in of the stack trusts these claims now.") {
		t.Fatalf("save = %d\n%s", status, page)
	}
	got, err := h.signInRegistry.Get(id)
	if err != nil || strings.Join(got.VerifiedClaims, ",") != "national_id,member_no" || got.ClientID != "vca-sign-in" || !got.IsDefault {
		t.Fatalf("the adapter holds %+v %v", got, err)
	}
	if !strings.Contains(h.pageOf(t, "/admin/providers"), `value="national_id, member_no"`) {
		t.Error("the page does not show the saved claims")
	}
	for name, form := range map[string]url.Values{
		"a bad name": {"verified_claims": {"national id"}},
	} {
		status, page = h.post(t, "/admin/providers/signin/issuer-inji/"+id, form)
		if status != http.StatusBadRequest {
			t.Errorf("%s: %d\n%s", name, status, page)
		}
	}
	if status, _ = h.post(t, "/admin/providers/signin/issuer-waltid/"+id, url.Values{"verified_claims": {"x"}}); status != http.StatusNotFound {
		t.Errorf("a pair without the server: %d", status)
	}
	// An empty list clears the claims.
	if status, _ = h.post(t, "/admin/providers/signin/issuer-inji/"+id, url.Values{"verified_claims": {""}}); status != http.StatusOK {
		t.Fatalf("clear = %d", status)
	}
	if got, gerr := h.signInRegistry.Get(id); gerr != nil || len(got.VerifiedClaims) != 0 {
		t.Errorf("the clear kept %v %v", got.VerifiedClaims, gerr)
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
