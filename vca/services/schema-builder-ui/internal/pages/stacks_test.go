// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/pages"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/service"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// Stack names the adapters report. The tests hold no vendor name
// (ADR-001 decision 4).
const (
	firstStack  = "First stack"
	secondStack = "Second stack"
	thirdStack  = "Third stack"
)

// peer returns one pair of a test deployment with its adapter.
func peer(role commonv1.Role, dpg configv1.Dpg) topology.Peer {
	pair := topology.PairName(role, dpg)
	services := map[string]string{topology.AdapterService(dpg): "http://" + pair + "-adapter:8090"}
	if auth := topology.AuthService(role); auth != "" {
		services[auth] = "http://" + pair + "-auth:8081"
	}
	return topology.Peer{Pair: pair, Role: role, Dpg: dpg, PublicURL: "https://" + pair + ".labs.example", Services: services}
}

// stackShell is the issuer shell of the first pair over a deployment of
// two live issuer stacks, one starting issuer stack, and a live
// verifier pair.
func stackShell() *staffshell.Shell {
	first := peer(commonv1.Role_ROLE_ISSUER, configv1.Dpg_DPG_WALTID)
	second := peer(commonv1.Role_ROLE_ISSUER, configv1.Dpg_DPG_INJI)
	third := peer(commonv1.Role_ROLE_ISSUER, configv1.Dpg_DPG_CREDEBL)
	verifier := peer(commonv1.Role_ROLE_VERIFIER, configv1.Dpg_DPG_CREDEBL)
	caps := func(name, version string) *backendv1.GetCapabilitiesResponse {
		return &backendv1.GetCapabilitiesResponse{DpgInfo: &backendv1.DpgInfo{DisplayName: name, Version: version}}
	}
	snap := topology.Snapshot{Peers: []topology.Status{
		{Peer: first, State: topology.Live, Capabilities: caps(firstStack, "1.0")},
		{Peer: second, State: topology.Live, Capabilities: caps(secondStack, "2.0")},
		{Peer: third, State: topology.Starting},
		{Peer: verifier, State: topology.Live, Capabilities: caps(thirdStack, "3.0")},
	}}
	return staffshell.New(staffshell.Options{
		Role: commonv1.Role_ROLE_ISSUER, Peers: []topology.Peer{first, second, third, verifier},
		Snapshot: func(context.Context) topology.Snapshot { return snap },
		JWKSURL:  first.Auth() + staffshell.JWKSPath, SignOut: "/builder/signout",
	})
}

// stackCatalogs holds one fake catalogue per adapter URL.
type stackCatalogs map[string]*fake.Catalog

func (s stackCatalogs) client(adapter string) backendv1connect.CatalogBackendServiceClient {
	if c, ok := s[adapter]; ok {
		return c
	}
	return &fake.Catalog{}
}

// shellHarness wires the builder pages inside the issuer shell with a
// catalogue per stack, and signs every request in.
func shellHarness(t *testing.T) (http.Handler, stackCatalogs) {
	t.Helper()
	registry := &fake.Registry{}
	svc, err := service.New(service.Options{Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	catalogs := stackCatalogs{
		"http://issuer-waltid-adapter:8090": {Entries: []*backendv1.CredentialConfiguration{{
			Id: "badge_jwt_vc_json", Format: commonv1.Format_FORMAT_JWT_VC_JSON, Type: "OpenBadgeCredential", JsonSchema: document,
		}}},
		"http://issuer-inji-adapter:8090": {Entries: []*backendv1.CredentialConfiguration{{
			Id: "farmer_ldp_vc", Format: commonv1.Format_FORMAT_LDP_VC, Type: "FarmerCredential", JsonSchema: document,
		}}},
	}
	pg, err := pages.New(pages.Options{Builder: svc, Registry: registry, Shell: stackShell(), Catalogs: catalogs.client, RegistryURL: "/portal/"})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	pg.Register(mux)
	sess := staffsession.Session{Subject: "kc|wanjiru", Name: "Wanjiru Kamau", CSRF: "tok"}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r.WithContext(staffsession.With(r.Context(), sess)))
	}), catalogs
}

func serve(t *testing.T, h http.Handler, method, target string, form url.Values) string {
	t.Helper()
	var req *http.Request
	if form == nil {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s %s: status %d: %s", method, target, rec.Code, rec.Body.String())
	}
	a11ytest.AssertPage(t, rec.Body.String())
	return rec.Body.String()
}

// TestBuilderUsesShell checks that the builder draws as a page of the
// issuer shell: the lead of the catalogue, the related fields side by
// side, the tabs of the builder pages, and the preview tabs that mark
// the open one.
func TestBuilderUsesShell(t *testing.T) {
	h, _ := shellHarness(t)
	body := serve(t, h, http.MethodGet, "/builder/", nil)
	for _, want := range []string{
		msg.T("issuer.builder.lead"), `class="field-row"`, `aria-label="` + msg.T("issuer.builder.tabs.label") + `"`,
		`href="/builder/" aria-current="page"`, `class="preview-tabs"`, `aria-expanded="true"`,
		`href="/portal/"`, msg.T("issuer.builder.registry.label"),
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the builder lacks %q", want)
		}
	}
	if strings.Contains(body, `<div class="tabs">`) {
		t.Error("the preview tabs still borrow the class of the page tabs")
	}
}

// TestImportListsLiveStacks checks that the import page offers the
// catalogue of each live issuer stack and no other pair: not a stack
// that is starting, and not a verifier pair. The own stack comes first
// and a query value picks another; an import reads the chosen stack.
func TestImportListsLiveStacks(t *testing.T) {
	h, catalogs := shellHarness(t)
	body := serve(t, h, http.MethodGet, "/builder/import", nil)
	for _, want := range []string{firstStack, secondStack, `value="issuer-waltid"`, `value="issuer-inji"`, "OpenBadgeCredential (badge_jwt_vc_json)"} {
		if !strings.Contains(body, want) {
			t.Errorf("the import page lacks %q", want)
		}
	}
	for _, bad := range []string{`value="issuer-credebl"`, `value="verifier-credebl"`, "FarmerCredential"} {
		if strings.Contains(body, bad) {
			t.Errorf("the import page has %q", bad)
		}
	}
	body = serve(t, h, http.MethodGet, "/builder/import?stack=issuer-inji", nil)
	if !strings.Contains(body, "FarmerCredential (farmer_ldp_vc)") || strings.Contains(body, "OpenBadgeCredential") {
		t.Fatal("the stack query does not pick the catalogue")
	}
	// A pair that is not a live issuer stack falls back to the own one.
	body = serve(t, h, http.MethodGet, "/builder/import?stack=issuer-credebl", nil)
	if !strings.Contains(body, "OpenBadgeCredential") {
		t.Fatal("a starting stack is not refused")
	}
	body = serve(t, h, http.MethodPost, "/builder/import", url.Values{"stack": {"issuer-inji"}, "catalog_entry_id": {"farmer_ldp_vc"}})
	if !strings.Contains(body, `value="FarmerCredential"`) || catalogs["http://issuer-inji-adapter:8090"].Calls == 0 {
		t.Fatal("the import does not read the chosen stack")
	}
	body = serve(t, h, http.MethodPost, "/builder/import", url.Values{"stack": {"issuer-credebl"}, "catalog_entry_id": {"x"}})
	if !strings.Contains(body, msg.T("issuer.builder.import.stack_down", "issuer-credebl")) {
		t.Fatal("an import from a stack that is not live goes through")
	}
}

// TestImportStackCatalogueStates checks what the import page says when
// the catalogue of the chosen stack fails or is empty, and when no
// issuer stack is live.
func TestImportStackCatalogueStates(t *testing.T) {
	h, catalogs := shellHarness(t)
	catalogs["http://issuer-waltid-adapter:8090"].Err = errors.New("down")
	if body := serve(t, h, http.MethodGet, "/builder/import", nil); !strings.Contains(body, msg.T("issuer.builder.import.down", firstStack)) {
		t.Fatal("no sentence for a catalogue that fails")
	}
	if body := serve(t, h, http.MethodGet, "/builder/import?stack=issuer-inji", nil); strings.Contains(body, msg.T("issuer.builder.import.down", secondStack)) {
		t.Fatal("the other stack reads as down")
	}
	catalogs["http://issuer-inji-adapter:8090"].Entries = nil
	if body := serve(t, h, http.MethodGet, "/builder/import?stack=issuer-inji", nil); !strings.Contains(body, msg.T("issuer.builder.import.empty", secondStack)) {
		t.Fatal("no sentence for an empty catalogue")
	}
	// A deployment whose issuer stacks all start offers no stack.
	registry := &fake.Registry{}
	svc, err := service.New(service.Options{Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	own := peer(commonv1.Role_ROLE_ISSUER, configv1.Dpg_DPG_WALTID)
	shell := staffshell.New(staffshell.Options{Role: commonv1.Role_ROLE_ISSUER, Peers: []topology.Peer{own},
		Snapshot: func(context.Context) topology.Snapshot {
			return topology.Snapshot{Peers: []topology.Status{{Peer: own, State: topology.Starting}}}
		}, JWKSURL: own.Auth() + staffshell.JWKSPath})
	pg, err := pages.New(pages.Options{Builder: svc, Registry: registry, Shell: shell, Catalogs: stackCatalogs{}.client})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	pg.Register(mux)
	if body := serve(t, mux, http.MethodGet, "/builder/import", nil); !strings.Contains(body, msg.T("issuer.builder.import.none")) {
		t.Fatal("no sentence without a live stack")
	}
}
