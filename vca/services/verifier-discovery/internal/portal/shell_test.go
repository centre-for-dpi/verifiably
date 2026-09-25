// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/portal"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/service"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// shellPortal wires the portal under /discovery in the verifier frame of
// the first pair, with the second pair live.
func shellPortal(t *testing.T) (*http.ServeMux, *service.Service) {
	t.Helper()
	_, svc := newPortal(t)
	pair := func(dpg configv1.Dpg) topology.Peer {
		name := topology.PairName(commonv1.Role_ROLE_VERIFIER, dpg)
		return topology.Peer{Pair: name, Role: commonv1.Role_ROLE_VERIFIER, Dpg: dpg, PublicURL: "https://" + name + ".labs.example",
			Services: map[string]string{"verifier-auth": "http://" + name + "-auth:8081"}}
	}
	first, second := pair(configv1.Dpg_DPG_WALTID), pair(configv1.Dpg_DPG_INJI)
	snap := topology.Snapshot{Peers: []topology.Status{
		{Peer: first, State: topology.Live, Capabilities: &backendv1.GetCapabilitiesResponse{DpgInfo: &backendv1.DpgInfo{DisplayName: "First stack"}}},
		{Peer: second, State: topology.Live, Capabilities: &backendv1.GetCapabilitiesResponse{DpgInfo: &backendv1.DpgInfo{DisplayName: "Second stack"}}},
	}}
	shell := staffshell.New(staffshell.Options{
		Role: commonv1.Role_ROLE_VERIFIER, Peers: []topology.Peer{first, second},
		Snapshot: func(context.Context) topology.Snapshot { return snap },
		JWKSURL:  first.Auth() + staffshell.JWKSPath, SignOut: "/discovery/signout",
	})
	p, err := portal.New(portal.Options{Client: svc, Prefix: "/discovery", Shell: shell, SignOut: http.NotFoundHandler()})
	if err != nil {
		t.Fatal(err)
	}
	if p.SignOutPath() != "/discovery/signout" {
		t.Fatalf("sign out path %q", p.SignOutPath())
	}
	mux := http.NewServeMux()
	p.Register(mux)
	return mux, svc
}

// staffGet answers one GET as a signed in verifier operator.
func staffGet(t *testing.T, mux *http.ServeMux, path string) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r = r.WithContext(staffsession.With(r.Context(), staffsession.Session{
		Subject: "kc|otieno", Name: "Akinyi Otieno", CSRF: "csrf-1", Roles: []string{"verifier-operator"},
	}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status %d %s", path, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

// TestDiscoveryPagesInVerifierShell draws the discovery pages in the
// verifier frame with the page of the request marked (P5-01).
func TestDiscoveryPagesInVerifierShell(t *testing.T) {
	mux, _ := shellPortal(t)
	for path, current := range map[string]string{
		"/discovery/":          "Discover schemas",
		"/discovery/types":     "Discover schemas",
		"/discovery/templates": "DCQL builder",
		"/discovery/pe/":       "DIF PE queries",
	} {
		body := staffGet(t, mux, path)
		a11ytest.AssertPage(t, body)
		for _, want := range []string{"First stack", "Second stack", "Akinyi Otieno", `action="/discovery/signout"`, "Overview", "Caching"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s lacks %q", path, want)
			}
		}
		if !regexp.MustCompile(`aria-current="page"[^>]*>` + current + `</a>`).MatchString(body) {
			t.Errorf("%s: want %s marked current", path, current)
		}
	}
}

// TestPeListShowsSavedQueries lists every saved query with its
// Presentation Exchange form, and an empty state without one.
func TestPeListShowsSavedQueries(t *testing.T) {
	mux, svc := shellPortal(t)
	empty := staffGet(t, mux, "/discovery/pe/")
	if !strings.Contains(empty, "No saved query yet.") {
		t.Error("want the empty state")
	}
	if _, err := svc.CreateTemplate(context.Background(), connect.NewRequest(&discoveryv1.CreateTemplateRequest{
		Template: &discoveryv1.PresentationTemplate{DisplayName: "Age check", Purpose: "Check the age.",
			Queries: []*discoveryv1.PresentationTemplate_CredentialQuery{{
				Type: "https://a.example/pid", Format: commonv1.Format_FORMAT_DC_SD_JWT, Claims: []string{"birth_date"},
			}}},
	})); err != nil {
		t.Fatal(err)
	}
	body := staffGet(t, mux, "/discovery/pe/")
	a11ytest.AssertPage(t, body)
	for _, want := range []string{"Age check", "Presentation definition", "input_descriptors", "Open the query"} {
		if !strings.Contains(body, want) {
			t.Errorf("PE list lacks %q", want)
		}
	}
}
