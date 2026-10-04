// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	combinedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/combined/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/combined/v1/combinedv1connect"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/app"
)

// combinedPair is a verifier pair whose adapter, auth service, and
// combined service answer on one test server.
type combinedPair struct {
	backendv1connect.UnimplementedCapabilityServiceHandler
	combinedv1connect.UnimplementedCombinedServiceHandler
}

func (combinedPair) GetCapabilities(context.Context, *connect.Request[backendv1.GetCapabilitiesRequest]) (*connect.Response[backendv1.GetCapabilitiesResponse], error) {
	return connect.NewResponse(&backendv1.GetCapabilitiesResponse{DpgInfo: &backendv1.DpgInfo{DisplayName: "MOSIP Inji"}}), nil
}

func (combinedPair) List(context.Context, *connect.Request[combinedv1.ListRequest]) (*connect.Response[combinedv1.ListResponse], error) {
	return connect.NewResponse(&combinedv1.ListResponse{Templates: []*combinedv1.CombinedTemplate{{Id: "guardian-pair", DisplayName: "Guardian pair"}}}), nil
}

// combinedApp wires the service in a verifier pair that lists the
// combined service in the peer list when runs is true.
func combinedApp(t *testing.T, runs bool) (*app.App, string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(backendv1connect.NewCapabilityServiceHandler(combinedPair{}))
	mux.Handle(combinedv1connect.NewCombinedServiceHandler(combinedPair{}))
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	services := "verifier-results=" + srv.URL + ",dpg-adapter-inji=" + srv.URL + ",verifier-auth=" + srv.URL
	if runs {
		services += ",verifier-combined=" + srv.URL
	}
	cfg := settings(t, map[string]string{
		topology.Env:                   "verifier-inji|" + srv.URL + "|" + services,
		"VCA_DISCOVERY_AUTH_JWKS_URL":  srv.URL + "/.well-known/jwks.json",
		"VCA_DISCOVERY_COMBINED_URL":   srv.URL + "/",
		"VCA_DISCOVERY_PORTAL_PREFIX":  "/discovery",
		"VCA_DISCOVERY_POLICY_TIMEOUT": "5s",
	})
	auth := staff(t)
	a, err := app.Build(cfg, app.Deps{Log: quiet(), SessionKeys: auth.Keys(), Now: func() time.Time { return now },
		Prober: &topology.Prober{Peers: cfg.Peers, Lookup: func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }}})
	if err != nil {
		t.Fatal(err)
	}
	return a, auth.Token(t, "kc|carol", "verifier-operator")
}

// TestCombinedPagesReadTheCombinedServiceOfTheLink is ADR-079 decision
// 4: with VCA_DISCOVERY_COMBINED_URL and a pair that lists the combined
// service, the combined page lists the templates of that service.
func TestCombinedPagesReadTheCombinedServiceOfTheLink(t *testing.T) {
	a, token := combinedApp(t, true)
	if a.Config.CombinedURL == "" || strings.HasSuffix(a.Config.CombinedURL, "/") {
		t.Errorf("combined URL %q", a.Config.CombinedURL)
	}
	rec := serve(a, http.MethodGet, "/discovery/combined/", token)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Guardian pair") {
		t.Fatalf("combined page: %d %s", rec.Code, rec.Body.String())
	}
	off, token := combinedApp(t, false)
	if rec := serve(off, http.MethodGet, "/discovery/combined/", token); rec.Code != http.StatusNotFound {
		t.Errorf("a pair without the combined service: %d", rec.Code)
	}
}
