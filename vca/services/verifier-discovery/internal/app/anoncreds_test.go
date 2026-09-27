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
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/app"
)

// anonStack is a verifier adapter that asks for AnonCreds proofs.
type anonStack struct {
	backendv1connect.UnimplementedVerifierBackendServiceHandler
	backendv1connect.UnimplementedCapabilityServiceHandler
	feature bool
}

func (s anonStack) GetCapabilities(context.Context, *connect.Request[backendv1.GetCapabilitiesRequest]) (*connect.Response[backendv1.GetCapabilitiesResponse], error) {
	out := &backendv1.GetCapabilitiesResponse{DpgInfo: &backendv1.DpgInfo{DisplayName: "CREDEBL"}}
	if s.feature {
		out.Features = []backendv1.Feature{backendv1.Feature_FEATURE_ANONCREDS_PROOF}
	}
	return connect.NewResponse(out), nil
}

func (anonStack) ListProofSchemas(context.Context, *connect.Request[backendv1.ListProofSchemasRequest]) (*connect.Response[backendv1.ListProofSchemasResponse], error) {
	return connect.NewResponse(&backendv1.ListProofSchemasResponse{Schemas: []*backendv1.ProofSchema{{
		Id: "did:indy:bcovrin:testnet:Ra8F/anoncreds/v0/SCHEMA/Farmer/1.0", Name: "Farmer", Version: "1.0", Attributes: []string{"fullName", "acres"},
	}}}), nil
}

// anonApp wires the service with one live CREDEBL verifier stack.
func anonApp(t *testing.T, feature bool) (*app.App, string) {
	t.Helper()
	stack := anonStack{feature: feature}
	mux := http.NewServeMux()
	mux.Handle(backendv1connect.NewVerifierBackendServiceHandler(stack))
	mux.Handle(backendv1connect.NewCapabilityServiceHandler(stack))
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	peers := "verifier-credebl|" + srv.URL + "|verifier-results=" + srv.URL + ",dpg-adapter-credebl=" + srv.URL
	cfg := settings(t, map[string]string{topology.Env: peers})
	auth := staff(t)
	a, err := app.Build(cfg, app.Deps{Log: quiet(), SessionKeys: auth.Keys(), Now: func() time.Time { return now },
		Prober: &topology.Prober{Peers: cfg.Peers, Lookup: func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }}})
	if err != nil {
		t.Fatal(err)
	}
	return a, auth.Token(t, "kc|carol", "verifier-operator")
}

// TestAnonCredsSchemasComeFromTheStacks is ADR-061 decision 4: the
// builder offers the AnonCreds schemas of each live verifier stack that
// lists FEATURE_ANONCREDS_PROOF, and shows no builder without one.
func TestAnonCredsSchemasComeFromTheStacks(t *testing.T) {
	a, token := anonApp(t, true)
	rec := serve(a, http.MethodGet, "/portal/anoncreds/", token)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Farmer 1.0, CREDEBL") {
		t.Fatalf("builder: %d %s", rec.Code, rec.Body.String())
	}
	off, token := anonApp(t, false)
	if rec := serve(off, http.MethodGet, "/portal/anoncreds/", token); rec.Code != http.StatusNotFound {
		t.Errorf("a stack without the feature: %d", rec.Code)
	}
	if rec := serve(off, http.MethodGet, "/portal/anoncreds/", ""); rec.Code == http.StatusOK {
		t.Errorf("the builder answers without a session: %d", rec.Code)
	}
}
