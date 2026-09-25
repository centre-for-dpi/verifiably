// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1/discoveryv1connect"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1/policyv1connect"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1/resultsv1connect"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/app"
)

const appQuery = `{"credentials":[{"id":"pid","format":"dc+sd-jwt","claims":[{"path":["given_name"]}]}]}`

const appAnswer = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCJ9.eyJ2Y3QiOiJodHRwczovL2V4YW1wbGUudGVzdC9waWQiLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiZ2l2ZW5fbmFtZSI6IkFzaGEiLCJsaWNlbmNlX2NsYXNzIjoiQiJ9.c2ln~"

type appDiscovery struct {
	discoveryv1connect.UnimplementedDiscoveryServiceHandler
}

func (appDiscovery) GetTemplate(context.Context, *connect.Request[discoveryv1.GetTemplateRequest]) (*connect.Response[discoveryv1.GetTemplateResponse], error) {
	return connect.NewResponse(&discoveryv1.GetTemplateResponse{Template: &discoveryv1.PresentationTemplate{
		Id: "pid-check", Version: 1, Dcql: appQuery, PolicySetId: "query-pid-check",
	}}), nil
}

type appPolicy struct {
	policyv1connect.UnimplementedPolicyServiceHandler
	mu  sync.Mutex
	set string
}

func (p *appPolicy) Evaluate(_ context.Context, req *connect.Request[policyv1.EvaluateRequest]) (*connect.Response[policyv1.EvaluateResponse], error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.set = req.Msg.GetPolicySetId()
	return connect.NewResponse(&policyv1.EvaluateResponse{Verdict: policyv1.EvaluateResponse_VERDICT_VALID, PolicySetId: p.set}), nil
}

type appResults struct {
	resultsv1connect.UnimplementedResultsServiceHandler
}

func (appResults) Store(_ context.Context, req *connect.Request[resultsv1.StoreRequest]) (*connect.Response[resultsv1.StoreResponse], error) {
	r := req.Msg.GetResult()
	r.Id = "res-9"
	return connect.NewResponse(&resultsv1.StoreResponse{Result: r}), nil
}

type appStack struct {
	backendv1connect.UnimplementedVerifierBackendServiceHandler
}

func (appStack) CreateRequest(context.Context, *connect.Request[backendv1.CreateRequestRequest]) (*connect.Response[backendv1.CreateRequestResponse], error) {
	return connect.NewResponse(&backendv1.CreateRequestResponse{RequestUri: "openid4vp://authorize?x=1", State: "s1"}), nil
}

// TestBuildWiresEvaluateAndStore links the policy service and the
// results service over HTTP, so a direct post ends as a stored result
// of the policy set of the template.
func TestBuildWiresEvaluateAndStore(t *testing.T) {
	pol := &appPolicy{}
	mux := http.NewServeMux()
	mux.Handle(policyv1connect.NewPolicyServiceHandler(pol))
	mux.Handle(resultsv1connect.NewResultsServiceHandler(appResults{}))
	mux.Handle(backendv1connect.NewVerifierBackendServiceHandler(appStack{}))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	cfg := settings(t, map[string]string{"VCA_INGEST_POLICY_URL": srv.URL, "VCA_INGEST_RESULTS_URL": srv.URL})
	a, err := app.Build(cfg, app.Deps{Log: quiet(), Discovery: appDiscovery{}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	created, err := a.Service.CreateOid4VpRequest(ctx, connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{TemplateId: "pid-check"}))
	if err != nil {
		t.Fatal(err)
	}
	record, err := a.Store.Get(ctx, created.Msg.GetTransactionId())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Service.ReceiveDirectPost(ctx, connect.NewRequest(&ingestv1.ReceiveDirectPostRequest{State: record.StateParam, VpToken: appAnswer})); err != nil {
		t.Fatal(err)
	}
	got, err := a.Service.GetTransaction(ctx, connect.NewRequest(&ingestv1.GetTransactionRequest{TransactionId: record.ID}))
	if err != nil || got.Msg.GetResultId() != "res-9" || pol.set != "query-pid-check" {
		t.Fatalf("result %q set %q err %v", got.Msg.GetResultId(), pol.set, err)
	}
}

// TestStacksComeFromTheProbe offers the live verifier stacks of the
// probe that have an adapter, and sends a request through one of them.
func TestStacksComeFromTheProbe(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle(backendv1connect.NewVerifierBackendServiceHandler(appStack{}))
	mux.Handle(backendv1connect.NewCapabilityServiceHandler(capabilities{}))
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	peers := "verifier-credebl|" + srv.URL + "|verifier-results=" + srv.URL + ",dpg-adapter-credebl=" + srv.URL
	cfg := settings(t, map[string]string{topology.Env: peers})
	a, err := app.Build(cfg, app.Deps{Log: quiet(), Discovery: appDiscovery{}, Now: func() time.Time { return now },
		Prober: &topology.Prober{Peers: cfg.Peers, Lookup: func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }}})
	if err != nil {
		t.Fatal(err)
	}
	created, err := a.Service.CreateOid4VpRequest(context.Background(), connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{
		TemplateId: "pid-check", Stack: "verifier-credebl",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.Msg.GetQrPayload(), "openid4vp://") {
		t.Errorf("request %+v", created.Msg)
	}
}

type capabilities struct {
	backendv1connect.UnimplementedCapabilityServiceHandler
}

func (capabilities) GetCapabilities(context.Context, *connect.Request[backendv1.GetCapabilitiesRequest]) (*connect.Response[backendv1.GetCapabilitiesResponse], error) {
	return connect.NewResponse(&backendv1.GetCapabilitiesResponse{
		Protocols: []backendv1.Protocol{backendv1.Protocol_PROTOCOL_OID4VP_DCQL}, DpgInfo: &backendv1.DpgInfo{DisplayName: "CREDEBL"},
	}), nil
}
