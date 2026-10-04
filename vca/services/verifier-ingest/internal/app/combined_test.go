// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"

	combinedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/combined/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/combined/v1/combinedv1connect"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/app"
)

// combinedServer is a combined service on the network of the test.
type combinedServer struct {
	combinedv1connect.UnimplementedCombinedServiceHandler
	built []string
}

func (f *combinedServer) Get(_ context.Context, req *connect.Request[combinedv1.GetRequest]) (*connect.Response[combinedv1.GetResponse], error) {
	return connect.NewResponse(&combinedv1.GetResponse{Template: &combinedv1.CombinedTemplate{Id: req.Msg.GetId(), DisplayName: "Guardian pair"}}), nil
}

func (f *combinedServer) BuildDcql(_ context.Context, req *connect.Request[combinedv1.BuildDcqlRequest]) (*connect.Response[combinedv1.BuildDcqlResponse], error) {
	f.built = append(f.built, req.Msg.GetTemplateId())
	return connect.NewResponse(&combinedv1.BuildDcqlResponse{Dcql: `{"credentials":[{"id":"a","format":"dc+sd-jwt"}]}`}), nil
}

// TestBuildCallsTheCombinedServiceOfTheLink is ADR-079 decision 2: with
// VCA_INGEST_COMBINED_URL the service reads the merged query of a
// combined template from the combined service of the pair.
func TestBuildCallsTheCombinedServiceOfTheLink(t *testing.T) {
	fake := &combinedServer{}
	_, handler := combinedv1connect.NewCombinedServiceHandler(fake)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	a, err := app.Build(settings(t, map[string]string{"VCA_INGEST_COMBINED_URL": srv.URL + "/"}), app.Deps{Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	if a.Config.CombinedURL != srv.URL {
		t.Errorf("combined URL %q", a.Config.CombinedURL)
	}
	if _, err := a.Service.CreateOid4VpRequest(context.Background(), connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{
		TemplateId: "guardian-pair", TemplateKind: discoveryv1.TemplateKind_TEMPLATE_KIND_COMBINED,
	})); err != nil {
		t.Fatal(err)
	}
	if len(fake.built) != 1 || fake.built[0] != "guardian-pair" {
		t.Errorf("BuildDcql calls %v", fake.built)
	}
}
