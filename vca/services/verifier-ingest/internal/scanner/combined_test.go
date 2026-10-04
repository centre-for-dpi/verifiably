// SPDX-License-Identifier: Apache-2.0

package scanner_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	combinedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/combined/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// guardianDCQL is the merged query of the combined template of the rig.
const guardianDCQL = `{"credentials":[{"id":"licence","format":"dc+sd-jwt","meta":{"vct_values":["https://example.test/pid"]}},` +
	`{"id":"guardian","format":"dc+sd-jwt","meta":{"vct_values":["https://example.test/guardian"]}}],` +
	`"credential_sets":[{"options":[["licence","guardian"]]}]}`

// combinedService holds one combined template. EvaluateCombined stores
// a valid result in the results of the rig, as the service does.
type combinedService struct {
	mu        sync.Mutex
	results   *results
	evaluated []string
}

func (f *combinedService) guardian() *combinedv1.CombinedTemplate {
	return &combinedv1.CombinedTemplate{Id: "guardian-pair", DisplayName: "Guardian pair",
		Members: []*combinedv1.CombinedTemplate_Member{{TemplateId: "licence-check"}}}
}

func (f *combinedService) List(context.Context, *connect.Request[combinedv1.ListRequest]) (*connect.Response[combinedv1.ListResponse], error) {
	return connect.NewResponse(&combinedv1.ListResponse{Templates: []*combinedv1.CombinedTemplate{f.guardian()}}), nil
}

func (f *combinedService) Get(_ context.Context, req *connect.Request[combinedv1.GetRequest]) (*connect.Response[combinedv1.GetResponse], error) {
	if req.Msg.GetId() != "guardian-pair" {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no combined template"))
	}
	return connect.NewResponse(&combinedv1.GetResponse{Template: f.guardian()}), nil
}

func (f *combinedService) BuildDcql(context.Context, *connect.Request[combinedv1.BuildDcqlRequest]) (*connect.Response[combinedv1.BuildDcqlResponse], error) {
	return connect.NewResponse(&combinedv1.BuildDcqlResponse{Dcql: guardianDCQL}), nil
}

func (f *combinedService) EvaluateCombined(ctx context.Context, req *connect.Request[combinedv1.EvaluateCombinedRequest]) (*connect.Response[combinedv1.EvaluateCombinedResponse], error) {
	f.mu.Lock()
	f.evaluated = append(f.evaluated, req.Msg.GetTemplateId())
	f.mu.Unlock()
	stored, err := f.results.Store(ctx, connect.NewRequest(&resultsv1.StoreRequest{Result: &resultsv1.VerificationResult{
		Verdict: policyv1.EvaluateResponse_VERDICT_VALID, TemplateId: req.Msg.GetTemplateId(), Carrier: "oid4vp",
		Credentials: []*resultsv1.CredentialSummary{{Format: commonv1.Format_FORMAT_DC_SD_JWT}},
	}}))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&combinedv1.EvaluateCombinedResponse{Result: stored.Msg.GetResult()}), nil
}

// TestACombinedTemplateIsAQueryOfTheRequestPage is ADR-079 decision 4:
// the request form lists the combined templates, offers each verifier
// that reads the merged query, and the answer goes to EvaluateCombined.
func TestACombinedTemplateIsAQueryOfTheRequestPage(t *testing.T) {
	rig := newRequestRig(t)
	ctx := context.Background()
	form := rig.get(t, "/scan/requests/new", false)
	a11ytest.AssertPage(t, form)
	if !strings.Contains(form, `value="combined:guardian-pair"`) || !strings.Contains(form, "Guardian pair, Combined") {
		t.Fatalf("the form does not offer the combined template: %s", form)
	}
	rec := staffDo(t, rig.mux, formPost("/scan/requests/new/answerers", url.Values{"template": {"combined:guardian-pair"}}))
	if rec.Code != http.StatusOK {
		t.Fatalf("answerers: %d", rec.Code)
	}
	a11ytest.AssertFragment(t, rec.Body.String())
	for _, want := range []string{`value="vca"`, `value="verifier-credebl"`, "Modern stack"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("the verifier choice lacks %q: %s", want, rec.Body.String())
		}
	}
	path := rig.create(t, url.Values{"template": {"combined:guardian-pair"}, "through": {"vca"}, "deliver": {"qr"}})
	record, err := rig.store.Get(ctx, idOf(t, path))
	if err != nil || record.DCQL != guardianDCQL || !record.Combined {
		t.Fatalf("record %+v %v", record, err)
	}
	page := rig.get(t, path, false)
	a11ytest.AssertPage(t, page)
	if !strings.Contains(page, "Guardian pair") || !strings.Contains(page, "Combined") {
		t.Errorf("the request page does not name the combined template: %s", page)
	}
	if _, err := rig.svc.ReceiveDirectPost(ctx, connect.NewRequest(&ingestv1.ReceiveDirectPostRequest{State: record.StateParam, VpToken: sdjwtAnswer})); err != nil {
		t.Fatal(err)
	}
	if len(rig.combined.evaluated) != 1 || len(rig.policy.seen) != 0 {
		t.Fatalf("combined %v, single runs %d", rig.combined.evaluated, len(rig.policy.seen))
	}
	state := rig.get(t, "/scan/requests/"+record.ID+"/state", true)
	a11ytest.AssertFragment(t, state)
	if !strings.Contains(state, "Verified") || !strings.Contains(state, `href="/portal/results/res-1"`) {
		t.Errorf("the state lacks the verdict of the combination: %s", state)
	}
	list := rig.get(t, "/scan/requests/", false)
	a11ytest.AssertPage(t, list)
	if !strings.Contains(list, "Guardian pair") {
		t.Errorf("the list does not name the combined template: %s", list)
	}
}
