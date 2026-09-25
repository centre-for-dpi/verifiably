// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/policy"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/service"
)

// fakePolicy keeps the policy sets the service writes.
type fakePolicy struct {
	sets     map[string]*policyv1.PolicySet
	created  int
	updated  int
	deleted  []string
	failWith error
}

func (f *fakePolicy) CreatePolicySet(_ context.Context, req *connect.Request[policyv1.CreatePolicySetRequest]) (*connect.Response[policyv1.CreatePolicySetResponse], error) {
	if f.failWith != nil {
		return nil, f.failWith
	}
	set := req.Msg.GetPolicySet()
	if _, ok := f.sets[set.GetId()]; ok {
		return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("exists"))
	}
	f.created++
	set.Version = 1
	f.sets[set.GetId()] = set
	return connect.NewResponse(&policyv1.CreatePolicySetResponse{PolicySet: set}), nil
}

func (f *fakePolicy) UpdatePolicySet(_ context.Context, req *connect.Request[policyv1.UpdatePolicySetRequest]) (*connect.Response[policyv1.UpdatePolicySetResponse], error) {
	set := req.Msg.GetPolicySet()
	if _, ok := f.sets[set.GetId()]; !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no set"))
	}
	f.updated++
	set.Version = f.sets[set.GetId()].GetVersion() + 1
	f.sets[set.GetId()] = set
	return connect.NewResponse(&policyv1.UpdatePolicySetResponse{PolicySet: set}), nil
}

func (f *fakePolicy) DeletePolicySet(_ context.Context, req *connect.Request[policyv1.DeletePolicySetRequest]) (*connect.Response[policyv1.DeletePolicySetResponse], error) {
	f.deleted = append(f.deleted, req.Msg.GetId())
	delete(f.sets, req.Msg.GetId())
	return connect.NewResponse(&policyv1.DeletePolicySetResponse{}), nil
}

// ruled is a template with a date rule and both trust flags.
func ruled() *discoveryv1.PresentationTemplate {
	return &discoveryv1.PresentationTemplate{
		DisplayName: "Driving licence check",
		Queries: []*discoveryv1.PresentationTemplate_CredentialQuery{{
			QueryId: "licence", Type: "https://ntsa.example/licence", Format: commonv1.Format_FORMAT_DC_SD_JWT,
			Claims: []string{"birth_date", "licence_class"},
		}},
		Predicates: []*discoveryv1.PresentationTemplate_ClaimPredicate{{
			QueryId: "licence", Path: "birth_date", Op: discoveryv1.PresentationTemplate_ClaimPredicate_OP_AT_LEAST_YEARS, Value: "18",
		}},
		RequireTrustedIssuer: true, RequireStatus: true,
	}
}

// TestDatePredicateStoredAsPolicyRule stores the date rule of a template
// as a claim_predicate check of a policy set of its own, and names the
// set on the template (ADR-042 decision 3). A new version updates the
// set, and a delete removes it.
func TestDatePredicateStoredAsPolicyRule(t *testing.T) {
	ctx := context.Background()
	fp := &fakePolicy{sets: map[string]*policyv1.PolicySet{}}
	svc, err := service.New(service.Options{Store: newStore(t), Policy: fp})
	if err != nil {
		t.Fatal(err)
	}
	created, err := svc.CreateTemplate(ctx, connect.NewRequest(&discoveryv1.CreateTemplateRequest{Template: ruled()}))
	if err != nil {
		t.Fatal(err)
	}
	tpl := created.Msg.GetTemplate()
	if tpl.GetPolicySetId() != "query-driving-licence-check" || len(tpl.GetPredicates()) != 1 {
		t.Fatalf("template = %+v", tpl)
	}
	set := fp.sets["query-driving-licence-check"]
	if set == nil || len(set.GetChecks()) != 3 {
		t.Fatalf("policy set = %+v", set)
	}
	rule := set.GetChecks()[2]
	if rule.GetName() != policy.NameClaimPredicate || !rule.GetBlocking() || rule.GetParams()["op"] != policy.OpAtLeastYears ||
		rule.GetParams()["path"] != "birth_date" || rule.GetParams()["value"] != "18" {
		t.Errorf("rule = %+v", rule)
	}
	if set.GetDisplayName() != "Driving licence check" {
		t.Errorf("set name %q", set.GetDisplayName())
	}
	got, err := svc.GetTemplate(ctx, connect.NewRequest(&discoveryv1.GetTemplateRequest{Id: tpl.GetId()}))
	if err != nil || got.Msg.GetTemplate().GetPredicates()[0].GetValue() != "18" || !got.Msg.GetTemplate().GetRequireStatus() {
		t.Fatalf("stored template = %+v %v", got, err)
	}
	next := ruled()
	next.Id = tpl.GetId()
	next.Predicates[0].Value = "21"
	if _, err := svc.VersionTemplate(ctx, connect.NewRequest(&discoveryv1.VersionTemplateRequest{Template: next})); err != nil {
		t.Fatal(err)
	}
	if fp.updated != 1 || fp.sets["query-driving-licence-check"].GetChecks()[2].GetParams()["value"] != "21" {
		t.Errorf("the new version did not update the set: %d", fp.updated)
	}
	if _, err := svc.DeleteTemplate(ctx, connect.NewRequest(&discoveryv1.DeleteTemplateRequest{Id: tpl.GetId()})); err != nil {
		t.Fatal(err)
	}
	if len(fp.deleted) != 1 || fp.deleted[0] != "query-driving-licence-check" {
		t.Errorf("deleted sets = %v", fp.deleted)
	}
}

// TestRulesNeedThePolicyService refuses a template with a rule when no
// policy service can enforce it, and stores nothing when the policy
// service fails. A template without a rule needs no set.
func TestRulesNeedThePolicyService(t *testing.T) {
	ctx := context.Background()
	bare, err := service.New(service.Options{Store: newStore(t)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bare.CreateTemplate(ctx, connect.NewRequest(&discoveryv1.CreateTemplateRequest{Template: ruled()})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("want failed precondition, got %v", err)
	}
	fp := &fakePolicy{sets: map[string]*policyv1.PolicySet{}, failWith: connect.NewError(connect.CodeUnavailable, errors.New("down"))}
	svc, err := service.New(service.Options{Store: newStore(t), Policy: fp})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.CreateTemplate(ctx, connect.NewRequest(&discoveryv1.CreateTemplateRequest{Template: ruled()})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("want the policy fault, got %v", err)
	}
	list, err := svc.ListTemplates(ctx, connect.NewRequest(&discoveryv1.ListTemplatesRequest{}))
	if err != nil || len(list.Msg.GetTemplates()) != 0 {
		t.Fatalf("a failed rule stored the template: %v", err)
	}
	plain := ruled()
	plain.Predicates, plain.RequireStatus, plain.RequireTrustedIssuer = nil, false, false
	fp.failWith = nil
	out, err := svc.CreateTemplate(ctx, connect.NewRequest(&discoveryv1.CreateTemplateRequest{Template: plain}))
	if err != nil || out.Msg.GetTemplate().GetPolicySetId() != "" || fp.created != 0 {
		t.Fatalf("a plain template: %v %+v", err, out)
	}
	// An orphan set of the same id takes a new version.
	fp.sets["query-orphan"] = &policyv1.PolicySet{Id: "query-orphan", Version: 4}
	orphan := ruled()
	orphan.DisplayName = "Orphan"
	if _, err := svc.CreateTemplate(ctx, connect.NewRequest(&discoveryv1.CreateTemplateRequest{Template: orphan})); err != nil {
		t.Fatal(err)
	}
	if fp.sets["query-orphan"].GetVersion() != 5 {
		t.Errorf("the orphan set was not updated")
	}
}
