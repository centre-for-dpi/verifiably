// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	combinedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/combined/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/portal"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// combinedStore is the combined service of the tests: it keeps the
// templates in a map and refuses a template without a member, as the
// service does.
type combinedStore struct {
	templates map[string]*combinedv1.CombinedTemplate
	failList  bool
}

func (f *combinedStore) List(context.Context, *connect.Request[combinedv1.ListRequest]) (*connect.Response[combinedv1.ListResponse], error) {
	if f.failList {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("down"))
	}
	out := &combinedv1.ListResponse{}
	for _, t := range f.templates {
		out.Templates = append(out.Templates, t)
	}
	sort.Slice(out.Templates, func(i, j int) bool { return out.Templates[i].GetId() < out.Templates[j].GetId() })
	return connect.NewResponse(out), nil
}

func (f *combinedStore) Get(_ context.Context, req *connect.Request[combinedv1.GetRequest]) (*connect.Response[combinedv1.GetResponse], error) {
	t, ok := f.templates[req.Msg.GetId()]
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no combined template"))
	}
	return connect.NewResponse(&combinedv1.GetResponse{Template: t}), nil
}

func (f *combinedStore) check(t *combinedv1.CombinedTemplate) error {
	if len(t.GetMembers()) == 0 {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("service: a combined template needs at least one member"))
	}
	return nil
}

func (f *combinedStore) Create(_ context.Context, req *connect.Request[combinedv1.CreateRequest]) (*connect.Response[combinedv1.CreateResponse], error) {
	t := req.Msg.GetTemplate()
	if err := f.check(t); err != nil {
		return nil, err
	}
	t.Id = "guardian-pair"
	f.templates[t.GetId()] = t
	return connect.NewResponse(&combinedv1.CreateResponse{Template: t}), nil
}

func (f *combinedStore) Update(_ context.Context, req *connect.Request[combinedv1.UpdateRequest]) (*connect.Response[combinedv1.UpdateResponse], error) {
	t := req.Msg.GetTemplate()
	if err := f.check(t); err != nil {
		return nil, err
	}
	if _, ok := f.templates[t.GetId()]; !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no combined template"))
	}
	f.templates[t.GetId()] = t
	return connect.NewResponse(&combinedv1.UpdateResponse{Template: t}), nil
}

func (f *combinedStore) Delete(_ context.Context, req *connect.Request[combinedv1.DeleteRequest]) (*connect.Response[combinedv1.DeleteResponse], error) {
	delete(f.templates, req.Msg.GetId())
	return connect.NewResponse(&combinedv1.DeleteResponse{}), nil
}

// combinedPortal wires the pages in the verifier frame of a pair that
// lists the combined service when runs is true, with two saved queries.
func combinedPortal(t *testing.T, runs bool) (*http.ServeMux, *combinedStore) {
	t.Helper()
	_, svc := newPortal(t)
	for _, q := range []struct{ name, typ string }{{"Identity check", "https://a.example/pid"}, {"Guardian check", "https://a.example/guardian"}} {
		if _, err := svc.CreateTemplate(context.Background(), connect.NewRequest(&discoveryv1.CreateTemplateRequest{
			Template: &discoveryv1.PresentationTemplate{DisplayName: q.name, Queries: []*discoveryv1.PresentationTemplate_CredentialQuery{{
				Type: q.typ, Format: commonv1.Format_FORMAT_DC_SD_JWT, Claims: []string{"given_name"},
			}}},
		})); err != nil {
			t.Fatal(err)
		}
	}
	name := topology.PairName(commonv1.Role_ROLE_VERIFIER, configv1.Dpg_DPG_INJI)
	pair := topology.Peer{Pair: name, Role: commonv1.Role_ROLE_VERIFIER, Dpg: configv1.Dpg_DPG_INJI, PublicURL: "https://" + name + ".labs.example",
		Services: map[string]string{"verifier-auth": "http://" + name + "-auth:8081"}}
	if runs {
		pair.Services["verifier-combined"] = "http://" + name + "-verifier-combined:8088"
	}
	snap := topology.Snapshot{Peers: []topology.Status{{Peer: pair, State: topology.Live,
		Capabilities: &backendv1.GetCapabilitiesResponse{DpgInfo: &backendv1.DpgInfo{DisplayName: "MOSIP Inji"}}}}}
	shell := staffshell.New(staffshell.Options{
		Role: commonv1.Role_ROLE_VERIFIER, Peers: []topology.Peer{pair},
		Snapshot: func(context.Context) topology.Snapshot { return snap },
		JWKSURL:  pair.Auth() + staffshell.JWKSPath, SignOut: "/discovery/signout",
	})
	combined := &combinedStore{templates: map[string]*combinedv1.CombinedTemplate{}}
	p, err := portal.New(portal.Options{Client: svc, Prefix: "/discovery", Shell: shell, Combined: combined})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	p.Register(mux)
	return mux, combined
}

// staffSend answers one request as a signed in verifier operator.
func staffSend(mux *http.ServeMux, method, path string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	r = r.WithContext(staffsession.With(r.Context(), staffsession.Session{
		Subject: "kc|otieno", Name: "Akinyi Otieno", CSRF: "csrf-1", Roles: []string{"verifier-operator"},
	}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	return rec
}

// queryIDs returns the ids of the saved queries, by name.
func queryIDs(t *testing.T, mux *http.ServeMux) map[string]string {
	t.Helper()
	body := staffGet(t, mux, "/discovery/combined/new")
	out := map[string]string{}
	for _, name := range []string{"identity-check", "guardian-check"} {
		if !strings.Contains(body, `value="`+name+`"`) {
			t.Fatalf("the form does not offer the query %s: %s", name, body)
		}
		out[name] = name
	}
	return out
}

// TestCombinedPagesListCreateEditAndDelete is ADR-079 decision 4: the
// verifier stores a combined query from saved queries, edits it, and
// removes it, each through the combined service.
func TestCombinedPagesListCreateEditAndDelete(t *testing.T) {
	mux, combined := combinedPortal(t, true)
	empty := staffGet(t, mux, "/discovery/combined/")
	a11ytest.AssertPage(t, empty)
	for _, want := range []string{"No combined query yet.", `href="/discovery/combined/new"`, "Combined queries", `aria-current="page"`} {
		if !strings.Contains(empty, want) {
			t.Errorf("the empty list lacks %q", want)
		}
	}
	if !strings.Contains(staffGet(t, mux, "/discovery/dcql/"), `href="/discovery/combined/"`) {
		t.Error("the query tabs do not lead to the combined queries")
	}
	queryIDs(t, mux)
	form := staffGet(t, mux, "/discovery/combined/new")
	a11ytest.AssertPage(t, form)
	for _, want := range []string{`name="display_name"`, `name="member"`, `name="group.identity-check"`, `name="policy_set"`,
		`name="rule_kind.1"`, "Same subject", "Delegation link", "Date order", "https___a_example_pid",
		"Group of Identity check", "Rule 1", "Rule 2"} {
		if !strings.Contains(form, want) {
			t.Errorf("the form lacks %q", want)
		}
	}
	rec := staffSend(mux, http.MethodPost, "/discovery/combined/new", url.Values{
		"display_name": {"Guardian pair"}, "member": {"identity-check", "guardian-check"}, "policy_set": {"strict"},
		"rule_kind.1": {"delegation_link"}, "rule_name.1": {"Guardian link"},
		"rule_first.1": {"https___a_example_pid"}, "rule_second.1": {"https___a_example_guardian"},
	})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/discovery/combined/?notice=combined-saved" {
		t.Fatalf("create: %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	saved := combined.templates["guardian-pair"]
	if saved.GetDisplayName() != "Guardian pair" || len(saved.GetMembers()) != 2 || saved.GetPolicySetId() != "strict" || len(saved.GetRules()) != 1 ||
		saved.GetRules()[0].GetKind() != combinedv1.CrossRule_CROSS_RULE_DELEGATION_LINK ||
		saved.GetRules()[0].GetParams()["subject"] != "https___a_example_pid" || saved.GetRules()[0].GetParams()["delegation"] != "https___a_example_guardian" {
		t.Fatalf("saved %+v", saved)
	}
	list := staffGet(t, mux, "/discovery/combined/?notice=combined-saved")
	a11ytest.AssertPage(t, list)
	for _, want := range []string{"Guardian pair", "Guardian check, Identity check", "Guardian link", `href="/discovery/combined/edit/guardian-pair"`,
		`action="/discovery/combined/delete/guardian-pair"`, "You saved the combined query."} {
		if !strings.Contains(list, want) {
			t.Errorf("the list lacks %q", want)
		}
	}
	edit := staffGet(t, mux, "/discovery/combined/edit/guardian-pair")
	a11ytest.AssertPage(t, edit)
	if !strings.Contains(edit, `value="Guardian pair"`) || !strings.Contains(edit, `value="strict"`) || !strings.Contains(edit, "Edit Guardian pair") {
		t.Errorf("the edit form does not hold the template: %s", edit)
	}
	rec = staffSend(mux, http.MethodPost, "/discovery/combined/edit/guardian-pair", url.Values{
		"display_name": {"Identity or guardian"}, "member": {"identity-check", "guardian-check"},
		"group.identity-check": {"either"}, "group.guardian-check": {"either"},
		"rule_kind.1": {"date_order"}, "rule_first.1": {"https___a_example_pid"}, "rule_first_claim.1": {"issued"},
		"rule_second.1": {"https___a_example_guardian"}, "rule_second_claim.1": {"valid_from"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("edit: %d %s", rec.Code, rec.Body.String())
	}
	saved = combined.templates["guardian-pair"]
	rule := saved.GetRules()[0]
	if saved.GetDisplayName() != "Identity or guardian" || saved.GetMembers()[0].GetAlternativeGroup() != "either" ||
		rule.GetKind() != combinedv1.CrossRule_CROSS_RULE_DATE_ORDER || rule.GetParams()["before_query"] != "https___a_example_pid" ||
		rule.GetParams()["before_claim"] != "issued" || rule.GetParams()["after_query"] != "https___a_example_guardian" || rule.GetParams()["after_claim"] != "valid_from" {
		t.Fatalf("edited %+v", saved)
	}
	rec = staffSend(mux, http.MethodPost, "/discovery/combined/delete/guardian-pair", url.Values{})
	if rec.Code != http.StatusSeeOther || len(combined.templates) != 0 {
		t.Fatalf("delete: %d, left %d", rec.Code, len(combined.templates))
	}
	if !strings.Contains(staffGet(t, mux, "/discovery/combined/?notice=combined-deleted"), "You removed the combined query.") {
		t.Error("the list does not confirm the removal")
	}
}

// TestCombinedFormShowsTheRefusal keeps the form and names the problem
// when the combined service refuses the template.
func TestCombinedFormShowsTheRefusal(t *testing.T) {
	mux, _ := combinedPortal(t, true)
	rec := staffSend(mux, http.MethodPost, "/discovery/combined/new", url.Values{"display_name": {"Empty"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
	a11ytest.AssertPage(t, rec.Body.String())
	if !strings.Contains(rec.Body.String(), `role="alert"`) || !strings.Contains(rec.Body.String(), `value="Empty"`) {
		t.Errorf("the form lacks the problem or the name: %s", rec.Body.String())
	}
	if rec := staffSend(mux, http.MethodGet, "/discovery/combined/edit/missing", nil); rec.Code != http.StatusNotFound {
		t.Errorf("a missing template: %d", rec.Code)
	}
}

// TestCombinedPagesHideWhenThePairRunsNoCombinedService hides the
// pages, the tab, and the side navigation entry when the own pair lists
// no combined service.
func TestCombinedPagesHideWhenThePairRunsNoCombinedService(t *testing.T) {
	mux, _ := combinedPortal(t, false)
	for _, path := range []string{"/discovery/combined/", "/discovery/combined/new", "/discovery/combined/edit/guardian-pair"} {
		if rec := staffSend(mux, http.MethodGet, path, nil); rec.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", path, rec.Code)
		}
	}
	if body := staffGet(t, mux, "/discovery/dcql/"); strings.Contains(body, "/discovery/combined/") {
		t.Error("the DCQL page leads to the hidden combined page")
	}
	_, svc := newPortal(t)
	p, err := portal.New(portal.Options{Client: svc})
	if err != nil {
		t.Fatal(err)
	}
	plain := http.NewServeMux()
	p.Register(plain)
	if rec := staffSend(plain, http.MethodGet, "/portal/combined/", nil); rec.Code != http.StatusNotFound {
		t.Errorf("a portal without a combined client: status %d", rec.Code)
	}
}

// TestCombinedListFailureAnswersAnError keeps the error text off the
// page.
func TestCombinedListFailureAnswersAnError(t *testing.T) {
	mux, combined := combinedPortal(t, true)
	combined.failList = true
	rec := staffSend(mux, http.MethodGet, "/discovery/combined/", nil)
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "down") {
		t.Errorf("status %d body %q", rec.Code, rec.Body.String())
	}
}

// TestCombinedFormMarksEachRuleRequired: staff mark each rule required
// or optional (ADR-080). A new rule starts required, because a required
// rule that cannot run fails the verdict. The edit form shows the mark
// the stored rule carries.
func TestCombinedFormMarksEachRuleRequired(t *testing.T) {
	mux, combined := combinedPortal(t, true)
	queryIDs(t, mux)
	form := staffGet(t, mux, "/discovery/combined/new")
	for _, want := range []string{`name="rule_need.1"`, `value="optional"`, "Required", "Optional"} {
		if !strings.Contains(form, want) {
			t.Errorf("the form lacks %q", want)
		}
	}
	if !regexp.MustCompile(`value="required"[^>]* checked`).MatchString(form) || regexp.MustCompile(`value="optional"[^>]* checked`).MatchString(form) {
		t.Error("a new rule does not start required")
	}
	// The store names every new template guardian-pair, so the optional
	// one comes last and the edit form reads it.
	for _, need := range []string{"required", "optional"} {
		rec := staffSend(mux, http.MethodPost, "/discovery/combined/new", url.Values{
			"display_name": {"Guardian pair"}, "member": {"identity-check", "guardian-check"},
			"rule_kind.1": {"same_subject"}, "rule_first.1": {"https___a_example_pid"}, "rule_second.1": {"https___a_example_guardian"},
			"rule_need.1": {need},
		})
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("%s: %d %s", need, rec.Code, rec.Body.String())
		}
		rules := combined.templates["guardian-pair"].GetRules()
		if len(rules) != 1 || rules[0].GetRequired() != (need == "required") {
			t.Errorf("%s: saved %+v", need, rules)
		}
	}
	edit := staffGet(t, mux, "/discovery/combined/edit/guardian-pair")
	a11ytest.AssertPage(t, edit)
	if !regexp.MustCompile(`name="rule_need.1" value="optional"[^>]* checked`).MatchString(edit) {
		t.Errorf("the edit form loses the optional mark")
	}
}
