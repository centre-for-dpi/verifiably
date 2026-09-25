// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"context"
	"encoding/json"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/policy"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	shared "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/catalog"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/portal"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/store"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// policySets keeps the policy sets the service writes.
type policySets struct {
	sets map[string]*policyv1.PolicySet
}

func (f *policySets) CreatePolicySet(_ context.Context, req *connect.Request[policyv1.CreatePolicySetRequest]) (*connect.Response[policyv1.CreatePolicySetResponse], error) {
	f.sets[req.Msg.GetPolicySet().GetId()] = req.Msg.GetPolicySet()
	return connect.NewResponse(&policyv1.CreatePolicySetResponse{PolicySet: req.Msg.GetPolicySet()}), nil
}

func (f *policySets) UpdatePolicySet(_ context.Context, req *connect.Request[policyv1.UpdatePolicySetRequest]) (*connect.Response[policyv1.UpdatePolicySetResponse], error) {
	f.sets[req.Msg.GetPolicySet().GetId()] = req.Msg.GetPolicySet()
	return connect.NewResponse(&policyv1.UpdatePolicySetResponse{PolicySet: req.Msg.GetPolicySet()}), nil
}

func (f *policySets) DeletePolicySet(context.Context, *connect.Request[policyv1.DeletePolicySetRequest]) (*connect.Response[policyv1.DeletePolicySetResponse], error) {
	return nil, errors.New("not used")
}

const licenceType = "https://ntsa.example/licence"

// builderPortal wires the pages over a catalogue with a driving licence
// type and a policy service fake.
func builderPortal(t *testing.T) (*http.ServeMux, *service.Service, *policySets) {
	t.Helper()
	st, err := store.New(shared.Memory())
	if err != nil {
		t.Fatal(err)
	}
	if err = st.PutIssuer(context.Background(), catalog.Issuer{
		CredentialIssuer: "https://issuer.example", DisplayName: "Transport authority", Trust: catalog.TrustTrusted,
		CrawledAt: time.Unix(1700000000, 0).UTC(),
		Types: []catalog.CredentialType{{
			Type: licenceType, ConfigurationID: "licence", Format: "dc+sd-jwt", Display: []catalog.Display{{Name: "Driving licence"}},
			Fields: []catalog.Field{
				{Path: "given_name", Type: "string", Title: "Given name"},
				{Path: "birth_date", Type: "string", Format: "date"},
				{Path: "licence_class", Type: "string"},
				{Path: "points", Type: "integer"},
			},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	sets := &policySets{sets: map[string]*policyv1.PolicySet{}}
	svc, err := service.New(service.Options{Store: st, Policy: sets})
	if err != nil {
		t.Fatal(err)
	}
	p, err := portal.New(portal.Options{Client: svc, Prefix: "/discovery"})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	p.Register(mux)
	return mux, svc, sets
}

// builderForm is a filled builder: a date rule, accepted values, both
// trust rules.
func builderForm(action string) url.Values {
	return url.Values{
		"display_name": {"Driving licence check"}, "purpose": {"Check the licence."},
		"pick":                 {url.Values{"credential_issuer": {"https://issuer.example"}, "type": {licenceType}, "format": {"dc+sd-jwt"}}.Encode()},
		"claim":                {"birth_date", "licence_class", "points"},
		"values:licence_class": {"B, C"}, "values:points": {"0, 1"},
		"op:birth_date": {policy.OpAtLeastYears}, "rule:birth_date": {"18"},
		"trust": {"issuer", "status"}, "action": {action},
	}
}

// do answers one request as a signed in operator.
func do(mux *http.ServeMux, r *http.Request) *httptest.ResponseRecorder {
	r = r.WithContext(staffsession.With(r.Context(), staffsession.Session{Subject: "kc|otieno", CSRF: "c", Roles: []string{"verifier-operator"}}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	return rec
}

// postForm answers one form post, as htmx when hx is true.
func postForm(mux *http.ServeMux, path string, form url.Values, hx bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if hx {
		r.Header.Set("HX-Request", "true")
	}
	return do(mux, r)
}

// previewJSON reads the dcql_query of a page or a fragment and compacts it.
func previewJSON(t *testing.T, body string) string {
	t.Helper()
	m := regexp.MustCompile(`(?s)<code>(.*?)</code>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no preview in %s", body)
	}
	var v any
	if err := json.Unmarshal([]byte(html.UnescapeString(m[1])), &v); err != nil {
		t.Fatalf("the preview is not JSON: %v", err)
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// TestDcqlBuilderPreviewMatchesSaved saves exactly the query the preview
// shows: the claims, the typed accepted values, and one required
// credential set (ADR-042 decision 2).
func TestDcqlBuilderPreviewMatchesSaved(t *testing.T) {
	mux, svc, _ := builderPortal(t)
	frag := postForm(mux, "/discovery/dcql/preview", builderForm("preview"), true)
	if frag.Code != http.StatusOK {
		t.Fatalf("preview: %d %s", frag.Code, frag.Body.String())
	}
	a11ytest.AssertFragment(t, frag.Body.String())
	shown := previewJSON(t, frag.Body.String())
	for _, want := range []string{`"values":["B","C"]`, `"values":[0,1]`, `"credential_sets":[{"options":[["licence"]]`, `"vct_values":["` + licenceType + `"]`} {
		if !strings.Contains(shown, want) {
			t.Errorf("the preview lacks %s: %s", want, shown)
		}
	}
	if strings.Contains(shown, "birth_date\",\"values") {
		t.Error("the date rule leaked into the DCQL values")
	}
	saved := postForm(mux, "/discovery/dcql/", builderForm("save"), false)
	if saved.Code != http.StatusSeeOther || !strings.HasPrefix(saved.Header().Get("Location"), "/discovery/templates/driving-licence-check") {
		t.Fatalf("save: %d %q %s", saved.Code, saved.Header().Get("Location"), saved.Body.String())
	}
	got, err := svc.GetTemplate(context.Background(), connect.NewRequest(&discoveryv1.GetTemplateRequest{Id: "driving-licence-check"}))
	if err != nil {
		t.Fatal(err)
	}
	var v any
	if err = json.Unmarshal([]byte(got.Msg.GetTemplate().GetDcql()), &v); err != nil {
		t.Fatal(err)
	}
	stored, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != shown {
		t.Fatalf("the saved query differs from the preview:\nsaved   %s\npreview %s", stored, shown)
	}
	if got.Msg.GetTemplate().GetKind() != discoveryv1.TemplateKind_TEMPLATE_KIND_DCQL {
		t.Errorf("kind = %s", got.Msg.GetTemplate().GetKind())
	}
}

// TestDatePredicateStoredAsPolicyRule turns the date rule of the builder
// into a claim_predicate check of the policy set of the query, beside
// the trust rules (ADR-042 decision 3).
func TestDatePredicateStoredAsPolicyRule(t *testing.T) {
	mux, svc, sets := builderPortal(t)
	if rec := postForm(mux, "/discovery/dcql/", builderForm("save"), false); rec.Code != http.StatusSeeOther {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	got, err := svc.GetTemplate(context.Background(), connect.NewRequest(&discoveryv1.GetTemplateRequest{Id: "driving-licence-check"}))
	if err != nil {
		t.Fatal(err)
	}
	tpl := got.Msg.GetTemplate()
	if len(tpl.GetPredicates()) != 1 || tpl.GetPredicates()[0].GetOp() != discoveryv1.PresentationTemplate_ClaimPredicate_OP_AT_LEAST_YEARS ||
		!tpl.GetRequireTrustedIssuer() || !tpl.GetRequireStatus() {
		t.Fatalf("template rules = %+v", tpl)
	}
	set := sets.sets[tpl.GetPolicySetId()]
	if set == nil {
		t.Fatalf("no policy set %q", tpl.GetPolicySetId())
	}
	var names []string
	for _, c := range set.GetChecks() {
		names = append(names, c.GetName())
	}
	if strings.Join(names, ",") != "trust_chain,status,claim_predicate" {
		t.Fatalf("checks = %v", names)
	}
	params := set.GetChecks()[2].GetParams()
	if params["path"] != "birth_date" || params["op"] != policy.OpAtLeastYears || params["value"] != "18" || params["type"] != licenceType {
		t.Errorf("params = %v", params)
	}
}

// TestBuilderWorksWithoutJS serves a plain form that posts to the page:
// the server draws the preview on every post, and the save button posts
// the same form. htmx only adds the swap of the preview.
func TestBuilderWorksWithoutJS(t *testing.T) {
	mux, _, _ := builderPortal(t)
	start := do(mux, httptest.NewRequest(http.MethodGet, "/discovery/dcql/?"+url.Values{
		"credential_issuer": {"https://issuer.example"}, "type": {licenceType}, "format": {"dc+sd-jwt"},
	}.Encode(), nil))
	body := start.Body.String()
	if start.Code != http.StatusOK {
		t.Fatalf("builder: %d %s", start.Code, body)
	}
	a11ytest.AssertPage(t, body)
	for _, want := range []string{
		`<form method="post" action="/discovery/dcql/"`, `name="action" value="preview"`, `name="action" value="save"`,
		`hx-post="/discovery/dcql/preview"`, "birth_date", "licence_class", "Trusted issuer only", "Status check",
		"DCQL (OID4VP)", `href="/discovery/pe/"`, "Query preview",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the builder lacks %q", want)
		}
	}
	if !regexp.MustCompile(`value="issuer"[^>]*checked`).MatchString(body) {
		t.Error("a new query does not start with the trust rules on")
	}
	page := postForm(mux, "/discovery/dcql/", builderForm("preview"), false)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "<!DOCTYPE html>") {
		t.Fatalf("a plain post does not answer with the page: %d", page.Code)
	}
	a11ytest.AssertPage(t, page.Body.String())
	if !strings.Contains(previewJSON(t, page.Body.String()), `"values":["B","C"]`) {
		t.Error("the page preview lacks the values")
	}
	for _, want := range []string{"Claim birth_date, rule At least N years, value 18.", `value="B, C"`} {
		if !strings.Contains(html.UnescapeString(page.Body.String()), want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	// A type change swaps the claims out of band; the same type does not.
	form := builderForm("preview")
	same := form
	same.Set("shown", form.Get("pick"))
	if frag := postForm(mux, "/discovery/dcql/preview", same, true); strings.Contains(frag.Body.String(), "hx-swap-oob") {
		t.Error("the same type swapped the claims")
	}
	if frag := postForm(mux, "/discovery/dcql/preview", builderForm("preview"), true); !strings.Contains(frag.Body.String(), `id="dcql-claims" hx-swap-oob="true"`) {
		t.Error("a new type did not swap the claims")
	}
}

// TestBuilderProblems names what is missing: a type, a name, a valid
// rule, and a free name.
func TestBuilderProblems(t *testing.T) {
	mux, _, _ := builderPortal(t)
	empty := do(mux, httptest.NewRequest(http.MethodGet, "/discovery/dcql/", nil))
	if !strings.Contains(empty.Body.String(), "Pick a credential type to start.") {
		t.Error("an empty builder does not ask for a type")
	}
	a11ytest.AssertPage(t, empty.Body.String())
	noName := builderForm("save")
	noName.Del("display_name")
	if rec := postForm(mux, "/discovery/dcql/", noName, false); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Give the query a name") {
		t.Errorf("no name: %d", rec.Code)
	}
	bad := builderForm("save")
	bad.Set("rule:birth_date", "many")
	if rec := postForm(mux, "/discovery/dcql/", bad, false); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "The query is not complete.") {
		t.Errorf("bad rule: %d %s", rec.Code, rec.Body.String())
	}
	noClaim := builderForm("preview")
	noClaim.Set("values:given_name", "Asha")
	noClaim["claim"] = []string{"given_name"}
	if rec := postForm(mux, "/discovery/dcql/preview", noClaim, true); !strings.Contains(rec.Body.String(), `&#34;values&#34;: [`) {
		t.Errorf("a ticked claim with values: %s", rec.Body.String())
	}
	if rec := postForm(mux, "/discovery/dcql/", builderForm("save"), false); rec.Code != http.StatusSeeOther {
		t.Fatalf("first save: %d", rec.Code)
	}
	if rec := postForm(mux, "/discovery/dcql/", builderForm("save"), false); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "did not save the query") {
		t.Errorf("a taken name: %d", rec.Code)
	}
}

// TestSavedQueryShowsItsRules lists the rules of a saved query and the
// policy set that holds them on the query page.
func TestSavedQueryShowsItsRules(t *testing.T) {
	mux, _, _ := builderPortal(t)
	if rec := postForm(mux, "/discovery/dcql/", builderForm("save"), false); rec.Code != http.StatusSeeOther {
		t.Fatalf("save: %d", rec.Code)
	}
	page := do(mux, httptest.NewRequest(http.MethodGet, "/discovery/templates/driving-licence-check", nil))
	body := html.UnescapeString(page.Body.String())
	a11ytest.AssertPage(t, page.Body.String())
	for _, want := range []string{"Rules, policy set query-driving-licence-check", "Trusted issuer only", "Status check", "Claim birth_date, rule At least N years, value 18."} {
		if !strings.Contains(body, want) {
			t.Errorf("the query page lacks %q", want)
		}
	}
}
