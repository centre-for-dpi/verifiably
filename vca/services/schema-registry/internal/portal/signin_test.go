// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	datasourcev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// fakeSignIn is the adapter side of the tab: it keeps one source.
type fakeSignIn struct {
	mu      sync.Mutex
	stored  *backendv1.HolderSignInSource
	sets    []*backendv1.SetHolderSignInSourceRequest
	gets    []*backendv1.GetHolderSignInSourceRequest
	vouched []string
	err     error
}

func (f *fakeSignIn) GetHolderSignInSource(_ context.Context, req *connect.Request[backendv1.GetHolderSignInSourceRequest]) (*connect.Response[backendv1.GetHolderSignInSourceResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets = append(f.gets, req.Msg)
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(&backendv1.GetHolderSignInSourceResponse{Source: f.stored, VouchedClaims: f.vouched}), nil
}

func (f *fakeSignIn) SetHolderSignInSource(_ context.Context, req *connect.Request[backendv1.SetHolderSignInSourceRequest]) (*connect.Response[backendv1.SetHolderSignInSourceResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sets = append(f.sets, req.Msg)
	if req.Msg.GetClear() {
		f.stored = nil
		return connect.NewResponse(&backendv1.SetHolderSignInSourceResponse{}), nil
	}
	if !slices.Contains(f.vouched, req.Msg.GetSource().GetTokenClaim()) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the holder provider does not vouch for the claim"))
	}
	f.stored = req.Msg.GetSource()
	return connect.NewResponse(&backendv1.SetHolderSignInSourceResponse{Source: f.stored}), nil
}

// fakeSources is the data source service of the pair. It records the
// bearer of each call, so the test sees the session travel.
type fakeSources struct {
	mu       sync.Mutex
	bearers  []string
	source   *datasourcev1.Source
	updates  []*datasourcev1.Source
	noMap    bool
	lookups  []*datasourcev1.LookupRequest
	lookup   *datasourcev1.LookupResponse
	denyEdit bool
}

func (f *fakeSources) seen(h http.Header) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bearers = append(f.bearers, h.Get("Authorization"))
}

func (f *fakeSources) List(_ context.Context, req *connect.Request[datasourcev1.ListRequest]) (*connect.Response[datasourcev1.ListResponse], error) {
	f.seen(req.Header())
	return connect.NewResponse(&datasourcev1.ListResponse{Sources: []*datasourcev1.Source{f.source}}), nil
}

func (f *fakeSources) Get(_ context.Context, req *connect.Request[datasourcev1.GetRequest]) (*connect.Response[datasourcev1.GetResponse], error) {
	f.seen(req.Header())
	if req.Msg.GetId() != f.source.GetId() {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no source"))
	}
	return connect.NewResponse(&datasourcev1.GetResponse{Source: f.source}), nil
}

func (f *fakeSources) Update(_ context.Context, req *connect.Request[datasourcev1.UpdateRequest]) (*connect.Response[datasourcev1.UpdateResponse], error) {
	f.seen(req.Header())
	if f.denyEdit {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("you do not have permission to do this"))
	}
	f.updates = append(f.updates, req.Msg.GetSource())
	f.source = req.Msg.GetSource()
	return connect.NewResponse(&datasourcev1.UpdateResponse{Source: f.source}), nil
}

func (f *fakeSources) PreviewFields(_ context.Context, req *connect.Request[datasourcev1.PreviewFieldsRequest]) (*connect.Response[datasourcev1.PreviewFieldsResponse], error) {
	f.seen(req.Header())
	return connect.NewResponse(&datasourcev1.PreviewFieldsResponse{Fields: []*datasourcev1.Field{
		{Name: "member_no", Type: "string"}, {Name: "given_name", Type: "string"},
	}}), nil
}

func (f *fakeSources) GetFieldMap(_ context.Context, req *connect.Request[datasourcev1.GetFieldMapRequest]) (*connect.Response[datasourcev1.GetFieldMapResponse], error) {
	f.seen(req.Header())
	if f.noMap {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no field map"))
	}
	return connect.NewResponse(&datasourcev1.GetFieldMapResponse{FieldMap: &datasourcev1.FieldMap{SourceId: req.Msg.GetSourceId(), SchemaId: req.Msg.GetSchemaId()}}), nil
}

func (f *fakeSources) Lookup(_ context.Context, req *connect.Request[datasourcev1.LookupRequest]) (*connect.Response[datasourcev1.LookupResponse], error) {
	f.seen(req.Header())
	f.lookups = append(f.lookups, req.Msg)
	return connect.NewResponse(f.lookup), nil
}

func memberRegister() *datasourcev1.Source {
	return &datasourcev1.Source{Id: "src-1", DisplayName: "Member register",
		Access: &datasourcev1.Source_Access{ViewFields: []string{"issuer-operator"}, Issue: []string{"issuer-operator"}}}
}

// sessionCookie is the session cookie value of the staff member.
const sessionCookie = "staff-session-cookie"

// signInFeatures is what the own stack lists when it takes a claim
// without an offer.
var signInFeatures = []backendv1.Feature{backendv1.Feature_FEATURE_CREDENTIAL_CONFIG_API, backendv1.Feature_FEATURE_HOLDER_SIGN_IN_SOURCE}

// signInServer wires a portal with a published schema, the shell of a
// stack that lists the features, and the two fakes. Each request
// carries the session cookie of the staff member.
func signInServer(t *testing.T, features []backendv1.Feature, signIn *fakeSignIn, sources *fakeSources) (http.Handler, string) {
	t.Helper()
	svc, _ := registry(t)
	ctx := context.Background()
	created, err := svc.Create(ctx, connect.NewRequest(&schemav1.CreateRequest{Schema: &schemav1.Schema{
		Type: "MembershipCard", JsonSchema: doc, Formats: []commonv1.Format{commonv1.Format_FORMAT_LDP_VC, commonv1.Format_FORMAT_DC_SD_JWT},
		Display: []*schemav1.Display{{Name: "Membership card", Locale: "en"}},
	}}))
	if err != nil {
		t.Fatal(err)
	}
	id := created.Msg.GetSchema().GetId()
	if _, perr := svc.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: id})); perr != nil {
		t.Fatal(perr)
	}
	shell := shellOf(stack{dpg: configv1.Dpg_DPG_INJI, name: firstStack, state: topology.Live, features: features,
		formats: []commonv1.Format{commonv1.Format_FORMAT_LDP_VC, commonv1.Format_FORMAT_DC_SD_JWT}})
	opts := Options{Client: svc, Shell: shell}
	if signIn != nil {
		opts.SignIn = signIn
	}
	if sources != nil {
		opts.Sources = sources
	}
	p, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	p.Register(mux)
	sess := staffsession.Session{Subject: "kc|staff", Name: "Staff member", CSRF: "tok", Roles: []string{"issuer-operator"}}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.AddCookie(&http.Cookie{Name: staffsession.IssuerCookie, Value: sessionCookie})
		mux.ServeHTTP(w, r.WithContext(staffsession.With(r.Context(), sess)))
	}), id
}

func postTo(h http.Handler, target string, form url.Values, htmx bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if htmx {
		r.Header.Set("HX-Request", "true")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// TestSignInSourceTabSavesAndTests walks the tab: the page lists the
// sources and the claims the provider vouches for, a pick of a source
// lists its fields, a save stores the source for every configuration
// of the version and lets the holder sign in read one row, a test shows
// the masked claims, and a remove clears it.
func TestSignInSourceTabSavesAndTests(t *testing.T) {
	signIn := &fakeSignIn{vouched: []string{"sub", "email", "phone_number"}}
	sources := &fakeSources{source: memberRegister(), lookup: &datasourcev1.LookupResponse{Found: true, SubjectData: `{"givenName":"G*******A","memberNumber":"M***0"}`}}
	h, id := signInServer(t, signInFeatures, signIn, sources)
	base := "/portal/schemas/" + id + "/signin"

	page := get(t, h, base)
	for _, want := range []string{`aria-current="page"`, "Claims by sign in", `value="src-1"`, "Member register"} {
		if !strings.Contains(page, want) {
			t.Errorf("the tab lacks %q", want)
		}
	}
	if len(signIn.gets) == 0 || len(signIn.gets[0].GetConfigurationIds()) != 2 {
		t.Fatalf("the tab asked for configurations %v, want the two of the version", signIn.gets)
	}
	picked := get(t, h, base+"?source=src-1")
	for _, want := range []string{
		`<option value="member_no"`, `<option value="given_name"`,
		`<option value="sub"`, `<option value="email"`, `<option value="phone_number"`, "[NATIONAL ID]",
	} {
		if !strings.Contains(picked, want) {
			t.Errorf("a picked source lacks %q", want)
		}
	}
	if strings.Contains(picked, "preferred_username") {
		t.Error("the tab offers a claim the provider does not vouch for")
	}
	for _, bearer := range sources.bearers {
		if bearer != "Bearer "+sessionCookie {
			t.Fatalf("a data source call carried %q, want the session of the staff member", bearer)
		}
	}

	rec := postTo(h, base, url.Values{"source": {"src-1"}, "field": {"member_no"}, "claim": {"sub"}}, false)
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "notice=signin-saved") {
		t.Fatalf("save: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	last := signIn.sets[len(signIn.sets)-1]
	if len(last.GetConfigurationIds()) != 2 || last.GetSource().GetSourceId() != "src-1" || last.GetSource().GetField() != "member_no" ||
		last.GetSource().GetTokenClaim() != "sub" || last.GetSource().GetSchemaId() != id || last.GetSource().GetSchemaVersion() != 1 {
		t.Fatalf("stored = %v", last)
	}
	if len(sources.updates) != 1 || !slices.Contains(sources.updates[0].GetAccess().GetIssue(), "holder-sign-in") ||
		!slices.Contains(sources.updates[0].GetAccess().GetIssue(), "issuer-operator") {
		t.Fatalf("the source access was not opened to the holder sign in: %v", sources.updates)
	}
	saved := get(t, h, base+"?notice=signin-saved")
	if !strings.Contains(saved, "Remove") || !strings.Contains(saved, `<option value="member_no" selected`) {
		t.Error("the saved source does not show")
	}
	// A second save keeps the rule as it is.
	postTo(h, base, url.Values{"source": {"src-1"}, "field": {"member_no"}, "claim": {"email"}}, false)
	if len(sources.updates) != 1 {
		t.Fatalf("a second save changed the access again: %d updates", len(sources.updates))
	}

	rec = postTo(h, base+"/test", url.Values{"source": {"src-1"}, "field": {"member_no"}, "value": {"M-100"}}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("test: %d %s", rec.Code, rec.Body.String())
	}
	fragment := rec.Body.String()
	a11ytest.AssertFragment(t, fragment)
	if !strings.Contains(fragment, "givenName") || !strings.Contains(fragment, "G*******A") || strings.Contains(fragment, "<html") {
		t.Fatalf("test fragment = %s", fragment)
	}
	if got := sources.lookups[0]; got.GetSourceId() != "src-1" || got.GetField() != "member_no" || got.GetValue() != "M-100" || got.GetSchemaId() != id {
		t.Fatalf("lookup = %v", got)
	}
	sources.lookup = &datasourcev1.LookupResponse{}
	if fragment = postTo(h, base+"/test", url.Values{"source": {"src-1"}, "field": {"member_no"}, "value": {"M-999"}}, true).Body.String(); !strings.Contains(fragment, "No row holds this value") {
		t.Fatalf("absent: %s", fragment)
	}
	sources.lookup = &datasourcev1.LookupResponse{Ambiguous: true}
	if fragment = postTo(h, base+"/test", url.Values{"source": {"src-1"}, "field": {"member_no"}, "value": {"M-200"}}, true).Body.String(); !strings.Contains(fragment, "Two or more rows") {
		t.Fatalf("ambiguous: %s", fragment)
	}

	rec = postTo(h, base, url.Values{"action": {"clear"}}, false)
	if rec.Code != http.StatusSeeOther || !signIn.sets[len(signIn.sets)-1].GetClear() || signIn.stored != nil {
		t.Fatalf("clear: %d %v", rec.Code, signIn.sets)
	}
}

// TestSignInSourceTabRefusals proves the tab explains each refusal on
// the page: a claim the provider does not vouch for, a missing field
// map, a staff member who cannot open the source, and a test without a
// value.
func TestSignInSourceTabRefusals(t *testing.T) {
	signIn := &fakeSignIn{vouched: []string{"sub", "email"}}
	sources := &fakeSources{source: memberRegister(), noMap: true, lookup: &datasourcev1.LookupResponse{}}
	h, id := signInServer(t, signInFeatures, signIn, sources)
	base := "/portal/schemas/" + id + "/signin"

	page := get(t, h, base+"?source=src-1")
	if !strings.Contains(page, "/sources/src-1/map?schema="+id) {
		t.Error("the tab does not link to the field map of the source")
	}
	rec := postTo(h, base, url.Values{"source": {"src-1"}, "field": {"member_no"}, "claim": {"preferred_username"}}, false)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "does not vouch") {
		t.Fatalf("an unvouched claim: %d", rec.Code)
	}
	a11ytest.AssertPage(t, rec.Body.String())
	rec = postTo(h, base, url.Values{"source": {"src-1"}, "claim": {"sub"}}, false)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("no field: %d", rec.Code)
	}
	sources.noMap, sources.denyEdit = false, true
	rec = postTo(h, base, url.Values{"source": {"src-1"}, "field": {"member_no"}, "claim": {"sub"}}, false)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "administrator") {
		t.Fatalf("a staff member who cannot edit the source: %d", rec.Code)
	}
	if len(signIn.sets) != 0 {
		t.Fatalf("the adapter stored a source the data source refused: %v", signIn.sets)
	}
	fragment := postTo(h, base+"/test", url.Values{"source": {"src-1"}, "field": {"member_no"}}, true).Body.String()
	a11ytest.AssertFragment(t, fragment)
	if !strings.Contains(fragment, "Type a value") {
		t.Fatalf("a test without a value: %s", fragment)
	}
	signIn.err = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	down := get(t, h, base)
	if !strings.Contains(down, "cannot reach") {
		t.Error("the tab hides an adapter that does not answer")
	}
}

// TestSignInSourceTabNeedsTheFeature proves the tab shows only for a
// stack that lists the feature and a published version, and the detail
// page links to it then.
func TestSignInSourceTabNeedsTheFeature(t *testing.T) {
	signIn := &fakeSignIn{vouched: []string{"sub"}}
	sources := &fakeSources{source: memberRegister()}
	h, id := signInServer(t, signInFeatures, signIn, sources)
	if detail := get(t, h, "/portal/schemas/"+id); !strings.Contains(detail, `href="/portal/schemas/`+id+`/signin?version=1"`) {
		t.Error("the detail page lacks the tab")
	}
	off, offID := signInServer(t, configAPI, signIn, sources)
	if detail := get(t, off, "/portal/schemas/"+offID); strings.Contains(detail, "/signin") {
		t.Error("a stack without the feature shows the tab")
	}
	if page := get(t, off, "/portal/schemas/"+offID+"/signin"); !strings.Contains(page, "takes no claim without an offer") {
		t.Error("the tab of a stack without the feature does not say why")
	}
	bare, bareID := signInServer(t, signInFeatures, nil, nil)
	if detail := get(t, bare, "/portal/schemas/"+bareID); strings.Contains(detail, "/signin") {
		t.Error("a portal without the clients shows the tab")
	}
	// A draft has no configuration yet.
	svcDraft, draftID := registry(t)
	shell := shellOf(stack{dpg: configv1.Dpg_DPG_INJI, name: firstStack, state: topology.Live, features: signInFeatures})
	p, err := New(Options{Client: svcDraft, Shell: shell, SignIn: signIn, Sources: sources})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	p.Register(mux)
	draft := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r.WithContext(staffsession.With(r.Context(), staffsession.Session{Subject: "kc|staff", CSRF: "tok"})))
	})
	if page := get(t, draft, "/portal/schemas/"+draftID+"/signin"); !strings.Contains(page, "Publish this version first") {
		t.Error("a draft does not say it needs a publish")
	}
}
