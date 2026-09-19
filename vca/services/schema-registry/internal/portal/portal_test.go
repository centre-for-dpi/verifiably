// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1/schemav1connect"
	sharedstore "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/store"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

const doc = `{"type":"object","properties":{"name":{"type":"string","title":"Full name"},"age":{"type":"integer"}},"required":["name"]}`

var now = time.Date(2024, 1, 31, 10, 0, 0, 0, time.UTC)

// registry builds a service with one draft schema and returns its id.
func registry(t *testing.T) (*service.Service, string) {
	t.Helper()
	n := 0
	st, err := store.Open(sharedstore.MemoryDoc(), store.Options{NewID: func(string) string {
		n++
		return "degree-" + string(rune('a'+n-1))
	}})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(service.Options{Store: st, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := svc.Create(context.Background(), connect.NewRequest(&schemav1.CreateRequest{Schema: &schemav1.Schema{
		Type: "UniversityDegree", JsonSchema: doc,
		Formats:  []commonv1.Format{commonv1.Format_FORMAT_DC_SD_JWT},
		Display:  []*schemav1.Display{{Name: "Degree", Description: "A university degree", Locale: "en"}},
		SdClaims: []string{"name"}, SearchableClaims: []string{"age"}, CreatedBy: "staff@example",
	}}))
	if err != nil {
		t.Fatal(err)
	}
	return svc, resp.Msg.GetSchema().GetId()
}

// server wires a portal over a client and returns the mux.
func server(t *testing.T, client schemav1connect.SchemaServiceClient) *http.ServeMux {
	t.Helper()
	p, err := New(Options{Client: client, BuilderURL: "https://builder.example/"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Prefix() != DefaultPrefix {
		t.Fatalf("prefix %q", p.Prefix())
	}
	mux := http.NewServeMux()
	p.Register(mux)
	return mux
}

func do(t *testing.T, mux *http.ServeMux, method, target string, form url.Values, header http.Header) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if form == nil {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range header {
		req.Header[k] = v
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func page(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	a11ytest.AssertPage(t, body)
	return body
}

func TestNewRejectsNoClient(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("want an error without a client")
	}
}

func TestListPage(t *testing.T) {
	svc, id := registry(t)
	mux := server(t, svc)
	body := page(t, do(t, mux, http.MethodGet, DefaultPrefix+"/", nil, nil))
	// html/template writes a plus sign as the numeric reference &#43;.
	for _, want := range []string{"Degree", "UniversityDegree", "Draft", "dc&#43;sd-jwt", DefaultPrefix + "/schemas/" + id} {
		if !strings.Contains(body, want) {
			t.Fatalf("list page has no %q", want)
		}
	}
	if !strings.Contains(body, `id="q"`) || !strings.Contains(body, `id="state"`) || !strings.Contains(body, `id="format"`) {
		t.Fatal("list page has no search or filter controls")
	}
}

func TestListSearchAndFilters(t *testing.T) {
	svc, _ := registry(t)
	mux := server(t, svc)
	cases := []struct {
		query string
		found bool
	}{
		{"q=degree", true},
		{"q=degree&state=draft", true},
		{"q=degree&state=published", false},
		{"q=degree&format=dc%2Bsd-jwt", true},
		{"q=degree&format=mso_mdoc", false},
		{"q=nothing", false},
		{"state=published", false},
		{"format=ldp_vc", false},
		{"state=unknown&format=unknown", true},
	}
	for _, c := range cases {
		body := page(t, do(t, mux, http.MethodGet, DefaultPrefix+"/?"+c.query, nil, nil))
		got := strings.Contains(body, "UniversityDegree")
		if got != c.found {
			t.Fatalf("%s: found=%v want %v", c.query, got, c.found)
		}
		if !c.found && !strings.Contains(body, "No schema matches") {
			t.Fatalf("%s: no empty message", c.query)
		}
	}
}

func TestDetailPageDraft(t *testing.T) {
	svc, id := registry(t)
	mux := server(t, svc)
	body := page(t, do(t, mux, http.MethodGet, DefaultPrefix+"/schemas/"+id, nil, nil))
	for _, want := range []string{"Publish this version", "Full name", "Selectively disclosable", "JSON Schema 2020-12 document", "Version history"} {
		if !strings.Contains(body, want) {
			t.Fatalf("detail page has no %q", want)
		}
	}
	// The version query selects one version.
	page(t, do(t, mux, http.MethodGet, DefaultPrefix+"/schemas/"+id+"?version=1", nil, nil))
	page(t, do(t, mux, http.MethodGet, DefaultPrefix+"/schemas/"+id+"?version=bad", nil, nil))
}

func TestDetailPageBrokenDocument(t *testing.T) {
	svc, _ := registry(t)
	mux := server(t, svc)
	resp, err := svc.Create(context.Background(), connect.NewRequest(&schemav1.CreateRequest{Schema: &schemav1.Schema{
		Type: "Plain", JsonSchema: `true`, Formats: []commonv1.Format{commonv1.Format_FORMAT_LDP_VC},
	}}))
	if err != nil {
		t.Fatal(err)
	}
	body := page(t, do(t, mux, http.MethodGet, DefaultPrefix+"/schemas/"+resp.Msg.GetSchema().GetId(), nil, nil))
	if !strings.Contains(body, "declares no property") {
		t.Fatal("want the empty claims message")
	}
}

func TestPublishThenRetire(t *testing.T) {
	svc, id := registry(t)
	mux := server(t, svc)
	rec := do(t, mux, http.MethodPost, DefaultPrefix+"/schemas/"+id+"/publish", url.Values{"version": {"1"}}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("publish status %d", rec.Code)
	}
	target := rec.Header().Get("Location")
	if !strings.Contains(target, "notice=published") {
		t.Fatalf("location %q", target)
	}
	body := page(t, do(t, mux, http.MethodGet, target, nil, nil))
	for _, want := range []string{"The version is published", "Retire this version", "Published"} {
		if !strings.Contains(body, want) {
			t.Fatalf("published detail page has no %q", want)
		}
	}
	rec = do(t, mux, http.MethodPost, DefaultPrefix+"/schemas/"+id+"/retire",
		url.Values{"version": {"1"}, "reason": {strings.Repeat("x", MaxReasonLength+10)}}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("retire status %d", rec.Code)
	}
	body = page(t, do(t, mux, http.MethodGet, rec.Header().Get("Location"), nil, nil))
	for _, want := range []string{"The version is retired", "no action left"} {
		if !strings.Contains(body, want) {
			t.Fatalf("retired detail page has no %q", want)
		}
	}
}

func TestPublishOverHTMX(t *testing.T) {
	svc, id := registry(t)
	mux := server(t, svc)
	rec := do(t, mux, http.MethodPost, DefaultPrefix+"/schemas/"+id+"/publish", url.Values{},
		http.Header{"Hx-Request": {"true"}})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("HX-Redirect"), "notice=published") {
		t.Fatalf("redirect %q", rec.Header().Get("HX-Redirect"))
	}
}

func TestActionErrors(t *testing.T) {
	svc, id := registry(t)
	mux := server(t, svc)
	cases := []struct {
		path   string
		form   url.Values
		status int
	}{
		{"/schemas/" + id + "/publish", url.Values{"version": {"x"}}, http.StatusBadRequest},
		{"/schemas/" + id + "/publish", url.Values{"version": {"9"}}, http.StatusNotFound},
		{"/schemas/" + id + "/retire", url.Values{"version": {"-1"}}, http.StatusBadRequest},
		{"/schemas/" + id + "/retire", url.Values{"version": {"1"}}, http.StatusBadRequest},
		{"/schemas/missing/publish", url.Values{}, http.StatusNotFound},
	}
	for _, c := range cases {
		rec := do(t, mux, http.MethodPost, DefaultPrefix+c.path, c.form, nil)
		if rec.Code != c.status {
			t.Fatalf("%s %v: status %d want %d", c.path, c.form, rec.Code, c.status)
		}
	}
}

func TestVersionHistory(t *testing.T) {
	svc, id := registry(t)
	mux := server(t, svc)
	if _, err := svc.Update(context.Background(), connect.NewRequest(&schemav1.UpdateRequest{Schema: &schemav1.Schema{
		Id: id, Type: "UniversityDegree", JsonSchema: doc,
		Formats: []commonv1.Format{commonv1.Format_FORMAT_DC_SD_JWT}, CreatedBy: "staff@example",
	}})); err != nil {
		t.Fatal(err)
	}
	body := page(t, do(t, mux, http.MethodGet, DefaultPrefix+"/schemas/"+id+"/versions", nil, nil))
	for _, want := range []string{"Version 1", "Version 2", "staff@example", "Back to the schema"} {
		if !strings.Contains(body, want) {
			t.Fatalf("history page has no %q", want)
		}
	}
	if rec := do(t, mux, http.MethodGet, DefaultPrefix+"/schemas/missing/versions", nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("missing history status %d", rec.Code)
	}
}

func TestDetailNotFound(t *testing.T) {
	svc, _ := registry(t)
	mux := server(t, svc)
	if rec := do(t, mux, http.MethodGet, DefaultPrefix+"/schemas/missing", nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("status %d", rec.Code)
	}
}

// failing is a client whose every call returns err.
type failing struct {
	schemav1connect.UnimplementedSchemaServiceHandler
	err error
}

func (f failing) List(context.Context, *connect.Request[schemav1.ListRequest]) (*connect.Response[schemav1.ListResponse], error) {
	return nil, f.err
}

func (f failing) Search(context.Context, *connect.Request[schemav1.SearchRequest]) (*connect.Response[schemav1.SearchResponse], error) {
	return nil, f.err
}

func (f failing) Get(context.Context, *connect.Request[schemav1.GetRequest]) (*connect.Response[schemav1.GetResponse], error) {
	return nil, f.err
}

func (f failing) ListVersions(context.Context, *connect.Request[schemav1.ListVersionsRequest]) (*connect.Response[schemav1.ListVersionsResponse], error) {
	return nil, f.err
}

func (f failing) Publish(context.Context, *connect.Request[schemav1.PublishRequest]) (*connect.Response[schemav1.PublishResponse], error) {
	return nil, f.err
}

func (f failing) Retire(context.Context, *connect.Request[schemav1.RetireRequest]) (*connect.Response[schemav1.RetireResponse], error) {
	return nil, f.err
}

func TestBackendFailureIsServerError(t *testing.T) {
	mux := server(t, failing{err: connect.NewError(connect.CodeUnavailable, http.ErrServerClosed)})
	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/"},
		{http.MethodGet, "/?q=x"},
		{http.MethodGet, "/schemas/a"},
		{http.MethodGet, "/schemas/a/versions"},
		{http.MethodPost, "/schemas/a/publish"},
		{http.MethodPost, "/schemas/a/retire"},
	}
	for _, c := range cases {
		var form url.Values
		if c.method == http.MethodPost {
			form = url.Values{}
		}
		rec := do(t, mux, c.method, DefaultPrefix+c.path, form, nil)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("%s: status %d", c.path, rec.Code)
		}
	}
}

func TestStateAndFormatHelpers(t *testing.T) {
	if StateText(schemav1.State_STATE_UNSPECIFIED) != "Any state" || StateStatus(schemav1.State_STATE_UNSPECIFIED) != "info" {
		t.Fatal("unspecified state")
	}
	if StateValue(schemav1.State_STATE_UNSPECIFIED) != "" || ParseState("  DRAFT ") != schemav1.State_STATE_DRAFT {
		t.Fatal("state values")
	}
	if FormatValue(commonv1.Format_FORMAT_UNSPECIFIED) != "" || ParseFormat("nope") != commonv1.Format_FORMAT_UNSPECIFIED {
		t.Fatal("format values")
	}
	for _, f := range Formats {
		if FormatValue(f) == "" || ParseFormat(FormatValue(f)) != f {
			t.Fatalf("format %v", f)
		}
	}
	for _, s := range States {
		if StateStatus(s) == "" || ParseState(StateValue(s)) != s {
			t.Fatalf("state %v", s)
		}
	}
	if Name(&schemav1.Schema{Type: "T"}) != "T" {
		t.Fatal("name falls back to the type")
	}
	if Name(&schemav1.Schema{Type: "T", Display: []*schemav1.Display{{Name: "N"}}}) != "N" {
		t.Fatal("name from the display")
	}
	if yesNo(true) != "Yes" || yesNo(false) != "No" {
		t.Fatal("yes or no")
	}
	if stamp("x", false) != "-" || stamp("x", true) != "x" {
		t.Fatal("stamp")
	}
	if rawJSON("{") != "{" {
		t.Fatal("raw json keeps a broken document")
	}
	if Claims("{") != nil {
		t.Fatal("claims of a broken document")
	}
}

func TestClaims(t *testing.T) {
	claims := Claims(doc)
	if len(claims) != 2 {
		t.Fatalf("claims %+v", claims)
	}
	if claims[0].Name != "name" || claims[0].Title != "Full name" || claims[0].Type != "string" || !claims[0].Required {
		t.Fatalf("first claim %+v", claims[0])
	}
	if claims[1].Title != "age" || claims[1].Required {
		t.Fatalf("second claim %+v", claims[1])
	}
}

func TestRetireEveryPublishedVersion(t *testing.T) {
	svc, id := registry(t)
	mux := server(t, svc)
	if _, err := svc.Publish(context.Background(), connect.NewRequest(&schemav1.PublishRequest{Id: id})); err != nil {
		t.Fatal(err)
	}
	// An empty version field retires every published version.
	rec := do(t, mux, http.MethodPost, DefaultPrefix+"/schemas/"+id+"/retire", url.Values{"reason": {"wrong claims"}}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != DefaultPrefix+"/schemas/"+id+"?notice=retired" {
		t.Fatalf("location %q", got)
	}
}

func TestNewNormalizesThePrefix(t *testing.T) {
	svc, _ := registry(t)
	kit, err := components.New()
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(Options{Client: svc, Kit: kit, Prefix: "staff/schemas/"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Prefix() != "/staff/schemas" {
		t.Fatalf("prefix %q", p.Prefix())
	}
	mux := http.NewServeMux()
	p.Register(mux)
	page(t, do(t, mux, http.MethodGet, "/staff/schemas/", nil, nil))
}

func TestStatusOfPlainError(t *testing.T) {
	if statusOf(http.ErrServerClosed) != http.StatusInternalServerError {
		t.Fatal("plain error")
	}
}

func TestNotice(t *testing.T) {
	if notice("nope") != nil || len(notice("published")) != 1 {
		t.Fatal("notice")
	}
}
