// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-results/internal/results"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-results/internal/service"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var testNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func sample(id string) *resultsv1.VerificationResult {
	return &resultsv1.VerificationResult{
		Id:          id,
		Verdict:     policyv1.EvaluateResponse_VERDICT_VALID,
		EvaluatedAt: timestamppb.New(testNow),
		TemplateId:  "age",
		Credentials: []*resultsv1.CredentialSummary{{
			Title: "Passport", Issuer: "did:web:issuer", IssuerName: "Ministry", Trust: "trusted",
		}},
	}
}

// fixture holds a portal with one stored result.
type fixture struct {
	portal *Portal
	mux    *http.ServeMux
	store  *results.Store
}

func newFixture(t *testing.T, evaluate Evaluator) fixture {
	t.Helper()
	st := results.New(store.Memory(), nil)
	svc, err := service.New(service.Options{
		Store: st, Retention: time.Hour, RawRetention: time.Hour,
		Now: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(Options{Service: svc, Evaluate: evaluate, Now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	p.Register(mux)
	if _, err := st.Put(context.Background(), sample("one")); err != nil {
		t.Fatal(err)
	}
	return fixture{portal: p, mux: mux, store: st}
}

// get runs one GET and returns the response.
func (f fixture) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// post runs one POST with a form body.
func (f fixture) post(t *testing.T, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

func TestNewRequiresService(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("want an error without a service")
	}
}

func TestPrefixes(t *testing.T) {
	f := newFixture(t, nil)
	if f.portal.Prefix() != DefaultPrefix || f.portal.PublicPrefix() != DefaultPublicPrefix {
		t.Fatalf("unexpected prefixes: %s %s", f.portal.Prefix(), f.portal.PublicPrefix())
	}
	if got := clean("/staff/", "/portal"); got != "/staff" {
		t.Fatalf("want /staff, got %q", got)
	}
}

func TestListPage(t *testing.T) {
	f := newFixture(t, nil)
	rec := f.get(t, DefaultPrefix+"/")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Verifications", "Download CSV", "Open", "age"} {
		if !strings.Contains(body, want) {
			t.Fatalf("want %q on the list page", want)
		}
	}
	a11ytest.AssertPage(t, body)
}

func TestListPageFilters(t *testing.T) {
	f := newFixture(t, nil)
	ok := f.get(t, DefaultPrefix+"/?from=2026-01-01&to=2026-12-31&verdict=valid&issuer=did:web:issuer&template=age")
	if !strings.Contains(ok.Body.String(), "Open") {
		t.Fatal("want the result to match the filter")
	}
	none := f.get(t, DefaultPrefix+"/?verdict=invalid")
	if !strings.Contains(none.Body.String(), "No verification matches") {
		t.Fatal("want the empty message")
	}
	bad := f.get(t, DefaultPrefix+"/?from=yesterday")
	body := bad.Body.String()
	if !strings.Contains(body, "YYYY-MM-DD") {
		t.Fatal("want the date problem on the page")
	}
	a11ytest.AssertPage(t, body)
	if badTo := f.get(t, DefaultPrefix+"/?to=soon"); !strings.Contains(badTo.Body.String(), "YYYY-MM-DD") {
		t.Fatal("want the date problem for the second field")
	}
}

func TestDetailPage(t *testing.T) {
	f := newFixture(t, nil)
	rec := f.get(t, DefaultPrefix+"/results/one")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Passport") || !strings.Contains(body, "Back to the list") {
		t.Fatalf("unexpected page: %s", body)
	}
	a11ytest.AssertPage(t, body)
	if missing := f.get(t, DefaultPrefix+"/results/missing"); missing.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", missing.Code)
	}
}

func TestDownload(t *testing.T) {
	f := newFixture(t, nil)
	csv := f.get(t, DefaultPrefix+"/export?encoding=csv")
	if csv.Code != http.StatusOK || !strings.Contains(csv.Body.String(), "result_id") {
		t.Fatalf("unexpected CSV export: %d %s", csv.Code, csv.Body.String())
	}
	if !strings.Contains(csv.Header().Get("Content-Disposition"), ".csv") {
		t.Fatalf("want a CSV file name, got %q", csv.Header().Get("Content-Disposition"))
	}
	jsonl := f.get(t, DefaultPrefix+"/export?encoding=json")
	if !strings.Contains(jsonl.Body.String(), `"id":"one"`) {
		t.Fatalf("unexpected JSON export: %s", jsonl.Body.String())
	}
	bad := f.get(t, DefaultPrefix+"/export?from=never")
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", bad.Code)
	}
}

func TestPublicPage(t *testing.T) {
	f := newFixture(t, func(context.Context, []byte) (*resultsv1.VerificationResult, error) {
		return sample("checked"), nil
	})
	form := f.get(t, DefaultPublicPrefix+"/")
	if form.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", form.Code)
	}
	a11ytest.AssertPage(t, form.Body.String())

	checked := f.post(t, DefaultPublicPrefix+"/", url.Values{"presentation": {"a token"}})
	body := checked.Body.String()
	if !strings.Contains(body, "Passport") {
		t.Fatalf("want the card on the citizen page: %s", body)
	}
	a11ytest.AssertPage(t, body)

	all, err := f.store.All(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("want the citizen check to store nothing, got %d results", len(all))
	}
}

func TestPublicProblems(t *testing.T) {
	f := newFixture(t, func(context.Context, []byte) (*resultsv1.VerificationResult, error) {
		return nil, errors.New("offline")
	})
	empty := f.post(t, DefaultPublicPrefix+"/", url.Values{})
	if !strings.Contains(empty.Body.String(), "Paste a credential") {
		t.Fatal("want the empty message")
	}
	failed := f.post(t, DefaultPublicPrefix+"/", url.Values{"presentation": {"a token"}})
	if !strings.Contains(failed.Body.String(), "did not run") {
		t.Fatal("want the failure message")
	}

	none := newFixture(t, nil)
	off := none.post(t, DefaultPublicPrefix+"/", url.Values{"presentation": {"a token"}})
	if !strings.Contains(off.Body.String(), "does not offer") {
		t.Fatal("want the message of a deployment without the check")
	}

	small := newFixture(t, nil)
	small.portal.opts.MaxPasteBytes = 2
	long := small.post(t, DefaultPublicPrefix+"/", url.Values{"presentation": {"a very long token"}})
	if !strings.Contains(long.Body.String(), "too long") {
		t.Fatal("want the length message")
	}
}

func TestPublicBadForm(t *testing.T) {
	f := newFixture(t, nil)
	req := httptest.NewRequest(http.MethodPost, DefaultPublicPrefix+"/", strings.NewReader("%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "could not be read") {
		t.Fatalf("want the form problem, got %s", rec.Body.String())
	}
}

func TestVerdictOf(t *testing.T) {
	cases := map[string]policyv1.EvaluateResponse_Verdict{
		"valid":         policyv1.EvaluateResponse_VERDICT_VALID,
		"invalid":       policyv1.EvaluateResponse_VERDICT_INVALID,
		"indeterminate": policyv1.EvaluateResponse_VERDICT_INDETERMINATE,
		"":              policyv1.EvaluateResponse_VERDICT_UNSPECIFIED,
	}
	for in, want := range cases {
		if got := verdictOf(in); got != want {
			t.Fatalf("%q: want %s, got %s", in, want, got)
		}
	}
}

func TestAtFallback(t *testing.T) {
	if got := at(&resultsv1.VerificationResult{}); got != "not known" {
		t.Fatalf("want the fallback, got %q", got)
	}
}

// brokenKV fails every list.
type brokenKV struct{ store.KeyValue }

func (brokenKV) List(context.Context, string) ([]string, error) { return nil, errors.New("broken") }

func TestPageErrors(t *testing.T) {
	svc, err := service.New(service.Options{
		Store: results.New(brokenKV{store.Memory()}, nil), Retention: time.Hour, RawRetention: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(Options{Service: svc})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	p.Register(mux)
	for _, path := range []string{DefaultPrefix + "/", DefaultPrefix + "/export"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("%s: want 500, got %d", path, rec.Code)
		}
	}
}
