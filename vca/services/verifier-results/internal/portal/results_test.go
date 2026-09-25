// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// TestFiltersByTemplateIssuerVerdict offers the saved queries, the
// issuers and the verdicts of the stored results as choices, and lists
// only the results that match all three.
func TestFiltersByTemplateIssuerVerdict(t *testing.T) {
	f := newShellFixture(t)
	third := sample("three")
	third.TemplateId, third.Verdict = "degree", policyv1.EvaluateResponse_VERDICT_VALID
	third.Credentials[0].Issuer = "https://university.labs.example"
	third.EvaluatedAt = timestamppb.New(testNow.Add(2 * time.Minute))
	if _, err := f.store.Put(context.Background(), third); err != nil {
		t.Fatal(err)
	}
	all := ok(t, f.get(t, DefaultPrefix+"/results/"))
	a11ytest.AssertPage(t, all)
	for _, want := range []string{
		`<select`, `<option value="degree">Degree check</option>`, `<option value="age">age</option>`,
		`<option value="https://university.labs.example">`, `<option value="did:web:issuer">Ministry</option>`,
		`<option value="invalid">`,
	} {
		if !strings.Contains(all, want) {
			t.Errorf("the filter form lacks %q", want)
		}
	}
	got := ok(t, f.get(t, DefaultPrefix+"/results/?template=degree&issuer=https%3A%2F%2Funiversity.labs.example&verdict=invalid"))
	a11ytest.AssertPage(t, got)
	if !strings.Contains(got, `href="/portal/results/two"`) || strings.Contains(got, `href="/portal/results/three"`) ||
		strings.Contains(got, `href="/portal/results/one"`) {
		t.Error("the filtered list does not hold only the invalid degree result")
	}
	for _, want := range []string{`<option value="degree" selected>`, `<option value="invalid" selected>`, `<option value="https://university.labs.example" selected>`} {
		if !strings.Contains(got, want) {
			t.Errorf("the filter form lacks the choice %q", want)
		}
	}
	if !strings.Contains(got, "Degree check") || !strings.Contains(got, "https://university.labs.example") {
		t.Error("the list names the query and the issuer of each result")
	}
}

// TestResultReportDownload offers the report on the result page and
// serves it as a PDF attachment.
func TestResultReportDownload(t *testing.T) {
	f := newShellFixture(t)
	r := sample("cached")
	r.MaterialAge, r.Stack = durationpb.New(90*time.Minute), "Second stack"
	r.StackChecks = []*backendv1.GetResultResponse_DpgCheck{{Name: "signature", Passed: true}}
	r.RawRef = "raw-ref-7"
	if _, err := f.store.Put(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	page := ok(t, f.get(t, DefaultPrefix+"/results/cached"))
	a11ytest.AssertPage(t, page)
	for _, want := range []string{"Download report", `href="/portal/results/cached/report.pdf"`, "From the cache, 1 h old", "Checks of Second stack"} {
		if !strings.Contains(page, want) {
			t.Errorf("the result page lacks %q", want)
		}
	}
	rec := f.get(t, DefaultPrefix+"/results/cached/report.pdf")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/pdf" ||
		!strings.Contains(rec.Header().Get("Content-Disposition"), `filename="verification-cached.pdf"`) ||
		!bytes.HasPrefix(rec.Body.Bytes(), []byte("%PDF-1.4")) || bytes.Contains(rec.Body.Bytes(), []byte("raw-ref-7")) {
		t.Fatalf("report = %d %v", rec.Code, rec.Header())
	}
	if missing := f.get(t, DefaultPrefix+"/results/nobody/report.pdf"); missing.Code != http.StatusNotFound {
		t.Fatalf("a missing report = %d", missing.Code)
	}
}
