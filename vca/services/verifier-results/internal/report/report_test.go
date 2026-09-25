// SPDX-License-Identifier: Apache-2.0

package report

import (
	"bytes"
	"compress/zlib"
	"io"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
)

var at = time.Date(2026, 9, 25, 9, 30, 0, 0, time.UTC)

// secret marks the parts of a result that a report must never hold.
const secret = "RAW-PRESENTATION-MARKER"

func result() *resultsv1.VerificationResult {
	return &resultsv1.VerificationResult{
		Id: "res-42", Verdict: policyv1.EvaluateResponse_VERDICT_VALID, TemplateId: "licence", TemplateVersion: 3,
		PolicySetId: "query-licence", PolicySetVersion: 1, EvaluatedAt: timestamppb.New(at), Carrier: "oid4vp",
		RawRef: "ref-" + secret, MaterialAge: durationpb.New(2 * time.Hour), MaterialStale: true, Stack: "Modern stack",
		Checks: []*policyv1.CheckResult{{Name: "nonce", Outcome: policyv1.Outcome_OUTCOME_PASS, Detail: "The nonce matches."}},
		StackChecks: []*backendv1.GetResultResponse_DpgCheck{
			{Name: "signature", Passed: true}, {Name: "expired", Passed: false, Reason: "The credential (copy) expired."},
		},
		Credentials: []*resultsv1.CredentialSummary{{
			Title: "Driving licence", Type: "DrivingLicence", Issuer: "did:web:transport.example", IssuerName: "Transport Authority",
			Trust: "trusted", DisplayFields: map[string]string{"given_name": "Wanjiru-" + secret, "licence_class": "B-" + secret},
			Validity:    &commonv1.ValidityWindow{ValidUntil: timestamppb.New(at.Add(365 * 24 * time.Hour))},
			DecodedJson: `{"given_name":"` + secret + `"}`,
			Checks: []*policyv1.CheckResult{
				{Name: "signature", Outcome: policyv1.Outcome_OUTCOME_PASS, Detail: "The issuer signature is valid."},
				{Name: "trust_chain", Outcome: policyv1.Outcome_OUTCOME_PASS, Detail: strings.Repeat("A long detail that wraps over the line. ", 6)},
			},
		}},
	}
}

// text returns the strings the content stream of a PDF draws.
func text(t *testing.T, doc []byte) string {
	t.Helper()
	var out strings.Builder
	for _, m := range regexp.MustCompile(`(?s)/FlateDecode[^>]*>>\s*stream\r?\n(.*?)\r?\nendstream`).FindAllSubmatch(doc, -1) {
		r, err := zlib.NewReader(bytes.NewReader(m[1]))
		if err != nil {
			continue
		}
		raw, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range regexp.MustCompile(`\(((?:\\.|[^\\)])*)\) Tj`).FindAllSubmatch(raw, -1) {
			out.WriteString(strings.NewReplacer(`\(`, "(", `\)`, ")", `\\`, `\`).Replace(string(s[1])))
			out.WriteString("\n")
		}
	}
	return out.String()
}

// TestReportPDFHasNoRawPresentation writes a one page PDF with the
// verdict, the checks of VCA and of the stack, and the cache age. It
// never holds the raw presentation, the decoded credential, or a claim
// value.
func TestReportPDFHasNoRawPresentation(t *testing.T) {
	doc := PDF(result(), "Driving licence check", at.Add(time.Hour))
	if !bytes.HasPrefix(doc, []byte("%PDF-1.4")) {
		t.Fatal("not a PDF")
	}
	if bytes.Contains(doc, []byte(secret)) {
		t.Fatal("the file holds the raw presentation")
	}
	got := text(t, doc)
	if strings.Contains(got, secret) {
		t.Fatal("the report text holds a claim value or the raw presentation")
	}
	for _, want := range []string{
		"Verification report", "res-42", "Valid", "Driving licence check", "query-licence v1", "Modern stack",
		"From the cache, 2 h old. Stale.", "nonce", "The nonce matches.", "expired", "The credential (copy) expired.",
		"Driving licence", "Transport Authority", "did:web:transport.example", "given_name, licence_class",
		"The report holds no presentation and no claim value.",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the report lacks %q:\n%s", want, got)
		}
	}
}

// TestReportFitsOnePage cuts a long result at the foot of the page and
// says so.
func TestReportFitsOnePage(t *testing.T) {
	r := result()
	r.MaterialAge, r.Stack, r.StackChecks = nil, "", nil
	for i := 0; i < 80; i++ {
		r.Checks = append(r.Checks, &policyv1.CheckResult{Name: "check_" + strconv.Itoa(i), Outcome: policyv1.Outcome_OUTCOME_FAIL})
	}
	got := text(t, PDF(r, "", at))
	for _, want := range []string{"Read online", "The VCA verifier", "licence v3", "The staff page shows the rest of the result."} {
		if !strings.Contains(got, want) {
			t.Errorf("the report lacks %q", want)
		}
	}
	if strings.Contains(got, "check_79") {
		t.Error("the report runs past the page")
	}
}

// TestWords names every verdict and outcome, and keeps an empty line.
func TestWords(t *testing.T) {
	for _, v := range []policyv1.EvaluateResponse_Verdict{0, 1, 2, 3} {
		if verdictWord(v) == "" {
			t.Errorf("no word for %s", v)
		}
	}
	for _, o := range []policyv1.Outcome{0, 1, 2, 3, 4} {
		if outcomeWord(o) == "" {
			t.Errorf("no word for %s", o)
		}
	}
	if got := wrap("Helvetica", 10, 100, ""); len(got) != 1 || got[0] != "" {
		t.Errorf("wrap of nothing = %q", got)
	}
	r := &resultsv1.VerificationResult{Credentials: []*resultsv1.CredentialSummary{{Type: "Degree", Issuer: "did:web:u.example"}}}
	got := text(t, PDF(r, "", at))
	for _, want := range []string{"Degree", "Issuer: did:web:u.example", "Query: Unknown now", "Verdict: Unknown now"} {
		if !strings.Contains(got, want) {
			t.Errorf("the report lacks %q:\n%s", want, got)
		}
	}
}
