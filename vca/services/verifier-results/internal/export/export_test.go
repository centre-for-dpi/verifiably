// SPDX-License-Identifier: Apache-2.0

package export

import (
	"bytes"
	"encoding/csv"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
)

var at = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func sample() *resultsv1.VerificationResult {
	return &resultsv1.VerificationResult{
		Id:          "one",
		Verdict:     policyv1.EvaluateResponse_VERDICT_VALID,
		EvaluatedAt: timestamppb.New(at),
		Carrier:     "oid4vp",
		TemplateId:  "age",
		Credentials: []*resultsv1.CredentialSummary{{
			Type: "Passport", Issuer: "did:web:issuer", IssuerName: "Ministry", Trust: "trusted",
			Checks: []*policyv1.CheckResult{
				{Name: "signature", Outcome: policyv1.Outcome_OUTCOME_PASS},
				{Name: "status", Outcome: policyv1.Outcome_OUTCOME_FAIL},
				{Name: "schema", Outcome: policyv1.Outcome_OUTCOME_SKIP},
			},
		}},
	}
}

func TestCSVRows(t *testing.T) {
	var buf bytes.Buffer
	if err := CSV(&buf, []*resultsv1.VerificationResult{sample()}); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || len(rows[0]) != len(Header) {
		t.Fatalf("unexpected rows: %+v", rows)
	}
	if rows[1][2] != "valid" || rows[1][9] != "did:web:issuer" {
		t.Fatalf("unexpected row: %+v", rows[1])
	}
	if rows[1][13] != "1" || rows[1][14] != "1" {
		t.Fatalf("want one passed and one failed check, got %+v", rows[1])
	}
}

func TestCSVWithoutCredentials(t *testing.T) {
	r := &resultsv1.VerificationResult{Id: "empty",
		Checks: []*policyv1.CheckResult{{Outcome: policyv1.Outcome_OUTCOME_PASS}}}
	var buf bytes.Buffer
	if err := CSV(&buf, []*resultsv1.VerificationResult{r}); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[1][1] != "" || rows[1][13] != "1" {
		t.Fatalf("unexpected rows: %+v", rows)
	}
}

// failWriter fails after a number of successful writes.
type failWriter struct{ left int }

func (f *failWriter) Write(p []byte) (int, error) {
	if f.left <= 0 {
		return 0, errors.New("full")
	}
	f.left--
	return len(p), nil
}

func TestCSVWriteError(t *testing.T) {
	if err := CSV(&failWriter{}, []*resultsv1.VerificationResult{sample()}); err == nil {
		t.Fatal("want an error when the writer fails")
	}
}

func TestJSONLines(t *testing.T) {
	var buf bytes.Buffer
	if err := JSONLines(&buf, []*resultsv1.VerificationResult{sample(), sample()}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"id":"one"`) {
		t.Fatalf("unexpected lines: %v", lines)
	}
	if err := JSONLines(&failWriter{}, []*resultsv1.VerificationResult{sample()}); err == nil {
		t.Fatal("want a write error")
	}
}

func TestVerdictWord(t *testing.T) {
	cases := map[policyv1.EvaluateResponse_Verdict]string{
		policyv1.EvaluateResponse_VERDICT_VALID:         "valid",
		policyv1.EvaluateResponse_VERDICT_INVALID:       "invalid",
		policyv1.EvaluateResponse_VERDICT_INDETERMINATE: "indeterminate",
		policyv1.EvaluateResponse_VERDICT_UNSPECIFIED:   "unknown",
	}
	for in, want := range cases {
		if got := VerdictWord(in); got != want {
			t.Fatalf("%s: want %s, got %s", in, want, got)
		}
	}
}

func TestSortedKeys(t *testing.T) {
	got := SortedKeys(map[string]string{"b": "2", "a": "1"})
	if len(got) != 2 || got[0] != "a" {
		t.Fatalf("unexpected keys: %v", got)
	}
}

func TestFilename(t *testing.T) {
	if got := Filename(resultsv1.ExportRequest_ENCODING_CSV, at); !strings.HasSuffix(got, ".csv") {
		t.Fatalf("want a csv name, got %q", got)
	}
	if got := Filename(resultsv1.ExportRequest_ENCODING_JSON, at); !strings.HasSuffix(got, ".jsonl") {
		t.Fatalf("want a json lines name, got %q", got)
	}
}

func TestCompactJSONError(t *testing.T) {
	if _, err := compactJSON([]byte("{oops")); err == nil {
		t.Fatal("want a parse error")
	}
}
