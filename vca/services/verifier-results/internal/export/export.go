// SPDX-License-Identifier: Apache-2.0

// Package export writes results as CSV or as JSON lines
// (ADR-025 decision 4). Reporting then needs no database access.
package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
)

// Header is the first row of a CSV export.
var Header = []string{
	"result_id", "evaluated_at", "verdict", "carrier", "template_id", "template_version",
	"policy_set_id", "policy_set_version", "credential_type", "issuer", "issuer_name",
	"trust", "role", "checks_passed", "checks_failed",
}

// CSV writes one header row and one row per credential (RFC 4180). A
// result without credentials gets one row with empty credential fields.
func CSV(w io.Writer, results []*resultsv1.VerificationResult) error {
	out := csv.NewWriter(w)
	// csv.Writer buffers and keeps the first error, so one check at the
	// end reports every write problem.
	ignored2 := out.Write(Header)
	_ = ignored2
	for _, r := range results {
		for _, row := range credentialRows(r) {
			ignored := out.Write(row)
			_ = ignored
		}
	}
	out.Flush()
	if err := out.Error(); err != nil {
		return fmt.Errorf("export: %w", err)
	}
	return nil
}

// credentialRows returns the CSV rows of one result.
func credentialRows(r *resultsv1.VerificationResult) [][]string {
	base := []string{
		r.GetId(), stamp(r), VerdictWord(r.GetVerdict()), r.GetCarrier(),
		r.GetTemplateId(), fmt.Sprint(r.GetTemplateVersion()),
		r.GetPolicySetId(), fmt.Sprint(r.GetPolicySetVersion()),
	}
	if len(r.GetCredentials()) == 0 {
		passed, failed := count(r.GetChecks())
		return [][]string{append(base, "", "", "", "", "", passed, failed)}
	}
	var rows [][]string
	for _, c := range r.GetCredentials() {
		passed, failed := count(c.GetChecks())
		rows = append(rows, append(append([]string{}, base...),
			c.GetType(), c.GetIssuer(), c.GetIssuerName(), c.GetTrust(), c.GetRole(), passed, failed))
	}
	return rows
}

// stamp returns the evaluation time in RFC 3339, or an empty string.
func stamp(r *resultsv1.VerificationResult) string {
	if r.GetEvaluatedAt() == nil {
		return ""
	}
	return r.GetEvaluatedAt().AsTime().UTC().Format(time.RFC3339)
}

// count returns the number of passed and failed checks as text.
func count(checks []*policyv1.CheckResult) (string, string) {
	passed, failed := 0, 0
	for _, c := range checks {
		switch c.GetOutcome() {
		case policyv1.Outcome_OUTCOME_PASS:
			passed++
		case policyv1.Outcome_OUTCOME_FAIL:
			failed++
		case policyv1.Outcome_OUTCOME_UNSPECIFIED, policyv1.Outcome_OUTCOME_SKIP, policyv1.Outcome_OUTCOME_ERROR:
		}
	}
	return fmt.Sprint(passed), fmt.Sprint(failed)
}

// JSONLines writes one JSON object per result.
func JSONLines(w io.Writer, results []*resultsv1.VerificationResult) error {
	marshal := protojson.MarshalOptions{}
	for _, r := range results {
		raw, err := marshal.Marshal(r)
		if err != nil {
			return fmt.Errorf("export: %w", err)
		}
		// protojson adds unstable spacing, so compact the line.
		compact, err := compactJSON(raw)
		if err != nil {
			return fmt.Errorf("export: %w", err)
		}
		if _, err := w.Write(append(compact, '\n')); err != nil {
			return fmt.Errorf("export: %w", err)
		}
	}
	return nil
}

// compactJSON removes the spacing of a JSON document.
func compactJSON(raw []byte) ([]byte, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// VerdictWord returns the plain word of a verdict.
func VerdictWord(v policyv1.EvaluateResponse_Verdict) string {
	switch v {
	case policyv1.EvaluateResponse_VERDICT_VALID:
		return "valid"
	case policyv1.EvaluateResponse_VERDICT_INVALID:
		return "invalid"
	case policyv1.EvaluateResponse_VERDICT_INDETERMINATE:
		return "indeterminate"
	case policyv1.EvaluateResponse_VERDICT_UNSPECIFIED:
	}
	return "unknown"
}

// SortedKeys returns the keys of a map in order. The card and the
// export show display fields in a stable order.
func SortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Filename returns a download name for an export.
func Filename(encoding resultsv1.ExportRequest_Encoding, at time.Time) string {
	ext := "csv"
	if encoding == resultsv1.ExportRequest_ENCODING_JSON {
		ext = "jsonl"
	}
	return strings.Join([]string{"verifications", at.UTC().Format("20060102-150405")}, "-") + "." + ext
}
