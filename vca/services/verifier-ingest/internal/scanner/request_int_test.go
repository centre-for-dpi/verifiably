// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
)

// TestRequestWords names every verdict, outcome, state, and step.
func TestRequestWords(t *testing.T) {
	for v, want := range map[policyv1.EvaluateResponse_Verdict]string{
		policyv1.EvaluateResponse_VERDICT_VALID: "ok", policyv1.EvaluateResponse_VERDICT_INVALID: "bad", policyv1.EvaluateResponse_VERDICT_INDETERMINATE: "warn",
	} {
		if got := verdictBadge(v).Status; got != want {
			t.Errorf("%v: %s", v, got)
		}
	}
	for o, want := range map[policyv1.Outcome]string{
		policyv1.Outcome_OUTCOME_PASS: "Passed", policyv1.Outcome_OUTCOME_FAIL: "Failed",
		policyv1.Outcome_OUTCOME_SKIP: "Skipped", policyv1.Outcome_OUTCOME_ERROR: "Could not run",
	} {
		if got := outcomeWord(o); got != want {
			t.Errorf("%v: %s", o, got)
		}
	}
	if stackWord(&backendv1.GetResultResponse_DpgCheck{}) != "Failed" || stackWord(&backendv1.GetResultResponse_DpgCheck{Passed: true}) != "Passed" {
		t.Error("stack word")
	}
	for s, want := range map[*ingestv1.TransactionSummary]string{
		{ResultId: "r"}: "Checked",
		{State: ingestv1.GetTransactionResponse_STATE_RECEIVED}: "Received",
		{State: ingestv1.GetTransactionResponse_STATE_REFUSED}:  "Refused",
		{State: ingestv1.GetTransactionResponse_STATE_EXPIRED}:  "Expired",
		{State: ingestv1.GetTransactionResponse_STATE_PENDING}:  "Waiting",
	} {
		if got := stateWord(s).Text; got != want {
			t.Errorf("%v: %s", s, got)
		}
	}
	received := &ingestv1.GetTransactionResponse{State: ingestv1.GetTransactionResponse_STATE_RECEIVED,
		Presentation: &ingestv1.RawPresentation{ReceivedAt: timestamppb.New(timestamppb.Now().AsTime())}}
	if stepOf(received) != 2 || footerOf(received) == "" || footerOf(&ingestv1.GetTransactionResponse{State: ingestv1.GetTransactionResponse_STATE_REFUSED}) != "" {
		t.Error("step or footer of a received answer")
	}
	if _, ok := qrImage(""); ok {
		t.Error("an empty payload has no QR code")
	}
	if _, err := RequestPDF("x", string(make([]byte, 5000)), timestamppb.Now().AsTime()); err == nil {
		t.Error("a payload too long for a QR code wants an error")
	}
}
