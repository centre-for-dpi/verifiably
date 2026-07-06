package waltid

import (
	"encoding/json"
	"testing"
)

// B1: walt.id's SD-JWT success results carry an informational `message`; it must
// NOT be reported as a failed policy (which rendered a spurious "Failed policies"
// block). Only explicit failure signals fail a policy.
func TestExtractPolicyOutcomes_MessageInformational(t *testing.T) {
	ok := json.RawMessage(`[{"policy":"signature","is_success":true,"message":"Verified 3 disclosures"}]`)
	out := extractPolicyOutcomes(ok)
	if len(out) != 1 || out[0].Name != "signature" || !out[0].Passed {
		t.Fatalf("informational message must stay passed: %+v", out)
	}

	// Explicit failure via is_success:false + error → failed, with reason.
	bad := json.RawMessage(`[{"policy":"expired","is_success":false,"error":"credential expired"}]`)
	out = extractPolicyOutcomes(bad)
	if len(out) != 1 || out[0].Passed || out[0].Reason != "credential expired" {
		t.Fatalf("explicit failure must be reported with reason: %+v", out)
	}

	// success:false with only a message → failed; message becomes the reason.
	bad2 := json.RawMessage(`[{"policy":"not-before","success":false,"message":"not yet valid"}]`)
	out = extractPolicyOutcomes(bad2)
	if len(out) != 1 || out[0].Passed || out[0].Reason != "not yet valid" {
		t.Fatalf("success:false + message reason: %+v", out)
	}

	// exception object → failed with its message.
	bad3 := json.RawMessage(`[{"policy":"schema","exception":{"message":"boom"}}]`)
	out = extractPolicyOutcomes(bad3)
	if len(out) != 1 || out[0].Passed || out[0].Reason != "boom" {
		t.Fatalf("exception -> failed with message: %+v", out)
	}

	// Empty / invalid input → nil.
	if extractPolicyOutcomes(nil) != nil {
		t.Fatal("empty raw must return nil")
	}
	if extractPolicyOutcomes(json.RawMessage(`not json`)) != nil {
		t.Fatal("invalid JSON must return nil")
	}
	// Maps/arrays without any policy name → no outcomes (recurses, finds none).
	if extractPolicyOutcomes(json.RawMessage(`[{"foo":"bar"},{"nested":{"x":1}}]`)) != nil {
		t.Fatal("no policy names must return nil")
	}
	// A named policy nested deeper is still found (recursion).
	out = extractPolicyOutcomes(json.RawMessage(`{"results":[{"policy":"signature","is_success":true}]}`))
	if len(out) != 1 || !out[0].Passed {
		t.Fatalf("nested policy must be found and passed: %+v", out)
	}
}
