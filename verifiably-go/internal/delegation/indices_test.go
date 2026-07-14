package delegation

import (
	"context"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
)

// Evaluate must record the delegation credential's index and the subject
// identity's index so the verifier UI can attribute each check to the right card.
func TestEvaluate_SetsCredentialIndices(t *testing.T) {
	// identity at index 0, delegation at index 1.
	creds := []backend.NormalizedCredential{identityCred(), delegationCredJSONLD()}
	got := Evaluate(context.Background(), creds, parentHolder(), baseOpts())
	if !got.Evaluated {
		t.Fatalf("expected Evaluated, got %+v", got)
	}
	if got.DelegationIndex != 1 {
		t.Errorf("DelegationIndex = %d, want 1", got.DelegationIndex)
	}
	if got.SubjectIndex != 0 {
		t.Errorf("SubjectIndex = %d, want 0", got.SubjectIndex)
	}
}

// A non-delegation presentation leaves the indices at -1.
func TestEvaluate_NoDelegationIndicesMinusOne(t *testing.T) {
	got := Evaluate(context.Background(), []backend.NormalizedCredential{identityCred()}, nil, baseOpts())
	if got.Evaluated {
		t.Fatalf("expected not a delegation presentation, got %+v", got)
	}
	if got.DelegationIndex != -1 || got.SubjectIndex != -1 {
		t.Errorf("indices = %d/%d, want -1/-1", got.DelegationIndex, got.SubjectIndex)
	}
}
