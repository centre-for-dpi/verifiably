package credebl

import (
	"context"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/vctypes"
)

// P2: a multi-credential (delegation pair) request must be surfaced as an error,
// not silently reduced to one credential.
func TestRequestPresentation_RejectsPair(t *testing.T) {
	a := &Adapter{}
	_, err := a.RequestPresentation(context.Background(), backend.PresentationRequest{
		Templates: []vctypes.OID4VPTemplate{{}, {}},
	})
	if err == nil {
		t.Fatal("credebl: expected an error for a multi-credential (pair) request")
	}
}
