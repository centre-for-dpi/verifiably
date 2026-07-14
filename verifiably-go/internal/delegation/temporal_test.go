package delegation

import (
	"context"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
)

// The base pair (identityCred + delegationCredJSONLD + parentHolder + baseOpts)
// authorizes; these tests add a stale validity window to one credential and
// assert the temporal gate denies — the B7 security fix (expired/not-yet-valid
// credentials must not resolve as authorized), evaluated at fixedNow (2026-06-25).

func TestEvaluate_ExpiredCredentialDenied(t *testing.T) {
	id := identityCred()
	id.Raw["validUntil"] = "2026-06-24T00:00:00Z" // the day before fixedNow
	got := Evaluate(context.Background(),
		[]backend.NormalizedCredential{id, delegationCredJSONLD()}, parentHolder(), baseOpts())
	if got.Authorized {
		t.Fatalf("expected denied for an expired identity credential, got Authorized=true (%+v)", got)
	}
	if !strings.Contains(got.Reason, "expired") {
		t.Fatalf("expected an 'expired' reason, got %q", got.Reason)
	}
	if got.Capability {
		t.Fatalf("Capability must not pass when a presented credential is expired")
	}
}

func TestEvaluate_NotYetValidCredentialDenied(t *testing.T) {
	deleg := delegationCredJSONLD()
	deleg.Raw["validFrom"] = "2026-07-01T00:00:00Z" // after fixedNow
	got := Evaluate(context.Background(),
		[]backend.NormalizedCredential{identityCred(), deleg}, parentHolder(), baseOpts())
	if got.Authorized {
		t.Fatalf("expected denied for a not-yet-valid delegation credential, got Authorized=true")
	}
	if !strings.Contains(got.Reason, "not yet valid") {
		t.Fatalf("expected a 'not yet valid' reason, got %q", got.Reason)
	}
}

func TestEvaluate_WithinValidityStillAuthorized(t *testing.T) {
	id := identityCred()
	id.Raw["validFrom"] = "2020-01-01T00:00:00Z"
	id.Raw["validUntil"] = "2030-01-01T00:00:00Z" // window includes fixedNow
	got := Evaluate(context.Background(),
		[]backend.NormalizedCredential{id, delegationCredJSONLD()}, parentHolder(), baseOpts())
	if !got.Authorized {
		t.Fatalf("expected authorized within a valid window, got denied: %q", got.Reason)
	}
}
