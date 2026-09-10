package registry_test

import (
	"context"
	"testing"

	"github.com/verifiably/verifiably-go/internal/adapters/registry"
)

// A deployment configured with only an issuer and a verifier — a valid
// topology, and the shape a federation member takes when it does not host a
// wallet — must render the holder screens as an empty wallet rather than an
// error. Returning an error here would surface a red toast on a page the
// operator never asked to be a wallet, which is why the return carries
// //nolint:nilerr rather than propagating currentHolder's failure.
func TestListWalletCredentials_NoHolderConfigured(t *testing.T) {
	r := registry.New()

	creds, err := r.ListWalletCredentials(context.Background())
	if err != nil {
		t.Fatalf("no holder DPG is a valid configuration, not an error: %v", err)
	}
	if creds == nil {
		t.Error("must return an empty slice, not nil — the template ranges over it")
	}
	if len(creds) != 0 {
		t.Errorf("creds = %v, want empty", creds)
	}
}
