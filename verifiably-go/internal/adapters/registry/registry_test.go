package registry_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/adapters/registry"
	"github.com/verifiably/verifiably-go/vctypes"
)

// stub is a no-op backend.Adapter that satisfies the interface without
// importing the real or mock adapters (which would create import cycles).
type stub struct{}

func (stub) ListIssuerDpgs(_ context.Context) (map[string]vctypes.DPG, error)  { return nil, nil }
func (stub) ListHolderDpgs(_ context.Context) (map[string]vctypes.DPG, error)  { return nil, nil }
func (stub) ListVerifierDpgs(_ context.Context) (map[string]vctypes.DPG, error) { return nil, nil }
func (stub) ListSchemas(_ context.Context, _ string) ([]vctypes.Schema, error)  { return nil, nil }
func (stub) ListAllSchemas(_ context.Context) ([]vctypes.Schema, error)         { return nil, nil }
func (stub) SaveCustomSchema(_ context.Context, _ vctypes.Schema) error         { return nil }
func (stub) DeleteCustomSchema(_ context.Context, _ string) error               { return nil }
func (stub) PrefillSubjectFields(_ context.Context, _ vctypes.Schema) (map[string]string, error) {
	return nil, nil
}
func (stub) IssueToWallet(_ context.Context, _ backend.IssueRequest) (backend.IssueToWalletResult, error) {
	return backend.IssueToWalletResult{}, nil
}
func (stub) IssueAsPDF(_ context.Context, _ backend.IssueRequest) (backend.IssueAsPDFResult, error) {
	return backend.IssueAsPDFResult{}, nil
}
func (stub) IssueBulk(_ context.Context, _ backend.IssueBulkRequest) (backend.IssueBulkResult, error) {
	return backend.IssueBulkResult{}, nil
}
func (stub) ListWalletCredentials(_ context.Context) ([]vctypes.Credential, error) { return nil, nil }
func (stub) DeleteWalletCredential(_ context.Context, _ string) error               { return nil }
func (stub) ListExampleOffers(_ context.Context) ([]string, error)                  { return nil, nil }
func (stub) ParseOffer(_ context.Context, _ string) (vctypes.Credential, error) {
	return vctypes.Credential{}, nil
}
func (stub) ClaimCredential(_ context.Context, c vctypes.Credential) (vctypes.Credential, error) {
	return c, nil
}
func (stub) PresentCredential(_ context.Context, _ backend.PresentCredentialRequest) (backend.PresentCredentialResult, error) {
	return backend.PresentCredentialResult{}, nil
}
func (stub) BootstrapOffers(_ context.Context) ([]string, error) { return nil, nil }
func (stub) ListOID4VPTemplates(_ context.Context) (map[string]vctypes.OID4VPTemplate, error) {
	return nil, nil
}
func (stub) RequestPresentation(_ context.Context, _ backend.PresentationRequest) (backend.PresentationRequestResult, error) {
	return backend.PresentationRequestResult{}, nil
}
func (stub) FetchPresentationResult(_ context.Context, _, _ string) (backend.VerificationResult, error) {
	return backend.VerificationResult{}, nil
}
func (stub) VerifyDirect(_ context.Context, _ backend.DirectVerifyRequest) (backend.VerificationResult, error) {
	return backend.VerificationResult{}, nil
}

// TestRegistry_NoRaceOnCustomSchemas launches 100 goroutines that concurrently
// call ListAllSchemas, SaveCustomSchema, and DeleteCustomSchema. Run with
// `go test -race ./internal/adapters/registry/...` to verify there are no
// data races in the Registry's custom-schema slice operations.
func TestRegistry_NoRaceOnCustomSchemas(t *testing.T) {
	r := registry.New()
	r.Register("stub", vctypes.DPG{Vendor: "stub"}, []string{"issuer"}, stub{})

	const workers = 100
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			ctx := context.Background()
			switch i % 3 {
			case 0:
				_, _ = r.ListAllSchemas(ctx)
			case 1:
				s := vctypes.Schema{
					ID:     fmt.Sprintf("custom-%d", i),
					Name:   fmt.Sprintf("Schema %d", i),
					Custom: true,
					DPGs:   []string{"stub"},
				}
				_ = r.SaveCustomSchema(ctx, s)
			case 2:
				// DeleteCustomSchema returns "not found" for non-existent IDs — that
				// is expected and harmless; we only check for data races here.
				_ = r.DeleteCustomSchema(ctx, fmt.Sprintf("custom-%d", i))
			}
		}(i)
	}
	wg.Wait()
}
