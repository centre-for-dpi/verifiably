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
func (stub) GetIssuerMetadata(_ context.Context) (backend.IssuerMetadata, error) {
	return backend.IssuerMetadata{}, backend.ErrNotSupported
}
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

// metaStub is a stub adapter that returns a fixed IssuerMetadata, used to
// verify that GetIssuerMetadata correctly merges vendor configs.
type metaStub struct {
	stub
	meta backend.IssuerMetadata
}

func (m metaStub) GetIssuerMetadata(_ context.Context) (backend.IssuerMetadata, error) {
	return m.meta, nil
}

// TestRegistry_GetIssuerMetadata_OnlyCustomSchemas pins several rules at once:
//  1. Authenticated schemas (keycloak| owner) appear in discovery.
//  2. Anonymous session schemas (session- owner) are excluded — they are
//     test/demo artifacts and must not pollute the public catalog.
//  3. Schemas with an empty OwnerKey (admin/CLI) are included.
//  4. Vendor adapter entries (HOCON templates) never appear regardless.
func TestRegistry_GetIssuerMetadata_OnlyCustomSchemas(t *testing.T) {
	ctx := context.Background()
	r := registry.New()

	r.Register("vendor", vctypes.DPG{Vendor: "vendor"}, []string{"issuer"}, metaStub{
		meta: backend.IssuerMetadata{
			CredentialsSupported: []backend.CredentialConfig{
				{ID: "VendorOnlyCred", Format: "jwt_vc_json", Display: "Vendor default — must be excluded"},
			},
		},
	})

	keycloakSchema := vctypes.Schema{ID: "ProdCred", Name: "Prod", Std: "sd_jwt_vc", Custom: true, OwnerKey: "keycloak|abc123", DPGs: []string{"vendor"}}
	sessionSchema := vctypes.Schema{ID: "TestCred", Name: "Test", Std: "sd_jwt_vc", Custom: true, OwnerKey: "session-deadbeef", DPGs: []string{"vendor"}}
	adminSchema := vctypes.Schema{ID: "AdminCred", Name: "Admin", Std: "sd_jwt_vc", Custom: true, OwnerKey: "", DPGs: []string{"vendor"}}

	for _, s := range []vctypes.Schema{keycloakSchema, sessionSchema, adminSchema} {
		if err := r.SaveCustomSchema(ctx, s); err != nil {
			t.Fatalf("SaveCustomSchema %s: %v", s.ID, err)
		}
	}

	meta, err := r.GetIssuerMetadata(ctx)
	if err != nil {
		t.Fatalf("GetIssuerMetadata: %v", err)
	}

	byID := map[string]backend.CredentialConfig{}
	for _, c := range meta.CredentialsSupported {
		byID[c.ID] = c
	}

	if _, ok := byID["ProdCred"]; !ok {
		t.Error("keycloak-owned schema must appear in discovery")
	}
	if _, ok := byID["AdminCred"]; !ok {
		t.Error("admin/CLI schema (empty OwnerKey) must appear in discovery")
	}
	if _, ok := byID["TestCred"]; ok {
		t.Error("session-owned schema must NOT appear in discovery")
	}
	if _, ok := byID["VendorOnlyCred"]; ok {
		t.Error("vendor adapter credential must NOT appear in discovery")
	}
	if got := len(meta.CredentialsSupported); got != 2 {
		t.Errorf("CredentialsSupported len = %d, want 2 (keycloak + admin schemas only)", got)
	}
}
