// Package injiweb wires the Inji Web Wallet v0.16.0 into verifiably-go as a
// holder DPG. Inji Web is a self-contained browser SPA backed by Mimoto
// (v0.21.0) and eSignet (v1.5.1); it does not expose a server-to-server API
// for third-party applications to read credentials out of a user's account.
//
// Realistic integration strategy: verifiably-go surfaces Inji Web as a
// redirect DPG. Selecting it routes through the UI's `redirect_notice`
// template, which links the operator to the Inji Web app in a new tab.
// All holder operations return backend.ErrNotLinked with a message explaining
// that credentials live inside Inji Web and must be presented from there.
//
// When MOSIP publishes a stable read-back API or SIOP-style consent flow,
// this adapter can be extended to implement it in place; the catalog-level
// capability descriptors are already shaped for that future.
package injiweb

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/vctypes"
)

// Config is the per-backend config blob.
type Config struct {
	// UIURL is the public URL of the Inji Web SPA, e.g. http://localhost:3004.
	UIURL string `json:"uiUrl"`
	// MimotoURL is the BFF URL, e.g. http://localhost:8099. Stored for future
	// use when a read-back API becomes available.
	MimotoURL string `json:"mimotoUrl"`
}

func UnmarshalConfig(raw json.RawMessage) (Config, error) {
	var c Config
	if len(raw) == 0 {
		return c, fmt.Errorf("injiweb: empty config")
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, err
	}
	if c.UIURL == "" {
		return c, fmt.Errorf("injiweb: uiUrl is required")
	}
	return c, nil
}

// Adapter implements backend.Adapter with a redirect-only strategy. Operations
// that require reading or mutating the holder's Inji Web credentials return
// backend.ErrNotLinked so the UI surfaces a clear "credentials live inside
// Inji Web" message instead of silently failing.
type Adapter struct {
	cfg    Config
	Vendor string
}

func New(cfg Config, vendor string) (*Adapter, error) {
	return &Adapter{cfg: cfg, Vendor: vendor}, nil
}

// UIURL is the address the UI opens when the holder picks this DPG.
func (a *Adapter) UIURL() string { return a.cfg.UIURL }

// Compile-time check.
var _ backend.Adapter = (*Adapter)(nil)

// --- Catalog (registry owns catalog maps) ---
func (a *Adapter) ListIssuerDpgs(_ context.Context) (map[string]vctypes.DPG, error) {
	return nil, nil
}
func (a *Adapter) ListHolderDpgs(_ context.Context) (map[string]vctypes.DPG, error) {
	return nil, nil
}
func (a *Adapter) ListVerifierDpgs(_ context.Context) (map[string]vctypes.DPG, error) {
	return nil, nil
}

// --- Schema / issuance / verification all N/A ---
func (a *Adapter) ListSchemas(_ context.Context, _ string) ([]vctypes.Schema, error) {
	return nil, backend.ErrNotApplicable
}
func (a *Adapter) ListAllSchemas(_ context.Context) ([]vctypes.Schema, error) { return nil, nil }
func (a *Adapter) GetIssuerMetadata(_ context.Context) (backend.IssuerMetadata, error) {
	return backend.IssuerMetadata{}, backend.ErrNotSupported
}
func (a *Adapter) SaveCustomSchema(_ context.Context, _ vctypes.Schema) error { return nil }
func (a *Adapter) DeleteCustomSchema(_ context.Context, _ string) error       { return nil }
func (a *Adapter) PrefillSubjectFields(_ context.Context, _ vctypes.Schema) (map[string]string, error) {
	return map[string]string{}, nil
}
func (a *Adapter) IssueToWallet(_ context.Context, _ backend.IssueRequest) (backend.IssueToWalletResult, error) {
	return backend.IssueToWalletResult{}, backend.ErrNotApplicable
}
func (a *Adapter) IssueAsPDF(_ context.Context, _ backend.IssueRequest) (backend.IssueAsPDFResult, error) {
	return backend.IssueAsPDFResult{}, backend.ErrNotApplicable
}
func (a *Adapter) IssueBulk(_ context.Context, _ backend.IssueBulkRequest) (backend.IssueBulkResult, error) {
	return backend.IssueBulkResult{}, backend.ErrNotApplicable
}
func (a *Adapter) BootstrapOffers(_ context.Context) ([]string, error) { return nil, nil }

// --- Holder: all return ErrNotLinked so the UI surfaces the explainer ---
func (a *Adapter) ListWalletCredentials(_ context.Context) ([]vctypes.Credential, error) {
	return nil, backend.ErrNotLinked
}
func (a *Adapter) DeleteWalletCredential(_ context.Context, _ string) error {
	return backend.ErrNotLinked
}
func (a *Adapter) ListExampleOffers(_ context.Context) ([]string, error) {
	return nil, nil
}
func (a *Adapter) ParseOffer(_ context.Context, _ string) (vctypes.Credential, error) {
	return vctypes.Credential{}, backend.ErrNotLinked
}
func (a *Adapter) ClaimCredential(_ context.Context, c vctypes.Credential) (vctypes.Credential, error) {
	return c, backend.ErrNotLinked
}
func (a *Adapter) PresentCredential(_ context.Context, _ backend.PresentCredentialRequest) (backend.PresentCredentialResult, error) {
	return backend.PresentCredentialResult{}, backend.ErrNotLinked
}

// --- Verifier N/A ---
func (a *Adapter) ListOID4VPTemplates(_ context.Context) (map[string]vctypes.OID4VPTemplate, error) {
	return nil, nil
}
func (a *Adapter) RequestPresentation(_ context.Context, _ backend.PresentationRequest) (backend.PresentationRequestResult, error) {
	return backend.PresentationRequestResult{}, backend.ErrNotApplicable
}
func (a *Adapter) FetchPresentationResult(_ context.Context, _, _ string) (backend.VerificationResult, error) {
	return backend.VerificationResult{}, backend.ErrNotApplicable
}
func (a *Adapter) VerifyDirect(_ context.Context, _ backend.DirectVerifyRequest) (backend.VerificationResult, error) {
	return backend.VerificationResult{}, backend.ErrNotApplicable
}
