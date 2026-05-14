package credebl

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/httpx"
	"github.com/verifiably/verifiably-go/vctypes"
)

// Adapter implements backend.Adapter against CREDEBL.
// Roles: issuer (OID4VCI pre-auth) + verifier (OID4VP DCQL).
// Holder methods return ErrNotApplicable — use Inji Web or walt.id wallet.
type Adapter struct {
	cfg    Config
	Vendor string
	client *httpx.Client
	cache  tokenCache

	// verifierMu guards auto-provisioning so concurrent first calls don't
	// race to register two OID4VP verifiers.
	verifierMu sync.Mutex
	verifierID string
}

// New constructs an Adapter.
func New(cfg Config, vendor string) (*Adapter, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("credebl: baseUrl required")
	}
	return &Adapter{
		cfg:        cfg,
		Vendor:     vendor,
		client:     httpx.New(cfg.BaseURL),
		verifierID: cfg.VerifierID,
	}, nil
}

// rewritePublic replaces internal Docker hostnames in s with the public URL
// so OID4VCI offer URIs are wallet-reachable from outside the container network.
func (a *Adapter) rewritePublic(s string) string {
	if a.cfg.InternalBaseURL == "" || a.cfg.PublicBaseURL == "" {
		return s
	}
	return strings.ReplaceAll(s, a.cfg.InternalBaseURL, a.cfg.PublicBaseURL)
}

// --- Catalog methods: registry holds its own map from backends.json. ---

func (a *Adapter) ListIssuerDpgs(_ context.Context) (map[string]vctypes.DPG, error) {
	return nil, nil
}
func (a *Adapter) ListHolderDpgs(_ context.Context) (map[string]vctypes.DPG, error) {
	return nil, nil
}
func (a *Adapter) ListVerifierDpgs(_ context.Context) (map[string]vctypes.DPG, error) {
	return nil, nil
}

// --- Schema persistence is registry-owned; these are no-ops. ---

func (a *Adapter) SaveCustomSchema(_ context.Context, _ vctypes.Schema) error { return nil }
func (a *Adapter) DeleteCustomSchema(_ context.Context, _ string) error       { return nil }

// --- Holder / wallet: CREDEBL has no wallet component. ---

func (a *Adapter) ListWalletCredentials(_ context.Context) ([]vctypes.Credential, error) {
	return nil, backend.ErrNotApplicable
}
func (a *Adapter) DeleteWalletCredential(_ context.Context, _ string) error {
	return backend.ErrNotApplicable
}
func (a *Adapter) ListExampleOffers(_ context.Context) ([]string, error) { return nil, nil }
func (a *Adapter) ParseOffer(_ context.Context, _ string) (vctypes.Credential, error) {
	return vctypes.Credential{}, backend.ErrNotApplicable
}
func (a *Adapter) ClaimCredential(_ context.Context, c vctypes.Credential) (vctypes.Credential, error) {
	return c, backend.ErrNotApplicable
}
func (a *Adapter) PresentCredential(_ context.Context, _ backend.PresentCredentialRequest) (backend.PresentCredentialResult, error) {
	return backend.PresentCredentialResult{}, backend.ErrNotApplicable
}

// Compile-time interface check.
var _ backend.Adapter = (*Adapter)(nil)
