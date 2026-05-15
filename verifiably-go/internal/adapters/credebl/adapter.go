package credebl

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
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

	// customTemplates maps verifiably-go custom schema IDs (custom-*) to
	// the CREDEBL credential template UUID created for them. Populated by
	// SaveCustomSchema and lazily re-populated on IssueToWallet cache miss.
	customTemplates sync.Map
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

// withAuth executes fn with a CREDEBL bearer token in the context, retrying
// once on HTTP 401 (stale session after a concurrent Studio login invalidated
// the cached token via CREDEBL's deleteInactiveSessions cleanup).
func (a *Adapter) withAuth(ctx context.Context, fn func(context.Context) error) error {
	authCtx, err := a.authCtx(ctx)
	if err != nil {
		return err
	}
	err = fn(authCtx)
	if httpx.IsStatus(err, http.StatusUnauthorized) {
		a.cache.clear()
		authCtx, err = a.authCtx(ctx)
		if err != nil {
			return err
		}
		err = fn(authCtx)
	}
	return err
}

// rewritePublic replaces internal Docker hostnames in s with the public URL
// so OID4VCI offer URIs are wallet-reachable from outside the container network.
// CREDEBL returns credential_offer_uri as a percent-encoded query param value
// (e.g. http%3A%2F%2F172.24.0.1%2Foid4vci%2F...), so we replace both the
// plain and percent-encoded forms.
func (a *Adapter) rewritePublic(s string) string {
	if a.cfg.InternalBaseURL == "" || a.cfg.PublicBaseURL == "" {
		return s
	}
	s = strings.ReplaceAll(s, a.cfg.InternalBaseURL, a.cfg.PublicBaseURL)
	s = strings.ReplaceAll(s,
		url.QueryEscape(a.cfg.InternalBaseURL),
		url.QueryEscape(a.cfg.PublicBaseURL))
	return s
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
