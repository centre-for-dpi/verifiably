package credebl

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
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
	// templateSF coalesces concurrent resolveTemplateID calls for the same
	// schema.ID so that at most one CREDEBL template creation races per key.
	templateSF sfGroup
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

// withAuth executes fn with a CREDEBL bearer token in the context.
// It retries once on HTTP 401 (stale session after a concurrent Studio login
// invalidated the cached token) and once on HTTP 5xx / network errors (transient
// upstream failures). The 401 retry re-authenticates; the 5xx retry reuses the
// same token. Both retries are logged so operators can trace stale-token races.
func (a *Adapter) withAuth(ctx context.Context, fn func(context.Context) error) error {
	authCtx, err := a.authCtx(ctx)
	if err != nil {
		return err
	}
	err = fn(authCtx)

	switch {
	case httpx.IsStatus(err, http.StatusUnauthorized):
		slog.Warn("credebl: 401 from upstream — clearing token cache and retrying")
		a.cache.clear()
		authCtx, err = a.authCtx(ctx)
		if err != nil {
			return err
		}
		err = fn(authCtx)

	case isTransient(err):
		slog.Warn("credebl: transient error — retrying once", "err", err)
		err = fn(authCtx)
	}

	return err
}

// isTransient returns true for HTTP 5xx responses and TCP-level network errors
// (connection refused, connection reset). It does NOT retry:
//   - 4xx errors (caller bugs — retry won't help)
//   - context cancellation / deadline exceeded (would cause double-issuance)
func isTransient(err error) bool {
	if err == nil {
		return false
	}
	// Never retry on context timeout or cancellation: a timed-out issuance
	// request may have succeeded on the CREDEBL side, so retrying would issue
	// the credential twice.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return false
	}
	for _, code := range []int{
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	} {
		if httpx.IsStatus(err, code) {
			return true
		}
	}
	// TCP-level failures (connection refused, connection reset, ECONNRESET).
	// These are safe to retry because no HTTP request reached CREDEBL.
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	return false
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
