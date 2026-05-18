package waltid

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/httpx"
	"github.com/verifiably/verifiably-go/vctypes"
)

// jsonReader marshals v to JSON and wraps it in an io.Reader — convenience for
// the DoRaw path where we still want to send JSON in the body.
func jsonReader(v any) io.Reader {
	b, _ := json.Marshal(v)
	return bytes.NewReader(b)
}

// Adapter holds the three role clients and lazily-bootstrapped session state.
type Adapter struct {
	cfg Config
	// Vendor is the key this adapter is registered under (e.g. "walt.id").
	// Used when PrefillSubjectFields / ListSchemas need to compare against
	// Schema.DPGs. Provided by main.go at construction.
	Vendor string

	issuer   *httpx.Client
	verifier *httpx.Client
	wallet   *httpx.Client

	mu        sync.Mutex
	issuerKey json.RawMessage // JWK wrapper from /onboard/issuer
	issuerDID string
	// sessions partitions walt.id wallet state by the per-user identity
	// key the handler injects via backend.WithHolderIdentity. Each caller
	// gets their own walt.id account + walletId so one user's credentials
	// never leak into another's inbox. Empty key hits the legacy shared
	// demo account — covers the pre-OIDC single-user demo mode.
	sessions map[string]*walletSession
	// registeredConfigIDs maps a custom schema's ID to the configurationId
	// SaveCustomSchema appended to walt.id's HOCON catalog. IssueToWallet
	// reads this to skip the borrow trick when a real catalog entry exists
	// — the issued VC then carries the user's chosen type name instead of
	// the borrowed credential's name.
	registeredConfigIDs map[string]string
}

// walletSession is the bootstrapped wallet-api state: a session JWT + a
// walletId to issue API calls against. Populated on first wallet call.
type walletSession struct {
	Token    string
	WalletID string
}

// IssuerSigningKey returns the cached walt.id issuer JWK (raw bytes from
// /onboard/issuer) and its DID. Lazily onboards on first call, mirroring
// what IssueToWallet does, so a status-list handler can demand-fetch the
// signing key without coupling to the issuance request path. The returned
// JWK envelope is what statuslist.ParseWaltidIssuerKey expects.
//
// Returns []byte (not json.RawMessage) so the result type matches the
// signingKeyAdapter interface declared in internal/handlers verbatim.
// Go's interface satisfaction is invariant on named types: a method
// returning json.RawMessage does NOT satisfy an interface that declares
// []byte even though they share the same underlying type, so a Registry
// type-asserting on the interface would silently miss this adapter.
func (a *Adapter) IssuerSigningKey(ctx context.Context) ([]byte, string, error) {
	if err := a.ensureIssuerKey(ctx); err != nil {
		return nil, "", err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// Defensive copy — callers shouldn't be able to mutate our cache.
	out := make([]byte, len(a.issuerKey))
	copy(out, a.issuerKey)
	return out, a.issuerDID, nil
}

// New constructs an Adapter from Config. Validates required URLs but defers
// onboarding + wallet login until the first call that needs them — so startup
// stays fast and a missing/unreachable backend surfaces as a per-request error
// rather than crashing the whole app.
//
// Only verifierBaseUrl is strictly required. When issuerBaseUrl or walletBaseUrl
// are absent the corresponding role clients are nil — methods that use them will
// return an error at call time. This allows hub nodes to register a verifier-only
// adapter for each federation member using just the member's verifierBaseUrl.
func New(cfg Config, vendor string) (*Adapter, error) {
	if cfg.VerifierBaseURL == "" {
		return nil, fmt.Errorf("waltid: verifierBaseUrl is required")
	}
	a := &Adapter{
		cfg:       cfg,
		Vendor:    vendor,
		verifier:  httpx.New(cfg.VerifierBaseURL),
		issuerKey: cfg.IssuerKey,
		issuerDID: cfg.IssuerDID,
		sessions:  map[string]*walletSession{},
	}
	if cfg.IssuerBaseURL != "" {
		a.issuer = httpx.New(cfg.IssuerBaseURL)
	}
	if cfg.WalletBaseURL != "" {
		a.wallet = httpx.New(cfg.WalletBaseURL)
	}
	return a, nil
}

// Compile-time check: Adapter satisfies backend.Adapter.
var _ backend.Adapter = (*Adapter)(nil)

// The catalog methods below exist only to satisfy backend.Adapter. The
// registry's own catalog takes precedence — it builds the DPG map from
// backends.json and never delegates to concrete adapters for ListXDpgs.
// Returning empty maps here is both honest and harmless.

func (a *Adapter) ListIssuerDpgs(_ context.Context) (map[string]vctypes.DPG, error) {
	return nil, nil
}

func (a *Adapter) ListHolderDpgs(_ context.Context) (map[string]vctypes.DPG, error) {
	return nil, nil
}

func (a *Adapter) ListVerifierDpgs(_ context.Context) (map[string]vctypes.DPG, error) {
	return nil, nil
}
