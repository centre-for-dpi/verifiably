package injicertify

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/httpx"
	"github.com/verifiably/verifiably-go/vctypes"
)

// Adapter implements backend.Adapter for one Inji Certify instance in one mode.
// For the Auth-Code card, construction also enables an in-memory offer store
// keyed by UUID — when the wallet later fetches the offer URI, it's served
// from OfferJSON().
type Adapter struct {
	cfg    Config
	Vendor string
	client *httpx.Client

	mu             sync.Mutex
	authCodeOffers map[string]json.RawMessage
	// pdfBlobs: id → rendered PDF bytes. Populated by pre-auth direct-to-PDF
	// issuance; served by /issuer/issue/pdf/{id}.
	pdfBlobs map[string][]byte
	// pdfKey signs proof-of-possession JWTs for the pre-auth direct-to-PDF
	// flow. Adapter-held because no holder wallet participates. Lazily
	// generated on first use; rotated whenever the container restarts.
	pdfKey *ecdsa.PrivateKey
}

// New constructs an Adapter.
func New(cfg Config, vendor string) (*Adapter, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("injicertify: baseUrl required")
	}
	return &Adapter{
		cfg:            cfg,
		Vendor:         vendor,
		client:         httpx.New(cfg.BaseURL),
		authCodeOffers: map[string]json.RawMessage{},
		pdfBlobs:       map[string][]byte{},
	}, nil
}

// OfferJSON returns the raw credential_offer JSON for a stored Auth-Code offer.
// Verifiably-go's /offers/{slug}/{id} route uses this to serve the offer to
// wallets that dereference by-reference URIs.
func (a *Adapter) OfferJSON(id string) (json.RawMessage, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	raw, ok := a.authCodeOffers[id]
	return raw, ok
}

// Slug returns an ASCII-safe lowercase form of the vendor name. Used in URL
// path segments for the offer-hosting route so wallet fetches don't trip on
// non-ASCII characters in display labels.
func (a *Adapter) Slug() string {
	var b strings.Builder
	for _, r := range a.Vendor {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 32)
		case r == ' ', r == '-', r == '_', r == '·':
			b.WriteRune('-')
		}
	}
	return b.String()
}

// rewritePublic replaces the InternalBaseURL in s with PublicBaseURL so URIs
// returned to the operator are host-reachable. Both raw and percent-encoded
// forms of the internal URL are rewritten so it works whether the host appears
// in a bare URL or is nested inside a `credential_offer_uri=` query parameter.
// If InternalBaseURL is empty, s is returned unchanged.
func (a *Adapter) rewritePublic(s string) string {
	if a.cfg.InternalBaseURL == "" || a.cfg.PublicBaseURL == "" {
		return s
	}
	// Raw form (e.g. in JSON bodies).
	s = strings.ReplaceAll(s, a.cfg.InternalBaseURL, a.cfg.PublicBaseURL)
	// Percent-encoded form used inside OID4VCI offer URIs:
	//   openid-credential-offer://?credential_offer_uri=http%3A%2F%2F…
	encIn := percentEncode(a.cfg.InternalBaseURL)
	encOut := percentEncode(a.cfg.PublicBaseURL)
	s = strings.ReplaceAll(s, encIn, encOut)
	return s
}

// percentEncode applies percent-encoding to the reserved characters that
// show up inside a credential_offer_uri query value (: and /).
func percentEncode(s string) string {
	s = strings.ReplaceAll(s, ":", "%3A")
	s = strings.ReplaceAll(s, "/", "%2F")
	return s
}

func randomID() string {
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// --- Catalog methods: registry holds its own map, so these return empty.

func (a *Adapter) ListIssuerDpgs(_ context.Context) (map[string]vctypes.DPG, error) {
	return nil, nil
}
func (a *Adapter) ListHolderDpgs(_ context.Context) (map[string]vctypes.DPG, error) {
	return nil, nil
}
func (a *Adapter) ListVerifierDpgs(_ context.Context) (map[string]vctypes.DPG, error) {
	return nil, nil
}

// SaveCustomSchema and DeleteCustomSchema are implemented in db.go.

// --- Wallet / verifier methods: Inji Certify is issuer-only. Return
// ErrNotApplicable so the registry routes holder/verifier calls elsewhere.

func (a *Adapter) ListWalletCredentials(_ context.Context) ([]vctypes.Credential, error) {
	return nil, backend.ErrNotApplicable
}
func (a *Adapter) DeleteWalletCredential(_ context.Context, _ string) error {
	return backend.ErrNotApplicable
}
func (a *Adapter) ListExampleOffers(_ context.Context) ([]string, error) {
	return nil, nil
}
func (a *Adapter) ParseOffer(_ context.Context, _ string) (vctypes.Credential, error) {
	return vctypes.Credential{}, backend.ErrNotApplicable
}
func (a *Adapter) ClaimCredential(_ context.Context, c vctypes.Credential) (vctypes.Credential, error) {
	return c, backend.ErrNotApplicable
}
func (a *Adapter) PresentCredential(_ context.Context, _ backend.PresentCredentialRequest) (backend.PresentCredentialResult, error) {
	return backend.PresentCredentialResult{}, backend.ErrNotApplicable
}
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

// Compile-time check.
var _ backend.Adapter = (*Adapter)(nil)
