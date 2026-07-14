// MockAdapter implements backend.Adapter by reading from the demo data in
// data.go. It's the default adapter used by cmd/server/main.go; swap it out
// for your own implementation to go live.
package mock

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/vctypes"
)

// MockAdapter is the in-memory implementation used by the demo.
// Safe for concurrent use.
type MockAdapter struct {
	mu            sync.Mutex
	customSchemas []vctypes.Schema

	// Static data snapshotted once at construction; handlers request them often.
	issuerDpgs    map[string]vctypes.DPG
	holderDpgs    map[string]vctypes.DPG
	verifierDpgs  map[string]vctypes.DPG
	schemas       []vctypes.Schema
	subjectVals   map[string]string
	issuerIds     map[string]vctypes.IssuerIdentity
	offerHosts    map[string]string
	verifierHosts map[string]string
	verIssuers    map[string]string
	oid4vpTpl     map[string]vctypes.OID4VPTemplate
	exampleOffers []ExampleOffer
}

// NewAdapter constructs a fresh in-memory adapter.
func NewAdapter() *MockAdapter {
	return &MockAdapter{
		issuerDpgs:    IssuerDpgs(),
		holderDpgs:    HolderDpgs(),
		verifierDpgs:  VerifierDpgs(),
		schemas:       Schemas(),
		subjectVals:   SubjectValues(),
		issuerIds:     IssuerIdentities(),
		offerHosts:    OfferURIHosts(),
		verifierHosts: VerifierHosts(),
		verIssuers:    VerificationIssuers(),
		oid4vpTpl:     OID4VPTemplates(),
		exampleOffers: ExampleOffers(),
	}
}

// Compile-time check: MockAdapter satisfies backend.Adapter.
var _ backend.Adapter = (*MockAdapter)(nil)

func (a *MockAdapter) ListIssuerDpgs(_ context.Context) (map[string]vctypes.DPG, error) {
	return a.issuerDpgs, nil
}
func (a *MockAdapter) ListHolderDpgs(_ context.Context) (map[string]vctypes.DPG, error) {
	return a.holderDpgs, nil
}
func (a *MockAdapter) ListVerifierDpgs(_ context.Context) (map[string]vctypes.DPG, error) {
	return a.verifierDpgs, nil
}

func (a *MockAdapter) ListSchemas(_ context.Context, issuerDpg string) ([]vctypes.Schema, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := []vctypes.Schema{}
	for _, s := range a.schemas {
		if contains(s.DPGs, issuerDpg) {
			out = append(out, s)
		}
	}
	for _, s := range a.customSchemas {
		if contains(s.DPGs, issuerDpg) {
			out = append(out, s)
		}
	}
	return out, nil
}

// GetIssuerMetadata assembles credential configurations from the mock's
// schema catalog so the discovery endpoint has demo data to serve.
func (a *MockAdapter) GetIssuerMetadata(ctx context.Context) (backend.IssuerMetadata, error) {
	schemas, err := a.ListAllSchemas(ctx)
	if err != nil {
		return backend.IssuerMetadata{}, err
	}
	return backend.IssuerMetadata{CredentialsSupported: backend.CredentialConfigsFromSchemas(schemas)}, nil
}

func (a *MockAdapter) ListAllSchemas(_ context.Context) ([]vctypes.Schema, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]vctypes.Schema, 0, len(a.schemas)+len(a.customSchemas))
	out = append(out, a.schemas...)
	out = append(out, a.customSchemas...)
	return out, nil
}

func (a *MockAdapter) SaveCustomSchema(_ context.Context, schema vctypes.Schema) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	schema.Custom = true
	a.customSchemas = append(a.customSchemas, schema)
	return nil
}

func (a *MockAdapter) DeleteCustomSchema(_ context.Context, id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i, s := range a.customSchemas {
		if s.ID == id {
			a.customSchemas = append(a.customSchemas[:i], a.customSchemas[i+1:]...)
			return nil
		}
	}
	return errors.New("custom schema not found")
}

func (a *MockAdapter) PrefillSubjectFields(_ context.Context, schema vctypes.Schema) (map[string]string, error) {
	out := map[string]string{}
	for _, f := range schemaFieldsOf(schema) {
		out[f] = a.subjectVals[f]
	}
	return out, nil
}

func (a *MockAdapter) IssueToWallet(_ context.Context, req backend.IssueRequest) (backend.IssueToWalletResult, error) {
	host, ok := a.offerHosts[req.IssuerDpg]
	if !ok {
		host = "issuer.example"
	}
	id := randomHex(6)
	return backend.IssueToWalletResult{
		OfferURI:  fmt.Sprintf("openid-credential-offer://?credential_offer_uri=https://%s/offer/%s", host, id),
		OfferID:   id,
		Flow:      req.Flow,
		ExpiresIn: 10 * time.Minute,
	}, nil
}

func (a *MockAdapter) IssueAsPDF(_ context.Context, req backend.IssueRequest) (backend.IssueAsPDFResult, error) {
	id, ok := a.issuerIds[req.IssuerDpg]
	if !ok {
		id = vctypes.IssuerIdentity{Name: "Unknown Issuer", DID: "did:example:unknown"}
	}
	size, _ := rand.Int(rand.Reader, big.NewInt(40))
	return backend.IssueAsPDFResult{
		IssuerName:    id.Name,
		IssuerDID:     id.DID,
		PayloadSizeKB: int(size.Int64()) + 15,
		Fields:        req.SubjectData,
	}, nil
}

func (a *MockAdapter) IssueBulk(_ context.Context, req backend.IssueBulkRequest) (backend.IssueBulkResult, error) {
	// Mock reports per-row outcomes deterministically: rows with an empty or
	// missing "holder" field are rejected, everything else accepted.
	var (
		accepted int
		rejected int
		errs     []backend.BulkError
	)
	for i, row := range req.Rows {
		if row["holder"] == "" {
			rejected++
			errs = append(errs, backend.BulkError{Row: i + 1, Reason: "missing holder"})
			continue
		}
		accepted++
	}
	return backend.IssueBulkResult{Accepted: accepted, Rejected: rejected, Errors: errs}, nil
}

func (a *MockAdapter) ListWalletCredentials(_ context.Context) ([]vctypes.Credential, error) {
	return SeedWalletCreds(), nil
}

func (a *MockAdapter) DeleteWalletCredential(_ context.Context, _ string) error {
	// Mock adapter has no persistent state — treat delete as a no-op
	// so UI flows that exercise it don't fail.
	return nil
}

func (a *MockAdapter) ListExampleOffers(_ context.Context) ([]string, error) {
	uris := make([]string, 0, len(a.exampleOffers))
	for _, ex := range a.exampleOffers {
		uris = append(uris, ex.URI)
	}
	return uris, nil
}

func (a *MockAdapter) ListOID4VPTemplates(_ context.Context) (map[string]vctypes.OID4VPTemplate, error) {
	return a.oid4vpTpl, nil
}

func (a *MockAdapter) ParseOffer(_ context.Context, offerURI string) (vctypes.Credential, error) {
	for _, ex := range a.exampleOffers {
		if len(ex.URI) > 40 && len(offerURI) > 40 && offerURI[:40] == ex.URI[:40] {
			c := ex.Offer
			c.ID = "pending-" + randomHex(4)
			c.Status = "pending"
			return c, nil
		}
	}
	return vctypes.Credential{
		ID:     "pending-" + randomHex(4),
		Title:  "Unknown Credential",
		Issuer: "Unverified Issuer",
		Type:   "w3c_vcdm_2",
		Status: "pending",
		Fields: map[string]string{"holder": "You", "note": "Parsed from custom offer URI"},
	}, nil
}

func (a *MockAdapter) ClaimCredential(_ context.Context, cred vctypes.Credential) (vctypes.Credential, error) {
	cred.Status = "accepted"
	return cred, nil
}

func (a *MockAdapter) PresentCredential(_ context.Context, req backend.PresentCredentialRequest) (backend.PresentCredentialResult, error) {
	return backend.PresentCredentialResult{
		Success:       true,
		Method:        "OID4VP · mock",
		SharedClaims:  req.DisclosedClaim,
		VerifierState: "mock-state-" + randomHex(4),
	}, nil
}

func (a *MockAdapter) BootstrapOffers(_ context.Context) ([]string, error) {
	uris := make([]string, 0, len(a.exampleOffers))
	for _, ex := range a.exampleOffers {
		uris = append(uris, ex.URI)
	}
	return uris, nil
}

func (a *MockAdapter) RequestPresentation(_ context.Context, req backend.PresentationRequest) (backend.PresentationRequestResult, error) {
	tpl, ok := a.oid4vpTpl[req.TemplateKey]
	if !ok {
		return backend.PresentationRequestResult{}, errors.New("unknown template key")
	}
	host, ok := a.verifierHosts[req.VerifierDpg]
	if !ok {
		host = "verifier.example"
	}
	nonce := randomHex(8)
	return backend.PresentationRequestResult{
		RequestURI: fmt.Sprintf("openid4vp://?client_id=verifiably.demo&request_uri=https://%s/oid4vp/%s", host, nonce),
		State:      nonce,
		Template:   tpl,
	}, nil
}

func (a *MockAdapter) FetchPresentationResult(_ context.Context, state, templateKey string) (backend.VerificationResult, error) {
	tpl, ok := a.oid4vpTpl[templateKey]
	if !ok {
		return backend.VerificationResult{}, errors.New("unknown template key")
	}
	return backend.VerificationResult{
		Valid:             flakyOutcome(),
		Method:            fmt.Sprintf("OID4VP · %s", tpl.Disclosure),
		Format:            tpl.Format,
		Issuer:            a.verIssuers["oid4vp"],
		Subject:           SubjectDID,
		Requested:         tpl.Fields,
		Issued:            time.Date(2024, 7, 14, 0, 0, 0, 0, time.UTC),
		CheckedRevocation: true,
	}, nil
}

func (a *MockAdapter) VerifyDirect(_ context.Context, req backend.DirectVerifyRequest) (backend.VerificationResult, error) {
	label := map[string]string{
		"scan":   "Direct QR scan (offline)",
		"upload": "Uploaded PDF — QR extracted, verified offline",
		"paste":  "Pasted credential string, verified against issuer key",
	}[req.Method]
	return backend.VerificationResult{
		Valid:             flakyOutcome(),
		Method:            label,
		Format:            "w3c_vcdm_2",
		Issuer:            a.verIssuers["direct"],
		Subject:           SubjectDID,
		Issued:            time.Date(2024, 7, 14, 0, 0, 0, 0, time.UTC),
		CheckedRevocation: req.Method != "scan",
	}, nil
}

// --- helpers ---

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func flakyOutcome() bool {
	// ~75% valid, 25% invalid — exercises both UI paths.
	n, _ := rand.Int(rand.Reader, big.NewInt(100))
	return n.Int64() > 25
}

// schemaFieldsOf returns the field names for a schema. Both builtin and custom
// schemas populate FieldsSpec now.
func schemaFieldsOf(s vctypes.Schema) []string {
	out := make([]string, 0, len(s.FieldsSpec))
	for _, f := range s.FieldsSpec {
		out = append(out, f.Name)
	}
	return out
}
