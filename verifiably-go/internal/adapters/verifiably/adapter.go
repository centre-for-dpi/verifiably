// Package verifiably implements backend.Adapter by delegating verification
// requests to another verifiably-go node's public API. Used by Hub nodes to
// route OID4VP requests through a federation member's own verifier without
// needing direct access to that member's internal waltid verifier-api.
//
// Only RequestPresentation and FetchPresentationResult are implemented;
// all issuer/holder methods return ErrNotSupported.
package verifiably

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/vctypes"
)

// Config is the JSON shape expected under verifierConfig in federation.json.
type Config struct {
	ServiceEndpoint string `json:"serviceEndpoint"` // base URL of the member's verifiably-go
	APIKey          string `json:"apiKey"`          // Bearer token for the member's /api/v1 endpoints
}

// UnmarshalConfig parses a raw JSON blob into Config.
func UnmarshalConfig(raw json.RawMessage) (Config, error) {
	var c Config
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return c, err
		}
	}
	return c, nil
}

// Adapter delegates OID4VP to a remote verifiably-go API.
type Adapter struct {
	cfg    Config
	client *http.Client
}

// New constructs an Adapter. Returns an error when serviceEndpoint is missing.
func New(cfg Config) (*Adapter, error) {
	if cfg.ServiceEndpoint == "" {
		return nil, fmt.Errorf("verifiably: serviceEndpoint is required")
	}
	return &Adapter{
		cfg:    cfg,
		client: &http.Client{Timeout: 15 * time.Second},
	}, nil
}

// Compile-time check.
var _ backend.Adapter = (*Adapter)(nil)

// ── Catalog stubs ─────────────────────────────────────────────────────────────

func (a *Adapter) ListIssuerDpgs(_ context.Context) (map[string]vctypes.DPG, error)  { return nil, nil }
func (a *Adapter) ListHolderDpgs(_ context.Context) (map[string]vctypes.DPG, error)  { return nil, nil }
func (a *Adapter) ListVerifierDpgs(_ context.Context) (map[string]vctypes.DPG, error) { return nil, nil }

// ── Schema stubs ──────────────────────────────────────────────────────────────

func (a *Adapter) ListSchemas(_ context.Context, _ string) ([]vctypes.Schema, error) {
	return nil, backend.ErrNotSupported
}
func (a *Adapter) ListAllSchemas(_ context.Context) ([]vctypes.Schema, error) {
	return nil, backend.ErrNotSupported
}
func (a *Adapter) SaveCustomSchema(_ context.Context, _ vctypes.Schema) error {
	return backend.ErrNotSupported
}
func (a *Adapter) DeleteCustomSchema(_ context.Context, _ string) error {
	return backend.ErrNotSupported
}

// ── Issuance stubs ────────────────────────────────────────────────────────────

func (a *Adapter) PrefillSubjectFields(_ context.Context, _ vctypes.Schema) (map[string]string, error) {
	return nil, backend.ErrNotSupported
}
func (a *Adapter) IssueToWallet(_ context.Context, _ backend.IssueRequest) (backend.IssueToWalletResult, error) {
	return backend.IssueToWalletResult{}, backend.ErrNotSupported
}
func (a *Adapter) IssueAsPDF(_ context.Context, _ backend.IssueRequest) (backend.IssueAsPDFResult, error) {
	return backend.IssueAsPDFResult{}, backend.ErrNotSupported
}
func (a *Adapter) IssueBulk(_ context.Context, _ backend.IssueBulkRequest) (backend.IssueBulkResult, error) {
	return backend.IssueBulkResult{}, backend.ErrNotSupported
}

// ── Holder stubs ──────────────────────────────────────────────────────────────

func (a *Adapter) ListWalletCredentials(_ context.Context) ([]vctypes.Credential, error) {
	return nil, backend.ErrNotSupported
}
func (a *Adapter) DeleteWalletCredential(_ context.Context, _ string) error {
	return backend.ErrNotSupported
}
func (a *Adapter) ListExampleOffers(_ context.Context) ([]string, error) { return nil, nil }
func (a *Adapter) ParseOffer(_ context.Context, _ string) (vctypes.Credential, error) {
	return vctypes.Credential{}, backend.ErrNotSupported
}
func (a *Adapter) ClaimCredential(_ context.Context, _ vctypes.Credential) (vctypes.Credential, error) {
	return vctypes.Credential{}, backend.ErrNotSupported
}
func (a *Adapter) PresentCredential(_ context.Context, _ backend.PresentCredentialRequest) (backend.PresentCredentialResult, error) {
	return backend.PresentCredentialResult{}, backend.ErrNotApplicable
}
func (a *Adapter) BootstrapOffers(_ context.Context) ([]string, error) { return nil, nil }

// ── Verifier stubs ────────────────────────────────────────────────────────────

func (a *Adapter) ListOID4VPTemplates(_ context.Context) (map[string]vctypes.OID4VPTemplate, error) {
	return nil, nil
}
func (a *Adapter) VerifyDirect(_ context.Context, _ backend.DirectVerifyRequest) (backend.VerificationResult, error) {
	return backend.VerificationResult{}, backend.ErrNotSupported
}

// ── Verification ──────────────────────────────────────────────────────────────

type verifyReqBody struct {
	Template *vctypes.OID4VPTemplate `json:"template,omitempty"`
	SchemaID string                  `json:"schema_id,omitempty"`
}

type verifyReqResult struct {
	RequestURI string `json:"request_uri"`
	State      string `json:"state"`
}

// RequestPresentation POSTs to the member's /api/v1/verify/request with the
// full OID4VPTemplate. The member generates the actual OID4VP offer using its
// own local waltid verifier-api; the hub only needs the resulting requestURI
// and state token to show the QR code and poll the result.
func (a *Adapter) RequestPresentation(ctx context.Context, req backend.PresentationRequest) (backend.PresentationRequestResult, error) {
	body := verifyReqBody{Template: req.Template}
	if req.Template == nil {
		body.SchemaID = req.TemplateKey
	}
	b, err := json.Marshal(body)
	if err != nil {
		return backend.PresentationRequestResult{}, fmt.Errorf("verifiably: marshal: %w", err)
	}
	url := a.cfg.ServiceEndpoint + "/api/v1/verify/request"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return backend.PresentationRequestResult{}, fmt.Errorf("verifiably: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if a.cfg.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+a.cfg.APIKey)
	}
	resp, err := a.client.Do(httpReq)
	if err != nil {
		return backend.PresentationRequestResult{}, fmt.Errorf("verifiably: POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return backend.PresentationRequestResult{}, fmt.Errorf("verifiably: POST %s returned %d: %s", url, resp.StatusCode, raw)
	}
	var res verifyReqResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return backend.PresentationRequestResult{}, fmt.Errorf("verifiably: decode response: %w", err)
	}
	return backend.PresentationRequestResult{
		RequestURI: res.RequestURI,
		State:      res.State,
	}, nil
}

type verifyResultBody struct {
	Status    string            `json:"status"`
	Valid      bool              `json:"valid"`
	Pending    bool              `json:"pending"`
	Issuer     string            `json:"issuer"`
	Format     string            `json:"format"`
	Disclosed  map[string]string `json:"disclosed"`
}

// FetchPresentationResult GETs the member's /api/v1/verify/result/{state}.
func (a *Adapter) FetchPresentationResult(ctx context.Context, state, _ string) (backend.VerificationResult, error) {
	url := a.cfg.ServiceEndpoint + "/api/v1/verify/result/" + state
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return backend.VerificationResult{}, fmt.Errorf("verifiably: build request: %w", err)
	}
	if a.cfg.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+a.cfg.APIKey)
	}
	resp, err := a.client.Do(httpReq)
	if err != nil {
		return backend.VerificationResult{}, fmt.Errorf("verifiably: GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return backend.VerificationResult{}, fmt.Errorf("verifiably: GET %s returned %d: %s", url, resp.StatusCode, raw)
	}
	var res verifyResultBody
	if err := json.Unmarshal(raw, &res); err != nil {
		return backend.VerificationResult{}, fmt.Errorf("verifiably: decode response: %w", err)
	}
	return backend.VerificationResult{
		Valid:           res.Valid,
		Pending:         res.Pending,
		Issuer:          res.Issuer,
		Format:          res.Format,
		DisclosedFields: res.Disclosed,
	}, nil
}
