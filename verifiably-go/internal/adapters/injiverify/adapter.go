package injiverify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/httpx"
	"github.com/verifiably/verifiably-go/vctypes"
)

// Adapter implements backend.Adapter for one Inji Verify v0.16.0 instance.
// Inji Verify is verifier-only; issuer/holder methods return ErrNotApplicable.
type Adapter struct {
	cfg    Config
	Vendor string
	client *httpx.Client
}

// New constructs an Adapter.
func New(cfg Config, vendor string) (*Adapter, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("injiverify: baseUrl required")
	}
	apiBase := cfg.BaseURL
	if cfg.InternalBaseURL != "" {
		apiBase = cfg.InternalBaseURL
	}
	return &Adapter{
		cfg:    cfg,
		Vendor: vendor,
		client: httpx.New(apiBase),
	}, nil
}

// oid4vpTemplates bundles a small curated set of presentation definitions the
// UI's verifier dropdown surfaces. Inji Verify doesn't expose a "list templates"
// endpoint — verifiers supply a Presentation Exchange definition on every
// vp-request. Keeping three presets matches the UI's existing shape.
var oid4vpTemplates = map[string]vctypes.OID4VPTemplate{
	"degree": {
		Title:      "University degree",
		Fields:     []string{"degree", "classification", "conferred"},
		Format:     "w3c_vcdm_2",
		Disclosure: "full credential shared",
	},
	"identity": {
		Title:      "Government identity",
		Fields:     []string{"holder", "date_of_birth"},
		Format:     "w3c_vcdm_2",
		Disclosure: "full credential shared",
	},
	"age": {
		Title:      "Proof of age over 18",
		Fields:     []string{"age_over_18"},
		Format:     "sd_jwt_vc (IETF)",
		Disclosure: "selective — only age_over_18 is shared",
	},
}

// ListOID4VPTemplates returns the curated preset list.
func (a *Adapter) ListOID4VPTemplates(_ context.Context) (map[string]vctypes.OID4VPTemplate, error) {
	out := make(map[string]vctypes.OID4VPTemplate, len(oid4vpTemplates))
	for k, v := range oid4vpTemplates {
		out[k] = v
	}
	return out, nil
}

// vpRequestCreate matches POST /v1/verify/vp-request body shape.
type vpRequestCreate struct {
	ClientID               string                 `json:"clientId"`
	TransactionID          string                 `json:"transactionId,omitempty"`
	PresentationDefinition map[string]any `json:"presentationDefinition,omitempty"`
	Nonce                  string                 `json:"nonce,omitempty"`
}

// vpRequestResponse is the slim view of VPRequestResponseDto.
type vpRequestResponse struct {
	TransactionID        string          `json:"transactionId"`
	RequestID            string          `json:"requestId"`
	RequestURI           string          `json:"requestUri"`
	ExpiresAt            int64           `json:"expiresAt"`
	AuthorizationDetails json.RawMessage `json:"authorizationDetails,omitempty"`
}

// RequestPresentation creates an OID4VP session via /v1/verify/vp-request and
// returns the Wallet-facing request URI + correlation tokens.
// Accepts either a named preset key (req.TemplateKey in oid4vpTemplates) or an
// inline custom template (req.Template != nil / req.TemplateKey == "custom").
func (a *Adapter) RequestPresentation(ctx context.Context, req backend.PresentationRequest) (backend.PresentationRequestResult, error) {
	var tpl vctypes.OID4VPTemplate
	if req.Template != nil {
		tpl = *req.Template
	} else {
		var ok bool
		tpl, ok = oid4vpTemplates[req.TemplateKey]
		if !ok {
			return backend.PresentationRequestResult{}, fmt.Errorf("injiverify: unknown template key %q", req.TemplateKey)
		}
	}
	body := vpRequestCreate{
		ClientID:               a.cfg.ClientID,
		Nonce:                  randomNonce(),
		PresentationDefinition: presentationDefinitionFor(tpl),
	}
	var resp vpRequestResponse
	if err := a.client.DoJSON(ctx, http.MethodPost, "/v1/verify/vp-request", body, &resp, nil); err != nil {
		return backend.PresentationRequestResult{}, err
	}
	// The state field we hand back to the UI is a composite of request ID and
	// transaction ID so FetchPresentationResult can poll both endpoints.
	state := resp.TransactionID + "|" + resp.RequestID
	return backend.PresentationRequestResult{
		RequestURI: resp.RequestURI,
		State:      state,
		Template:   tpl,
	}, nil
}

// vpTokenResult is the slim view of VPTokenResultDto returned from /vp-result.
type vpTokenResult struct {
	TransactionID  string         `json:"transactionId"`
	VPResultStatus string         `json:"vpResultStatus"`
	VCResults      []vcResultItem `json:"vcResults"`
}

type vcResultItem struct {
	VC                 json.RawMessage `json:"vc"`
	VerificationStatus string          `json:"verificationStatus"`
}

// FetchPresentationResult polls /v1/verify/vp-result/{txid} until a terminal
// state or timeout. Applies the INJIVER-1131 guard: if no VC result's claims
// intersect the template's requested fields, Valid is forced to false.
// When templateKey is "custom" (inline template path), the guard has no field
// list to check against and passes through — the handler enriches Method/Format
// from the session's CustomOID4VPTemplate.
func (a *Adapter) FetchPresentationResult(ctx context.Context, state, templateKey string) (backend.VerificationResult, error) {
	tpl, _ := oid4vpTemplates[templateKey]
	txid := ""
	if i := strings.Index(state, "|"); i > 0 {
		txid = state[:i]
	} else {
		txid = state
	}
	if txid == "" {
		return backend.VerificationResult{}, fmt.Errorf("injiverify: empty transaction id")
	}
	path := "/v1/verify/vp-result/" + url.PathEscape(txid)
	deadline := time.Now().Add(12 * time.Second)
	var res vpTokenResult
	for {
		err := a.client.DoJSON(ctx, http.MethodGet, path, nil, &res, nil)
		if err == nil && res.VPResultStatus != "" {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	valid := strings.EqualFold(res.VPResultStatus, "SUCCESS")
	if valid && len(res.VCResults) > 0 {
		// INJIVER-1131 guard: at least one returned VC must carry a claim
		// matching one of the template's requested fields; otherwise demote.
		valid = matchesTemplateFields(res.VCResults, tpl.Fields)
	}
	return backend.VerificationResult{
		Valid:             valid,
		Method:            fmt.Sprintf("OID4VP · %s", tpl.Disclosure),
		Format:            tpl.Format,
		Issuer:            "(resolved by verifier)",
		Subject:           "(resolved by verifier)",
		Requested:         tpl.Fields,
		Issued:            time.Now().UTC(),
		CheckedRevocation: true,
	}, nil
}

// vcSubmissionDto matches POST /v1/verify/vc-submission body shape.
type vcSubmissionDto struct {
	VC            string `json:"vc"`
	TransactionID string `json:"transactionId,omitempty"`
}

type vcSubmissionResponseDto struct {
	TransactionID string `json:"transactionId"`
}

// VerifyDirect handles paste / scan / upload requests. Strategy:
//
//   - For JSON-LD VCs (format w3c_vcdm_*) the adapter calls the synchronous
//     /vc-verification endpoint, which returns a single verificationStatus.
//
//   - For JWT-encoded VCs (jwt_vc, sd_jwt_vc) the synchronous endpoint rejects
//     them; we POST to /vc-submission to get a transactionId and poll
//     /vp-result/{txid} for the outcome.
func (a *Adapter) VerifyDirect(ctx context.Context, req backend.DirectVerifyRequest) (backend.VerificationResult, error) {
	cred := strings.TrimSpace(req.CredentialData)
	if cred == "" {
		return backend.VerificationResult{}, fmt.Errorf("injiverify: empty credential data")
	}
	if looksLikeJSONLD(cred) {
		return a.verifyJSONLD(ctx, req, cred)
	}
	return a.verifyViaSubmission(ctx, req, cred)
}

type vcVerificationStatus struct {
	VerificationStatus string `json:"verificationStatus"`
}

func (a *Adapter) verifyJSONLD(ctx context.Context, req backend.DirectVerifyRequest, cred string) (backend.VerificationResult, error) {
	// vc-verification takes the raw VC string, not JSON-wrapped. Content-Type
	// must carry the VC's format (application/ld+json for JSON-LD VCs).
	h := http.Header{}
	h.Set("Content-Type", "application/ld+json")
	raw, err := a.client.DoRaw(ctx, http.MethodPost, "/v1/verify/vc-verification",
		bytes.NewReader([]byte(cred)), "application/ld+json", h)
	if err != nil {
		return backend.VerificationResult{}, err
	}
	var r vcVerificationStatus
	if err := json.Unmarshal(raw, &r); err != nil {
		return backend.VerificationResult{}, fmt.Errorf("parse verification status: %w", err)
	}
	return backend.VerificationResult{
		Valid:             strings.EqualFold(r.VerificationStatus, "SUCCESS"),
		Method:            methodLabel(req.Method, "vc-verification"),
		Format:            "w3c_vcdm_2",
		Issuer:            extractIssuerFromJSONLD(cred),
		Subject:           "(from credential)",
		Issued:            time.Now().UTC(),
		CheckedRevocation: true,
	}, nil
}

func (a *Adapter) verifyViaSubmission(ctx context.Context, req backend.DirectVerifyRequest, cred string) (backend.VerificationResult, error) {
	var sub vcSubmissionResponseDto
	if err := a.client.DoJSON(ctx, http.MethodPost, "/v1/verify/vc-submission",
		vcSubmissionDto{VC: cred}, &sub, nil); err != nil {
		return backend.VerificationResult{}, err
	}
	path := "/v1/verify/vp-result/" + url.PathEscape(sub.TransactionID)
	var res vpTokenResult
	deadline := time.Now().Add(8 * time.Second)
	for {
		if err := a.client.DoJSON(ctx, http.MethodGet, path, nil, &res, nil); err == nil && res.VPResultStatus != "" {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	return backend.VerificationResult{
		Valid:             strings.EqualFold(res.VPResultStatus, "SUCCESS"),
		Method:            methodLabel(req.Method, "vc-submission"),
		Format:            "sd_jwt_vc (IETF)",
		Issuer:            "(from credential)",
		Subject:           "(from credential)",
		Issued:            time.Now().UTC(),
		CheckedRevocation: true,
	}, nil
}

// --- Stubs for non-verifier methods (Inji Verify is verifier-only) ---

func (a *Adapter) ListIssuerDpgs(_ context.Context) (map[string]vctypes.DPG, error) {
	return nil, nil
}
func (a *Adapter) ListHolderDpgs(_ context.Context) (map[string]vctypes.DPG, error) {
	return nil, nil
}
func (a *Adapter) ListVerifierDpgs(_ context.Context) (map[string]vctypes.DPG, error) {
	return nil, nil
}
func (a *Adapter) ListSchemas(_ context.Context, _ string) ([]vctypes.Schema, error) {
	return nil, backend.ErrNotApplicable
}
func (a *Adapter) ListAllSchemas(_ context.Context) ([]vctypes.Schema, error) { return nil, nil }
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

// Compile-time check.
var _ backend.Adapter = (*Adapter)(nil)

// --- helpers ---

func randomNonce() string {
	b := make([]byte, 12)
	_, _ = readRandom(b)
	return fmt.Sprintf("%x", b)
}

// readRandom is declared so tests can swap it; defaults to crypto/rand.
var readRandom = func(b []byte) (int, error) {
	return readRandomReal(b)
}

func methodLabel(method, backendLabel string) string {
	switch method {
	case "scan":
		return fmt.Sprintf("Direct QR scan · %s", backendLabel)
	case "upload":
		return fmt.Sprintf("Uploaded file · %s", backendLabel)
	case "paste":
		return fmt.Sprintf("Pasted credential · %s", backendLabel)
	default:
		return backendLabel
	}
}

// looksLikeJSONLD returns true if s starts with a JSON object — a reasonable
// heuristic for VCDM JSON-LD credentials versus JWS-compact strings.
func looksLikeJSONLD(s string) bool {
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		return r == '{' || r == '['
	}
	return false
}

// presentationDefinitionFor builds a minimal PE definition from a template.
func presentationDefinitionFor(tpl vctypes.OID4VPTemplate) map[string]any {
	return map[string]any{
		"id":                "pd-" + randomNonce(),
		"input_descriptors": []map[string]any{
			{
				"id":     "vc-1",
				"format": map[string]any{formatKey(tpl.Format): map[string]any{"alg": []string{"ES256", "EdDSA", "RS256"}}},
				"constraints": map[string]any{
					"fields": fieldsClause(tpl.Fields),
				},
			},
		},
	}
}

func formatKey(std string) string {
	switch std {
	case "sd_jwt_vc (IETF)":
		return "vc+sd-jwt"
	case "mso_mdoc":
		return "mso_mdoc"
	default:
		return "jwt_vc_json"
	}
}

func fieldsClause(names []string) []map[string]any {
	out := make([]map[string]any, 0, len(names))
	for _, n := range names {
		out = append(out, map[string]any{
			"path": []string{"$." + n, "$.credentialSubject." + n},
		})
	}
	return out
}

// matchesTemplateFields scans each returned VC (which may be a JWT-compact
// string or a JSON-LD object) for any of the template's requested field names.
// Used to mitigate INJIVER-1131.
func matchesTemplateFields(vcs []vcResultItem, fields []string) bool {
	if len(fields) == 0 {
		return true
	}
	for _, vc := range vcs {
		raw := string(vc.VC)
		for _, f := range fields {
			if strings.Contains(raw, `"`+f+`"`) {
				return true
			}
		}
	}
	return false
}

// extractIssuerFromJSONLD pulls `"issuer":"…"` from a raw JSON-LD VC string.
// Returns an empty string if not findable; the adapter falls back to a generic
// label in that case.
func extractIssuerFromJSONLD(s string) string {
	key := `"issuer"`
	i := strings.Index(s, key)
	if i < 0 {
		return ""
	}
	rest := s[i+len(key):]
	rest = strings.TrimLeft(rest, " \t:")
	if strings.HasPrefix(rest, `"`) {
		end := strings.Index(rest[1:], `"`)
		if end > 0 {
			return rest[1 : end+1]
		}
	}
	return ""
}

// readRandomReal defers actual randomness to crypto/rand.Reader.
func readRandomReal(b []byte) (int, error) {
	return io.ReadFull(randReader(), b)
}

// randReader is a minimal wrapper so tests can swap.
func randReader() io.Reader {
	return cryptoReader{}
}

type cryptoReader struct{}

func (cryptoReader) Read(b []byte) (int, error) {
	return cryptoReadFunc(b)
}
