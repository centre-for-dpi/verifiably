package injiverify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/httpx"
	"github.com/verifiably/verifiably-go/internal/vp"
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
	// Resolve the requested credential(s). A delegated-access PAIR sets
	// req.Templates = [subject, delegation]; Inji Verify 0.16 accepts a
	// multi-input_descriptor presentation_definition and returns a per-credential
	// vcResults array (PROVEN), so we build ONE request with N descriptors — a
	// single QR any wallet scans, then FetchPresentationResult + the delegation
	// evaluator combine the two into the delegated-access verdict.
	var tpls []vctypes.OID4VPTemplate
	switch {
	case len(req.Templates) > 0:
		tpls = req.Templates
	case req.Template != nil:
		tpls = []vctypes.OID4VPTemplate{*req.Template}
	default:
		tpl, ok := oid4vpTemplates[req.TemplateKey]
		if !ok {
			return backend.PresentationRequestResult{}, fmt.Errorf("injiverify: unknown template key %q", req.TemplateKey)
		}
		tpls = []vctypes.OID4VPTemplate{tpl}
	}
	body := vpRequestCreate{
		ClientID:               a.cfg.ClientID,
		Nonce:                  randomNonce(),
		PresentationDefinition: presentationDefinitionForN(tpls),
	}
	var resp vpRequestResponse
	if err := a.client.DoJSON(ctx, http.MethodPost, "/v1/verify/vp-request", body, &resp, nil); err != nil {
		return backend.PresentationRequestResult{}, err
	}
	// Inji Verify v0.16 does not return requestUri in the POST response.
	// Build the OID4VP cross-device URI: the wallet fetches the signed JAR
	// from GET /vp-request/{requestId} (application/oauth-authz-req+jwt).
	requestURI := fmt.Sprintf(
		"openid4vp://authorize?client_id=%s&request_uri=%s",
		url.QueryEscape(a.cfg.ClientID),
		url.QueryEscape(a.cfg.BaseURL+"/v1/verify/vp-request/"+resp.RequestID),
	)
	// The state field we hand back to the UI is a composite of request ID and
	// transaction ID so FetchPresentationResult can poll both endpoints.
	state := resp.TransactionID + "|" + resp.RequestID
	return backend.PresentationRequestResult{
		RequestURI: requestURI,
		State:      state,
		Template:   tpls[0],
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

	// No submission landed within the poll window — the wallet hasn't posted
	// yet (vp-result returns NO_VP_SUBMISSION until it does). Report PENDING,
	// not invalid, so the UI/API keeps polling instead of showing a spurious
	// "failed" the instant the request is created.
	if res.VPResultStatus == "" {
		return backend.VerificationResult{
			Pending:   true,
			Method:    fmt.Sprintf("OID4VP · %s", tpl.Disclosure),
			Format:    tpl.Format,
			Requested: tpl.Fields,
			Issued:    time.Now().UTC(),
		}, nil
	}

	valid := strings.EqualFold(res.VPResultStatus, "SUCCESS")
	if valid && len(res.VCResults) > 0 {
		// INJIVER-1131 guard: at least one returned VC must carry a claim
		// matching one of the template's requested fields; otherwise demote.
		valid = matchesTemplateFields(res.VCResults, tpl.Fields)
	}
	creds, holder := normalizeInjiCredentials(res.VCResults)
	result := backend.VerificationResult{
		Valid:             valid,
		Method:            fmt.Sprintf("OID4VP · %s", tpl.Disclosure),
		Format:            tpl.Format,
		Issuer:            "(resolved by verifier)",
		Subject:           "(resolved by verifier)",
		Requested:         tpl.Fields,
		Issued:            time.Now().UTC(),
		// Inji Verify's vcverifier does NOT check status for VC_SD_JWT (it logs
		// "Credential status checking not supported for this credential format"),
		// so this path has NOT checked revocation. Report honestly; the handler's
		// attachRevocationVerdict does the real status check and flips this true
		// when it resolves the credential's status list.
		CheckedRevocation: false,
		Credentials:       creds,
		HolderBinding:     holder,
	}
	// Single-credential presentation: surface the disclosed claim values so the
	// result shows the STRUCTURED FIELDS (e.g. testa_id, last_name), not just the
	// signed envelope. The claims were already parsed into creds[0].Claims from the
	// presented VC's credentialSubject (normalizeInjiCredentials → vp.FromVCObject).
	// A multi-credential / delegated pair instead renders per-credential cards
	// (CredentialViews) in the handler, so leave DisclosedFields empty there.
	if len(creds) == 1 {
		result.DisclosedFields = disclosedForRequest(creds[0].Claims, tpl.Fields)
	}
	return result, nil
}

// disclosedForRequest picks the claim values to display for a single-credential
// OID4VP verify. It returns claims filtered to the requested field names (matching
// the "Requesting: …" line); when no fields were requested (full disclosure) or
// none of the requested names match what the VC actually carries (e.g. a
// namespacing mismatch), it returns all disclosed claims rather than nothing.
func disclosedForRequest(claims map[string]string, fields []string) map[string]string {
	if len(claims) == 0 {
		return nil
	}
	if len(fields) == 0 {
		return claims
	}
	out := make(map[string]string, len(fields))
	for _, f := range fields {
		if v, ok := claims[f]; ok {
			out[f] = v
		}
	}
	if len(out) == 0 {
		return claims
	}
	return out
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
	Error              string `json:"error"`
}

// normalizeDirectCredential decodes a directly-submitted credential — a JSON-LD
// VC object, a compact SD-JWT (has `~`), or a compact VC-JWT — into the shared
// NormalizedCredential shape plus a flat disclosed-claims map. This lets the
// direct-verify path feed the SAME revocation/temporal gates (via the handler's
// attachDelegationVerdict → StatusRefOf, which reads the credentialStatus /
// status_list pointer off the credential) and surface the SAME claim values the
// OID4VP path shows. Mirrors normalizeInjiCredentials. Returns (nil, nil) when
// the payload can't be decoded (verification proceeds without the extra gates).
func normalizeDirectCredential(cred string) ([]backend.NormalizedCredential, map[string]string) {
	cred = strings.TrimSpace(cred)
	var nc backend.NormalizedCredential
	switch {
	case strings.HasPrefix(cred, "{"):
		var obj map[string]any
		if json.Unmarshal([]byte(cred), &obj) != nil || len(obj) == 0 {
			return nil, nil
		}
		nc = vp.FromVCObject(obj)
	case strings.Contains(cred, "~"):
		var ok bool
		if nc, ok = vp.FromCompactSDJWT(cred); !ok {
			return nil, nil
		}
	default:
		p := vp.DecodeJWTPayload(cred)
		if p == nil {
			return nil, nil
		}
		nc = vp.FromVCObject(p)
	}
	fields := nc.Claims
	if len(fields) == 0 {
		fields = nil
	}
	return []backend.NormalizedCredential{nc}, fields
}

func (a *Adapter) verifyJSONLD(ctx context.Context, req backend.DirectVerifyRequest, cred string) (backend.VerificationResult, error) {
	// vc-verification takes the raw VC string, not JSON-wrapped. Content-Type
	// must carry the VC's format (application/ld+json for JSON-LD VCs).
	h := http.Header{}
	h.Set("Content-Type", "application/ld+json")
	raw, err := a.client.DoRaw(ctx, http.MethodPost, "/v1/verify/vc-verification",
		bytes.NewReader([]byte(cred)), "application/ld+json", h)
	if err != nil {
		// Inji Verify returns a NON-2xx when it can't retrieve verifiably's SIGNED
		// (JWS) bitstring status list (STATUS_RETRIEVAL_ERROR) — the signature and
		// everything else verified, it just can't parse our status list. verifiably
		// OWNS the status list and re-checks revocation in the handler gate (F14),
		// so build a signature-valid result from the credential itself and let the
		// gate be the authority (a genuinely revoked cred is then still denied).
		if strings.Contains(strings.ToUpper(err.Error()), "STATUS_RETRIEVAL_ERROR") {
			creds, disclosed := normalizeDirectCredential(cred)
			return backend.VerificationResult{
				Valid:             true,
				Method:            methodLabel(req.Method, "vc-verification"),
				Format:            "w3c_vcdm_2",
				Issuer:            extractIssuerFromJSONLD(cred),
				Subject:           "(from credential)",
				Issued:            time.Now().UTC(),
				DisclosedFields:   disclosed,
				Credentials:       creds,
				CheckedRevocation: false,
			}, nil
		}
		return backend.VerificationResult{}, err
	}
	var r vcVerificationStatus
	if err := json.Unmarshal(raw, &r); err != nil {
		return backend.VerificationResult{}, fmt.Errorf("parse verification status: %w", err)
	}
	creds, disclosed := normalizeDirectCredential(cred)
	valid := strings.EqualFold(r.VerificationStatus, "SUCCESS")
	// Inji Verify's vcverifier chokes on verifiably's SIGNED (JWS) bitstring status
	// list and returns STATUS_RETRIEVAL_ERROR even when the signature + everything
	// else verified. verifiably OWNS the status list and re-checks revocation in the
	// handler's gate (attachRevocationVerdict, F14), so a PURE status-retrieval
	// failure isn't a verification failure here — treat it as signature-valid and
	// let the gate be the authority (a genuinely revoked cred is then still denied,
	// a live one still passes). Any OTHER non-SUCCESS status remains invalid.
	if !valid && strings.Contains(strings.ToUpper(r.Error), "STATUS_RETRIEVAL_ERROR") {
		valid = true
	}
	return backend.VerificationResult{
		Valid:             valid,
		Method:            methodLabel(req.Method, "vc-verification"),
		Format:            "w3c_vcdm_2",
		Issuer:            extractIssuerFromJSONLD(cred),
		Subject:           "(from credential)",
		Issued:            time.Now().UTC(),
		// Decode the credentialSubject claims (F12) and the normalized credential
		// (F14) so the handler shows the values AND runs the revocation/temporal
		// gates — Inji Verify's own /vc-verification is status-blind.
		DisclosedFields: disclosed,
		Credentials:     creds,
		// CheckedRevocation stays false here; the handler's revocation gate flips
		// it to true only once a status list is actually resolved (P2 honesty).
		CheckedRevocation: false,
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
	creds, disclosed := normalizeDirectCredential(cred)
	issuer := "(from credential)"
	if len(creds) > 0 && creds[0].Issuer != "" {
		issuer = creds[0].Issuer
	}
	return backend.VerificationResult{
		Valid:             strings.EqualFold(res.VPResultStatus, "SUCCESS"),
		Method:            methodLabel(req.Method, "vc-submission"),
		Format:            "sd_jwt_vc (IETF)",
		Issuer:            issuer,
		Subject:           "(from credential)",
		Issued:            time.Now().UTC(),
		// Decode disclosed claims (F12) + normalized credential (F14) so the
		// handler shows the values and runs the revocation/temporal gates.
		DisclosedFields: disclosed,
		Credentials:     creds,
		// Handler's revocation gate flips CheckedRevocation to true once a status
		// list is resolved (P2 honesty).
		CheckedRevocation: false,
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
	return presentationDefinitionForN([]vctypes.OID4VPTemplate{tpl})
}

// presentationDefinitionForN builds a presentation_definition with one
// input_descriptor per template — a single descriptor for an ordinary request, N
// for a delegated-access pair ([subject, delegation]). Inji Verify 0.16 honours a
// multi-descriptor PD and returns a per-credential vcResults array, so the whole
// pair rides one cross-device QR. Each descriptor gets a stable, unique id
// (vc-1, vc-2, …) so the wallet's presentation_submission can map each leg.
func presentationDefinitionForN(tpls []vctypes.OID4VPTemplate) map[string]any {
	descs := make([]map[string]any, 0, len(tpls))
	for i, tpl := range tpls {
		desc := map[string]any{
			"id":     fmt.Sprintf("vc-%d", i+1),
			"format": map[string]any{formatKey(tpl.Format): formatAlgClause(tpl.Format)},
			"constraints": map[string]any{
				"fields": fieldsClause(tpl),
			},
		}
		// Name the descriptor so the wallet's consent screen labels each
		// requested credential (not a guessed/held one).
		if tpl.Title != "" {
			desc["name"] = tpl.Title
		}
		descs = append(descs, desc)
	}
	return map[string]any{
		"id":                "pd-" + randomNonce(),
		"input_descriptors": descs,
	}
}

func formatKey(std string) string {
	switch {
	case std == "sd_jwt_vc (IETF)":
		return "vc+sd-jwt"
	case std == "mso_mdoc":
		return "mso_mdoc"
	case strings.HasPrefix(std, "w3c_vcdm"):
		// Inji-issued W3C credentials are JSON-LD (ldp_vc); presenting them to
		// Inji Verify is an ldp_vp (a JSON-LD VerifiablePresentation), NOT a
		// JWT-encoded VC. Advertising jwt_vc_json here would mismatch the format.
		return "ldp_vp"
	default:
		return "jwt_vc_json"
	}
}

// formatAlgClause returns the DIF Presentation Exchange format-algorithm object
// for a given std. SD-JWT VC (vc+sd-jwt) MUST use sd-jwt_alg_values /
// kb-jwt_alg_values (per the OID4VP SD-JWT VC profile); the JWT-style "alg" key
// is not permitted under a vc+sd-jwt format entry, so a strict wallet PEX
// validator (e.g. @sphereon/pex in credo-ts) rejects the whole definition with
// "This is not a valid PresentationDefinition". Other formats (jwt_vc_json,
// mso_mdoc) use "alg".
func formatAlgClause(std string) map[string]any {
	algs := []string{"ES256", "EdDSA", "RS256"}
	switch {
	case std == "sd_jwt_vc (IETF)":
		return map[string]any{
			"sd-jwt_alg_values": algs,
			"kb-jwt_alg_values": algs,
		}
	case strings.HasPrefix(std, "w3c_vcdm"):
		// ldp_vp advertises the Data-Integrity proof suites the verifier accepts
		// (Inji Verify: Ed25519Signature2018/2020, RsaSignature2018). The in-app
		// holder presents an UNSIGNED VP — Inji Verify accepts an ldp_vp without a
		// VP-level proof, verifying the wrapped credential's own issuer proof — so
		// this list only satisfies the PEX format entry.
		return map[string]any{
			"proof_type": []string{"Ed25519Signature2020", "Ed25519Signature2018", "RsaSignature2018"},
		}
	default:
		return map[string]any{"alg": algs}
	}
}

func fieldsClause(tpl vctypes.OID4VPTemplate) []map[string]any {
	out := make([]map[string]any, 0, len(tpl.Fields)+1)
	// Pin the SD-JWT VC type with a vct filter so the wallet selects the EXACT
	// credential to present instead of matching any held credential that
	// happens to share these field names. Without it, a wallet holding another
	// credential from the same schema family (e.g. an older "Police Clearance
	// Certificate" with subjectRef/givenName) matches the wrong one and reports
	// "No credential found for: vc-1". vct is a base-payload claim (never in a
	// selective disclosure), so the filter always resolves.
	//
	// Pin the vct with `pattern` (an anchored regex of the exact vct). We ALSO
	// emit `const` because it's the SD-JWT VC-profile-recommended way to pin a
	// vct and any wallet/verifier that consumes this PD directly can key its
	// candidate pre-selection off it. NOTE (measured 2026-07-08): Inji Verify's
	// FilterDTO models only {type, pattern} and STRIPS `const` when it serves
	// the signed request object, so over the Inji path the wallet (Credo-TS)
	// only ever sees `pattern` — that must stay present (const-only would leave
	// an empty `{type:string}` that matches everything). A value satisfying
	// const also satisfies the identical pattern, so they never conflict.
	// vct is a base-payload claim (never selectively disclosed) so both resolve.
	if tpl.Vct != "" {
		out = append(out, map[string]any{
			"path": []string{"$.vct"},
			"filter": map[string]any{
				"type":    "string",
				"const":   tpl.Vct,
				"pattern": "^" + regexp.QuoteMeta(tpl.Vct) + "$",
			},
		})
	}
	for _, n := range tpl.Fields {
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
