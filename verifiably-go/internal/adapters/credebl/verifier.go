package credebl

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/httpx"
	"github.com/verifiably/verifiably-go/vctypes"
)

// presentationCreateRequest matches
// POST /v1/orgs/{orgId}/oid4vp/presentation?verifierId={id}.
type presentationCreateRequest struct {
	RequestSigner requestSigner `json:"requestSigner"`
	ResponseMode  string        `json:"responseMode"`
	DCQL          dcqlQuery     `json:"dcql"`
}

type requestSigner struct {
	Method string `json:"method"`
}

type dcqlQuery struct {
	Query struct {
		Credentials []dcqlCredential `json:"credentials"`
	} `json:"query"`
}

type dcqlCredential struct {
	ID     string    `json:"id"`
	Format string    `json:"format"`
	Meta   *dcqlMeta `json:"meta,omitempty"`
	Claims []dcqlClaim `json:"claims"`
}

type dcqlMeta struct {
	VctValues []string `json:"vct_values,omitempty"`
}

type dcqlClaim struct {
	Path []string `json:"path"`
}

type presentationCreateResponse struct {
	Data struct {
		AuthorizationRequest string `json:"authorizationRequest"`
		VerificationSession  struct {
			ID string `json:"id"`
		} `json:"verificationSession"`
	} `json:"data"`
}

type verifierPresentationResponse struct {
	Data struct {
		State                string          `json:"state"`
		PresentationDocument json.RawMessage `json:"presentationDocument"`
	} `json:"data"`
}

// ListOID4VPTemplates builds OID4VP templates dynamically from the configured
// CREDEBL credential templates. One template per credential type, all-fields.
func (a *Adapter) ListOID4VPTemplates(ctx context.Context) (map[string]vctypes.OID4VPTemplate, error) {
	schemas, err := a.ListSchemas(ctx, a.Vendor)
	if err != nil {
		return map[string]vctypes.OID4VPTemplate{}, nil
	}
	out := make(map[string]vctypes.OID4VPTemplate, len(schemas))
	for _, s := range schemas {
		fields := make([]string, 0, len(s.FieldsSpec))
		for _, f := range s.FieldsSpec {
			fields = append(fields, f.Name)
		}
		key := schemaKey(s.Name)
		out[key] = vctypes.OID4VPTemplate{
			Title:          s.Name,
			Fields:         fields,
			Format:         s.Std,
			Disclosure:     "selective — SD-JWT VC (dc+sd-jwt)",
			CredentialType: s.Name,
			Vct:            s.Vct,
			WireFormat:     "dc+sd-jwt",
		}
	}
	return out, nil
}

// RequestPresentation creates an OID4VP verification session via CREDEBL's
// DCQL-based presentation API. Returns the openid4vp:// authorization_request
// URI the holder scans, plus the session ID used by FetchPresentationResult.
func (a *Adapter) RequestPresentation(ctx context.Context, req backend.PresentationRequest) (backend.PresentationRequestResult, error) {
	var tpl vctypes.OID4VPTemplate
	if req.Template != nil {
		tpl = *req.Template
	} else {
		templates, terr := a.ListOID4VPTemplates(ctx)
		if terr != nil || len(templates) == 0 {
			return backend.PresentationRequestResult{}, fmt.Errorf("credebl: no OID4VP templates available")
		}
		var ok bool
		if tpl, ok = templates[req.TemplateKey]; !ok {
			return backend.PresentationRequestResult{}, fmt.Errorf("credebl: unknown template key %q", req.TemplateKey)
		}
	}

	claims := make([]dcqlClaim, 0, len(tpl.Fields))
	for _, f := range tpl.Fields {
		claims = append(claims, dcqlClaim{Path: []string{f}})
	}

	var body presentationCreateRequest
	body.RequestSigner.Method = "DID"
	body.ResponseMode = "direct_post"
	cred := dcqlCredential{
		ID:     "vc-1",
		Format: "dc+sd-jwt",
		Claims: claims,
	}
	if tpl.Vct != "" {
		cred.Meta = &dcqlMeta{VctValues: []string{tpl.Vct}}
	}
	body.DCQL.Query.Credentials = []dcqlCredential{cred}

	var result backend.PresentationRequestResult
	if err := a.withAuth(ctx, func(ctx context.Context) error {
		verifierID, err := a.ensureVerifier(ctx)
		if err != nil {
			return err
		}
		path := fmt.Sprintf("/v1/orgs/%s/oid4vp/presentation?verifierId=%s", a.cfg.OrgID, verifierID)
		var resp presentationCreateResponse
		if err := a.client.DoJSON(ctx, http.MethodPost, path, body, &resp, nil); err != nil {
			return fmt.Errorf("create presentation: %w", err)
		}
		if resp.Data.AuthorizationRequest == "" {
			return fmt.Errorf("credebl: create-presentation returned empty authorizationRequest")
		}
		result = backend.PresentationRequestResult{
			RequestURI: resp.Data.AuthorizationRequest,
			State:      resp.Data.VerificationSession.ID,
			Template:   tpl,
		}
		return nil
	}); err != nil {
		return backend.PresentationRequestResult{}, err
	}
	return result, nil
}

// FetchPresentationResult polls CREDEBL's verification session until the holder
// submits a presentation or the context is cancelled.
// state is the verificationSession.id from RequestPresentation.
func (a *Adapter) FetchPresentationResult(ctx context.Context, state, _ string) (backend.VerificationResult, error) {
	path := fmt.Sprintf("/v1/orgs/%s/oid4vp/verifier-presentation?id=%s", a.cfg.OrgID, state)
	deadline := time.Now().Add(30 * time.Second)
	var resp verifierPresentationResponse
	for {
		if err := a.withAuth(ctx, func(ctx context.Context) error {
			return a.client.DoJSON(ctx, http.MethodGet, path, nil, &resp, nil)
		}); err != nil {
			return backend.VerificationResult{}, fmt.Errorf("poll presentation: %w", err)
		}
		switch resp.Data.State {
		case "ResponseVerified":
			return backend.VerificationResult{
				Valid:             true,
				Method:            "OID4VP · selective — SD-JWT VC",
				Format:            "sd_jwt_vc (IETF)",
				Issuer:            "(verified by CREDEBL)",
				Subject:           "(from credential)",
				Issued:            time.Now().UTC(),
				CheckedRevocation: true,
				DisclosedFields:   extractDisclosedFields(resp.Data.PresentationDocument),
			}, nil
		case "Error":
			return backend.VerificationResult{
				Valid:  false,
				Method: "OID4VP · CREDEBL",
			}, nil
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return backend.VerificationResult{Pending: true}, nil
		case <-time.After(time.Second):
		}
	}
	return backend.VerificationResult{Pending: true}, nil
}

// VerifyDirect is not supported — CREDEBL does not expose a synchronous
// direct-verify endpoint. Holders must use the OID4VP flow.
func (a *Adapter) VerifyDirect(_ context.Context, _ backend.DirectVerifyRequest) (backend.VerificationResult, error) {
	return backend.VerificationResult{}, backend.ErrNotSupported
}

// ensureVerifier returns the OID4VP verifier DB ID, auto-provisioning a verifier
// named "verifiably-go" on first use when no verifierId was set in config.
// On 409 (verifier exists from a prior run) it recovers by listing the org's
// verifiers and matching on publicVerifierId — same pattern as resolveTemplateID.
func (a *Adapter) ensureVerifier(ctx context.Context) (string, error) {
	a.verifierMu.Lock()
	defer a.verifierMu.Unlock()
	if a.verifierID != "" {
		return a.verifierID, nil
	}
	body := map[string]any{
		"verifierId": "verifiably-go",
		"clientMetadata": map[string]string{
			"client_name": "Verifiably",
			"logo_uri":    a.cfg.PublicBaseURL + "/static/logo.png",
		},
	}
	path := fmt.Sprintf("/v1/orgs/%s/oid4vp/verifier", a.cfg.OrgID)
	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	err := a.client.DoJSON(ctx, http.MethodPost, path, body, &resp, nil)
	if err == nil {
		if resp.Data.ID == "" {
			return "", fmt.Errorf("credebl: provision verifier returned empty id")
		}
		a.verifierID = resp.Data.ID
		return a.verifierID, nil
	}
	if !httpx.IsStatus(err, http.StatusConflict) {
		return "", fmt.Errorf("provision verifier: %w", err)
	}
	// 409 — verifier already registered (container restart); look it up by publicVerifierId.
	type verifierEntry struct {
		ID               string `json:"id"`
		PublicVerifierID string `json:"publicVerifierId"`
	}
	var listResp struct {
		Data []verifierEntry `json:"data"`
	}
	if err := a.client.DoJSON(ctx, http.MethodGet, path, nil, &listResp, nil); err != nil {
		return "", fmt.Errorf("list verifiers after 409: %w", err)
	}
	for _, v := range listResp.Data {
		if v.PublicVerifierID == "verifiably-go" {
			a.verifierID = v.ID
			return a.verifierID, nil
		}
	}
	return "", fmt.Errorf("credebl: verifier 'verifiably-go' not found after 409")
}

// --- helpers ---

// schemaKey converts a schema name to a stable lowercase underscore key
// suitable for use as a map key in the OID4VP template index.
func schemaKey(name string) string {
	var b strings.Builder
	prevUnderscore := false
	for i, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevUnderscore = false
		default:
			if !prevUnderscore && i > 0 {
				b.WriteByte('_')
				prevUnderscore = true
			}
		}
	}
	s := strings.TrimRight(b.String(), "_")
	if s == "" {
		return "credential"
	}
	return s
}

// jwtTechnicalFields lists JWT/SD-JWT protocol fields that are not credential claims.
var jwtTechnicalFields = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true, "nbf": true, "iat": true,
	"jti": true, "vct": true, "_sd": true, "_sd_alg": true, "cnf": true,
	"status": true, "type": true, "@context": true,
}

// extractDisclosedFields pulls credential claim values from CREDEBL's
// presentationDocument. The shape varies by verification flow:
//   - Flat SD-JWT payload: {"given_name":"…","iss":"…",…}
//   - DCQL nested:         {"credentials":{"vc-1":{"given_name":"…",…}}}
//
// JWT/SD-JWT protocol fields are omitted so only human-readable claims remain.
func extractDisclosedFields(raw json.RawMessage) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	log.Printf("[credebl] presentationDocument (%d bytes): %.800s", len(raw), string(raw))

	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil || doc == nil {
		return nil
	}

	// DCQL nested: {"credentials":{"vc-1":{…claims…}}}
	if credsAny, ok := doc["credentials"]; ok {
		if credsMap, ok := credsAny.(map[string]any); ok {
			out := make(map[string]string)
			for _, v := range credsMap {
				if claimMap, ok := v.(map[string]any); ok {
					mergeClaimValues(out, claimMap)
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}

	// Flat (decoded SD-JWT VC payload or PEX result at top level)
	out := make(map[string]string, len(doc))
	mergeClaimValues(out, doc)
	if len(out) == 0 {
		return nil
	}
	return out
}

// mergeClaimValues copies non-technical claim values from src into dst,
// stringifying each value appropriately.
func mergeClaimValues(dst map[string]string, src map[string]any) {
	for k, v := range src {
		if jwtTechnicalFields[k] {
			continue
		}
		switch tv := v.(type) {
		case string:
			dst[k] = tv
		case bool:
			dst[k] = fmt.Sprintf("%v", tv)
		case float64:
			if tv == float64(int64(tv)) {
				dst[k] = fmt.Sprintf("%d", int64(tv))
			} else {
				dst[k] = fmt.Sprintf("%g", tv)
			}
		case map[string]any:
			b, _ := json.Marshal(tv)
			dst[k] = string(b)
		case []any:
			b, _ := json.Marshal(tv)
			dst[k] = string(b)
		default:
			if v != nil {
				dst[k] = fmt.Sprintf("%v", tv)
			}
		}
	}
}
