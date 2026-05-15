package credebl

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/backend"
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
	ID     string       `json:"id"`
	Format string       `json:"format"`
	Meta   dcqlMeta     `json:"meta"`
	Claims []dcqlClaim  `json:"claims"`
}

type dcqlMeta struct {
	VctValues []string `json:"vct_values"`
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
	body.DCQL.Query.Credentials = []dcqlCredential{
		{
			ID:     "vc-1",
			Format: "dc+sd-jwt",
			Meta:   dcqlMeta{VctValues: []string{tpl.Vct}},
			Claims: claims,
		},
	}

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
				DisclosedFields:   flattenJSON(resp.Data.PresentationDocument),
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
	if err := a.client.DoJSON(ctx, http.MethodPost, path, body, &resp, nil); err != nil {
		return "", fmt.Errorf("provision verifier: %w", err)
	}
	if resp.Data.ID == "" {
		return "", fmt.Errorf("credebl: provision verifier returned empty id")
	}
	a.verifierID = resp.Data.ID
	return a.verifierID, nil
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

// flattenJSON converts a JSON object to a string map for DisclosedFields.
func flattenJSON(raw json.RawMessage) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	out := make(map[string]string, len(doc))
	for k, v := range doc {
		out[k] = fmt.Sprintf("%v", v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
