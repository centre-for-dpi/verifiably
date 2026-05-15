package credebl

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/vctypes"
)

// credentialTemplate is the shape returned by
// GET /v1/orgs/{orgId}/oid4vc/{issuerId}/template.
type credentialTemplate struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Format   string `json:"format"`
	Template struct {
		Vct        string              `json:"vct"`
		Attributes []templateAttribute `json:"attributes"`
	} `json:"template"`
}

type templateAttribute struct {
	Key       string `json:"key"`
	ValueType string `json:"value_type"`
	Disclose  bool   `json:"disclose"`
}

type templateListResponse struct {
	Data []credentialTemplate `json:"data"`
}

// ListSchemas fetches CREDEBL credential templates and maps each one to a
// vctypes.Schema. Schema.ID is the template DB ID — passed back verbatim as
// templateId in the IssueToWallet offer payload.
func (a *Adapter) ListSchemas(ctx context.Context, issuerDpg string) ([]vctypes.Schema, error) {
	path := fmt.Sprintf("/v1/orgs/%s/oid4vc/%s/template", a.cfg.OrgID, a.cfg.IssuerID)
	var resp templateListResponse
	if err := a.withAuth(ctx, func(ctx context.Context) error {
		return a.client.DoJSON(ctx, http.MethodGet, path, nil, &resp, nil)
	}); err != nil {
		return nil, fmt.Errorf("list templates: %w", err)
	}
	out := make([]vctypes.Schema, 0, len(resp.Data))
	for _, t := range resp.Data {
		fields := make([]vctypes.FieldSpec, 0, len(t.Template.Attributes))
		for _, attr := range t.Template.Attributes {
			fields = append(fields, vctypes.FieldSpec{
				Name:     attr.Key,
				Datatype: coerceDatatype(attr.ValueType),
				Required: true,
			})
		}
		std := formatToStd(t.Format)
		if std == "" {
			std = "sd_jwt_vc (IETF)"
		}
		out = append(out, vctypes.Schema{
			ID:         t.ID,
			Name:       t.Name,
			Std:        std,
			DPGs:       []string{issuerDpg},
			Desc:       fmt.Sprintf("SD-JWT VC issued by CREDEBL · %s", issuerDpg),
			FieldsSpec: fields,
			Vct:        t.Template.Vct,
		})
	}
	return out, nil
}

// ListAllSchemas mirrors ListSchemas for interface completeness.
func (a *Adapter) ListAllSchemas(ctx context.Context) ([]vctypes.Schema, error) {
	return a.ListSchemas(ctx, a.Vendor)
}

// PrefillSubjectFields returns empty — the operator enters data manually.
func (a *Adapter) PrefillSubjectFields(_ context.Context, _ vctypes.Schema) (map[string]string, error) {
	return map[string]string{}, nil
}

// offerCreateRequest matches POST /v1/orgs/{orgId}/oid4vc/{issuerId}/create-offer.
type offerCreateRequest struct {
	AuthorizationType string            `json:"authorizationType"`
	PIN               string            `json:"pin"`
	Credentials       []offerCredential `json:"credentials"`
}

type offerCredential struct {
	TemplateID string         `json:"templateId"`
	Payload    map[string]any `json:"payload"`
}

type offerCreateResponse struct {
	Data struct {
		CredentialOffer string `json:"credentialOffer"`
		IssuanceSession struct {
			UserPin string `json:"userPin"`
		} `json:"issuanceSession"`
	} `json:"data"`
}

// IssueToWallet generates a CREDEBL OID4VCI credential offer using the
// pre-authorized code flow. Returns the openid-credential-offer:// URI the
// Verifiably UI renders as a QR code for the holder's wallet.
func (a *Adapter) IssueToWallet(ctx context.Context, req backend.IssueRequest) (backend.IssueToWalletResult, error) {
	// Resolve templateID first (may need auth for custom-* schemas).
	templateID := req.Schema.ID
	if strings.HasPrefix(templateID, "custom-") {
		var resolved string
		if err := a.withAuth(ctx, func(ctx context.Context) error {
			var rerr error
			resolved, rerr = a.resolveTemplateID(ctx, req.Schema)
			return rerr
		}); err != nil {
			return backend.IssueToWalletResult{}, fmt.Errorf("resolve template: %w", err)
		}
		templateID = resolved
	}
	payload := make(map[string]any, len(req.SubjectData))
	for k, v := range req.SubjectData {
		payload[k] = v
	}
	body := offerCreateRequest{
		AuthorizationType: "preAuthorizedCodeFlow",
		PIN:               a.cfg.DefaultPIN,
		Credentials: []offerCredential{
			{TemplateID: templateID, Payload: payload},
		},
	}
	path := fmt.Sprintf("/v1/orgs/%s/oid4vc/%s/create-offer", a.cfg.OrgID, a.cfg.IssuerID)
	var resp offerCreateResponse
	if err := a.withAuth(ctx, func(ctx context.Context) error {
		return a.client.DoJSON(ctx, http.MethodPost, path, body, &resp, nil)
	}); err != nil {
		return backend.IssueToWalletResult{}, fmt.Errorf("create-offer: %w", err)
	}
	if resp.Data.CredentialOffer == "" {
		return backend.IssueToWalletResult{}, fmt.Errorf("credebl: create-offer returned empty credentialOffer")
	}
	offerURI := a.rewritePublic(resp.Data.CredentialOffer)
	return backend.IssueToWalletResult{
		OfferURI: offerURI,
		OfferID:  extractOfferID(offerURI),
		Flow:     "pre_auth",
		PIN:      resp.Data.IssuanceSession.UserPin,
	}, nil
}

// IssueAsPDF is not supported by CREDEBL in this adapter.
func (a *Adapter) IssueAsPDF(_ context.Context, _ backend.IssueRequest) (backend.IssueAsPDFResult, error) {
	return backend.IssueAsPDFResult{}, backend.ErrNotSupported
}

// IssueBulk iterates rows and issues one pre-auth offer per row.
func (a *Adapter) IssueBulk(ctx context.Context, req backend.IssueBulkRequest) (backend.IssueBulkResult, error) {
	if len(req.Rows) == 0 {
		return backend.IssueBulkResult{}, fmt.Errorf("credebl: no rows")
	}
	var out backend.IssueBulkResult
	out.Rows = make([]backend.BulkRowResult, 0, len(req.Rows))
	for i, row := range req.Rows {
		label := rowLabel(row)
		res, err := a.IssueToWallet(ctx, backend.IssueRequest{
			IssuerDpg:   req.IssuerDpg,
			Schema:      req.Schema,
			SubjectData: row,
			Flow:        "pre_auth",
		})
		if err != nil {
			out.Rejected++
			reason := truncate(err.Error(), 140)
			out.Errors = append(out.Errors, backend.BulkError{Row: i + 1, Reason: reason})
			out.Rows = append(out.Rows, backend.BulkRowResult{
				Row: i + 1, Subject: row, Label: label, Status: "failed", Error: reason,
			})
			continue
		}
		out.Accepted++
		out.Rows = append(out.Rows, backend.BulkRowResult{
			Row: i + 1, Subject: row, Label: label, Status: "issued", OfferURI: res.OfferURI,
		})
	}
	return out, nil
}

// BootstrapOffers issues one demo offer against the first available template.
// Called at startup to seed the wallet's "paste example" helper.
func (a *Adapter) BootstrapOffers(ctx context.Context) ([]string, error) {
	schemas, err := a.ListSchemas(ctx, a.Vendor)
	if err != nil || len(schemas) == 0 {
		return nil, nil
	}
	seed := make(map[string]string, len(schemas[0].FieldsSpec))
	for _, f := range schemas[0].FieldsSpec {
		seed[f.Name] = "demo"
	}
	res, err := a.IssueToWallet(ctx, backend.IssueRequest{
		IssuerDpg:   a.Vendor,
		Schema:      schemas[0],
		SubjectData: seed,
		Flow:        "pre_auth",
	})
	if err != nil {
		return nil, nil
	}
	return []string{res.OfferURI}, nil
}

// --- helpers ---

func formatToStd(format string) string {
	switch format {
	case "dc+sd-jwt", "vc+sd-jwt":
		return "sd_jwt_vc (IETF)"
	case "jwt_vc_json", "ldp_vc":
		return "w3c_vcdm_2"
	default:
		return ""
	}
}

func coerceDatatype(t string) string {
	switch t {
	case "number", "integer", "boolean":
		return t
	default:
		return "string"
	}
}

func rowLabel(row map[string]string) string {
	for _, k := range []string{"given_name", "fullName", "holder", "name", "personalIdentifier"} {
		if v := strings.TrimSpace(row[k]); v != "" {
			return v
		}
	}
	first := strings.TrimSpace(row["firstName"])
	last := strings.TrimSpace(row["family_name"])
	if first != "" || last != "" {
		return strings.TrimSpace(first + " " + last)
	}
	for _, v := range row {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return "(empty row)"
}

func extractOfferID(offerURI string) string {
	if i := strings.LastIndex(offerURI, "/"); i >= 0 && i+1 < len(offerURI) {
		return offerURI[i+1:]
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// --- custom schema push to CREDEBL ---

type schemaCreateRequest struct {
	Type          string           `json:"type"`
	SchemaPayload schemaPayloadBody `json:"schemaPayload"`
}

type schemaPayloadBody struct {
	SchemaName  string       `json:"schemaName"`
	SchemaType  string       `json:"schemaType"`
	Attributes  []schemaAttr `json:"attributes"`
	Description string       `json:"description"`
	OrgID       string       `json:"orgId"`
}

type schemaAttr struct {
	AttributeName string `json:"attributeName"`
	DataType      string `json:"schemaDataType"`
	DisplayName   string `json:"displayName"`
	IsRequired    bool   `json:"isRequired"`
}

type schemaCreateResponse struct {
	Data struct {
		SchemaLedgerID string `json:"schemaLedgerId"`
		SchemaID       string `json:"schemaId"`
		ID             string `json:"id"`
	} `json:"data"`
}

type templateCreateRequest struct {
	Name         string            `json:"name"`
	Format       string            `json:"format"`
	SignerOption  string            `json:"signerOption"`
	CanBeRevoked bool              `json:"canBeRevoked"`
	Template     templateCreateBody `json:"template"`
}

type templateCreateBody struct {
	Vct        string              `json:"vct"`
	Attributes []templateAttribute `json:"attributes"`
}

type templateCreateResponse struct {
	Data struct {
		ID string `json:"id"`
	} `json:"data"`
}

// SaveCustomSchema creates a CREDEBL schema + credential template for a
// verifiably-go custom schema and caches the mapping so IssueToWallet can
// resolve the custom-* ID to the CREDEBL template UUID.
func (a *Adapter) SaveCustomSchema(ctx context.Context, schema vctypes.Schema) error {
	return a.withAuth(ctx, func(ctx context.Context) error {
		_, err := a.createCredeblTemplate(ctx, schema)
		return err
	})
}

// DeleteCustomSchema removes the in-memory custom-* → CREDEBL UUID mapping.
// The CREDEBL template itself is left in place (no delete API exposed).
func (a *Adapter) DeleteCustomSchema(_ context.Context, id string) error {
	a.customTemplates.Delete(id)
	return nil
}

// resolveTemplateID returns the CREDEBL template UUID for a schema.
// For non-custom schemas the ID is already the CREDEBL UUID. For custom-*
// schemas it checks the in-memory cache first, then the live template list
// (handles container restarts), and finally creates the template lazily.
func (a *Adapter) resolveTemplateID(ctx context.Context, schema vctypes.Schema) (string, error) {
	if v, ok := a.customTemplates.Load(schema.ID); ok {
		return v.(string), nil
	}
	// Cache miss — fetch template list and match by name (restart recovery).
	path := fmt.Sprintf("/v1/orgs/%s/oid4vc/%s/template", a.cfg.OrgID, a.cfg.IssuerID)
	var listResp templateListResponse
	if err := a.client.DoJSON(ctx, http.MethodGet, path, nil, &listResp, nil); err == nil {
		for _, t := range listResp.Data {
			if t.Name == schema.Name {
				a.customTemplates.Store(schema.ID, t.ID)
				return t.ID, nil
			}
		}
	}
	// Not found — create lazily and cache.
	return a.createCredeblTemplate(ctx, schema)
}

// createCredeblTemplate calls the CREDEBL API to create a schema + template
// for the given custom schema, stores the result in customTemplates, and
// returns the CREDEBL template UUID.
func (a *Adapter) createCredeblTemplate(ctx context.Context, schema vctypes.Schema) (string, error) {
	sAttrs := make([]schemaAttr, 0, len(schema.FieldsSpec))
	for _, f := range schema.FieldsSpec {
		sAttrs = append(sAttrs, schemaAttr{
			AttributeName: f.Name,
			DataType:      f.Datatype,
			DisplayName:   f.Name,
			IsRequired:    f.Required,
		})
	}
	schemaBody := schemaCreateRequest{
		Type: "json",
		SchemaPayload: schemaPayloadBody{
			SchemaName:  schema.Name,
			SchemaType:  "no_ledger",
			Attributes:  sAttrs,
			Description: schema.Name,
			OrgID:       a.cfg.OrgID,
		},
	}
	var schemaResp schemaCreateResponse
	if err := a.client.DoJSON(ctx, http.MethodPost,
		fmt.Sprintf("/v1/orgs/%s/schemas", a.cfg.OrgID),
		schemaBody, &schemaResp, nil); err != nil {
		return "", fmt.Errorf("credebl create schema: %w", err)
	}
	vct := schemaResp.Data.SchemaLedgerID
	if vct == "" {
		vct = schemaResp.Data.SchemaID
	}
	if vct == "" {
		vct = schemaResp.Data.ID
	}
	if vct == "" {
		return "", fmt.Errorf("credebl: schema creation returned empty id")
	}

	tAttrs := make([]templateAttribute, 0, len(schema.FieldsSpec))
	for _, f := range schema.FieldsSpec {
		tAttrs = append(tAttrs, templateAttribute{Key: f.Name, ValueType: f.Datatype, Disclose: false})
	}
	tmplBody := templateCreateRequest{
		Name:         schema.Name,
		Format:       "dc+sd-jwt",
		SignerOption:  "DID",
		CanBeRevoked: false,
		Template:     templateCreateBody{Vct: vct, Attributes: tAttrs},
	}
	var tmplResp templateCreateResponse
	if err := a.client.DoJSON(ctx, http.MethodPost,
		fmt.Sprintf("/v1/orgs/%s/oid4vc/%s/template", a.cfg.OrgID, a.cfg.IssuerID),
		tmplBody, &tmplResp, nil); err != nil {
		return "", fmt.Errorf("credebl create template: %w", err)
	}
	if tmplResp.Data.ID == "" {
		return "", fmt.Errorf("credebl: template creation returned empty id")
	}
	a.customTemplates.Store(schema.ID, tmplResp.Data.ID)
	return tmplResp.Data.ID, nil
}
