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
	ctx, err := a.authCtx(ctx)
	if err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/v1/orgs/%s/oid4vc/%s/template", a.cfg.OrgID, a.cfg.IssuerID)
	var resp templateListResponse
	if err := a.client.DoJSON(ctx, http.MethodGet, path, nil, &resp, nil); err != nil {
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
	ctx, err := a.authCtx(ctx)
	if err != nil {
		return backend.IssueToWalletResult{}, err
	}
	payload := make(map[string]any, len(req.SubjectData))
	for k, v := range req.SubjectData {
		payload[k] = v
	}
	body := offerCreateRequest{
		AuthorizationType: "preAuthorizedCodeFlow",
		PIN:               a.cfg.DefaultPIN,
		Credentials: []offerCredential{
			{TemplateID: req.Schema.ID, Payload: payload},
		},
	}
	path := fmt.Sprintf("/v1/orgs/%s/oid4vc/%s/create-offer", a.cfg.OrgID, a.cfg.IssuerID)
	var resp offerCreateResponse
	if err := a.client.DoJSON(ctx, http.MethodPost, path, body, &resp, nil); err != nil {
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
