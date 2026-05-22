package handlers

// api_schemas.go — REST API endpoints for custom schema management.
//
// Routes (under /api/v1/schemas, issuer role only):
//
//   POST   /api/v1/schemas         create a custom schema
//   GET    /api/v1/schemas         list custom schemas (owner-scoped)
//   DELETE /api/v1/schemas/{id}    delete a custom schema
//
// Auth: Authorization: Bearer <key>  (same as the rest of /api/v1/).

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/vctypes"
)

type apiCreateSchemaRequest struct {
	Name              string         `json:"name"`
	Desc              string         `json:"desc"`
	Std               string         `json:"std"`
	IssuerDisplayName string         `json:"issuer_display_name"`
	ExtraType         string         `json:"extra_type"`
	IssuerDpg         string         `json:"issuer_dpg,omitempty"`
	Fields            []apiFieldSpec `json:"fields"`
}

type apiFieldSpec struct {
	Name     string `json:"name"`
	Datatype string `json:"datatype"`
	Format   string `json:"format,omitempty"`
	Required bool   `json:"required"`
}

type apiSchemaResult struct {
	ID                string         `json:"id"`
	Name              string         `json:"name"`
	Desc              string         `json:"desc,omitempty"`
	Std               string         `json:"std"`
	IssuerDisplayName string         `json:"issuer_display_name,omitempty"`
	Custom            bool           `json:"custom"`
	Fields            []apiFieldSpec `json:"fields"`
}

// APICreateSchema handles POST /api/v1/schemas.
func (h *H) APICreateSchema(w http.ResponseWriter, r *http.Request) {
	keyName, ok := h.requireAPIAuth(w, r)
	if !ok {
		return
	}
	var req apiCreateSchemaRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		apiError(w, http.StatusBadRequest, "name required")
		return
	}
	if len(req.Fields) == 0 {
		apiError(w, http.StatusBadRequest, "fields required")
		return
	}
	ctx := apiCtx(r, keyName)
	if req.IssuerDpg == "" {
		req.IssuerDpg = h.firstIssuerDPG(ctx)
	}
	std := canonicalStd(req.Std)
	if std == "" {
		std = "w3c_vcdm_2"
	}
	desc := strings.TrimSpace(req.Desc)
	if desc == "" {
		desc = "—"
	}
	schema := vctypes.Schema{
		ID:                "custom-" + strconv.FormatInt(time.Now().UnixNano(), 36),
		Name:              strings.TrimSpace(req.Name),
		Desc:              desc,
		IssuerDisplayName: strings.TrimSpace(req.IssuerDisplayName),
		Std:               std,
		DPGs:              []string{req.IssuerDpg},
		Custom:            true,
		AdditionalTypes:   []string{},
	}
	if et := strings.TrimSpace(req.ExtraType); et != "" {
		schema.AdditionalTypes = []string{et}
	}
	for _, f := range req.Fields {
		if strings.TrimSpace(f.Name) != "" {
			dt := f.Datatype
			if dt == "" {
				dt = "string"
			}
			schema.FieldsSpec = append(schema.FieldsSpec, vctypes.FieldSpec{
				Name:     strings.TrimSpace(f.Name),
				Datatype: dt,
				Format:   f.Format,
				Required: f.Required,
			})
		}
	}
	if len(schema.FieldsSpec) == 0 {
		apiError(w, http.StatusBadRequest, "fields must contain at least one non-blank field name")
		return
	}
	if err := h.Adapter.SaveCustomSchema(ctx, schema); err != nil {
		apiError(w, http.StatusBadGateway, err.Error())
		return
	}
	slog.Info("api: schema created", "id", schema.ID, "name", schema.Name, "api_key", keyName)
	apiJSON(w, http.StatusCreated, schemaToAPIResult(schema))
}

// APIListSchemas handles GET /api/v1/schemas.
// Returns only custom (user-built) schemas scoped to the caller's API key.
func (h *H) APIListSchemas(w http.ResponseWriter, r *http.Request) {
	keyName, ok := h.requireAPIAuth(w, r)
	if !ok {
		return
	}
	ctx := apiCtx(r, keyName)
	schemas, err := h.Adapter.ListAllSchemas(ctx)
	if err != nil {
		apiError(w, http.StatusServiceUnavailable, "backend unavailable: "+err.Error())
		return
	}
	out := make([]apiSchemaResult, 0)
	for _, s := range schemas {
		if !s.Custom {
			continue
		}
		out = append(out, schemaToAPIResult(s))
	}
	apiJSON(w, http.StatusOK, map[string]any{"schemas": out, "total": len(out)})
}

// APIDeleteSchema handles DELETE /api/v1/schemas/{id}.
func (h *H) APIDeleteSchema(w http.ResponseWriter, r *http.Request) {
	keyName, ok := h.requireAPIAuth(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if id == "" {
		apiError(w, http.StatusBadRequest, "id required")
		return
	}
	ctx := apiCtx(r, keyName)
	if err := h.Adapter.DeleteCustomSchema(ctx, id); err != nil {
		apiError(w, http.StatusBadGateway, err.Error())
		return
	}
	slog.Info("api: schema deleted", "id", id, "api_key", keyName)
	apiJSON(w, http.StatusOK, map[string]string{"id": id, "status": "deleted"})
}

// schemaToAPIResult maps a vctypes.Schema to its API wire representation.
func schemaToAPIResult(s vctypes.Schema) apiSchemaResult {
	out := apiSchemaResult{
		ID:                s.ID,
		Name:              s.Name,
		Desc:              s.Desc,
		Std:               s.Std,
		IssuerDisplayName: s.IssuerDisplayName,
		Custom:            s.Custom,
	}
	for _, f := range s.FieldsSpec {
		out.Fields = append(out.Fields, apiFieldSpec{
			Name:     f.Name,
			Datatype: f.Datatype,
			Format:   f.Format,
			Required: f.Required,
		})
	}
	return out
}
