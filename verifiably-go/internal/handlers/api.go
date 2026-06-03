package handlers

// api.go — REST API surface for programmatic credential issuance,
// revocation and OID4VP verification requests.
//
// Routes (all under /api/v1/):
//
//   GET    /api/v1/catalog                      DPGs, standards, templates (api_catalog.go)
//   POST   /api/v1/schemas                      create custom schema       (api_schemas.go)
//   GET    /api/v1/schemas                      list custom schemas        (api_schemas.go)
//   DELETE /api/v1/schemas/{id}                 delete custom schema       (api_schemas.go)
//   POST   /api/v1/credentials/issue            issue single credential
//   POST   /api/v1/credentials/issue/bulk       issue batch from JSON rows
//   GET    /api/v1/credentials                  list issued (owner-scoped)
//   GET    /api/v1/credentials/{id}             get one issuance record
//   POST   /api/v1/credentials/{id}/revoke      revoke
//   POST   /api/v1/credentials/{id}/reinstate   un-revoke
//   POST   /api/v1/verify/request               create OID4VP request
//   GET    /api/v1/verify/result/{state}        poll verification result
//
// Auth: Authorization: Bearer <key>
// API keys are configured via VERIFIABLY_API_KEYS="name1:key1,name2:key2".
// Each key is scoped in the issuance log as ownerKey "api:<name>".

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/issuance"
	"github.com/verifiably/verifiably-go/internal/metrics"
	"github.com/verifiably/verifiably-go/internal/statuslist"
	"github.com/verifiably/verifiably-go/vctypes"
)

// APIKeyMap maps key-name → secret. Built from VERIFIABLY_API_KEYS at startup.
type APIKeyMap map[string]string

// ParseAPIKeys parses "name1:key1,name2:key2" into an APIKeyMap.
// Entries with empty name or key are silently skipped.
func ParseAPIKeys(s string) APIKeyMap {
	m := APIKeyMap{}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		key := strings.TrimSpace(parts[1])
		if name != "" && key != "" {
			m[name] = key
		}
	}
	return m
}

// Authenticate extracts and validates the Bearer token. Returns the key name
// on success. Uses constant-time comparison to avoid timing side-channels.
func (km APIKeyMap) Authenticate(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", false
	}
	secret := strings.TrimPrefix(auth, "Bearer ")
	for name, key := range km {
		if subtle.ConstantTimeCompare([]byte(key), []byte(secret)) == 1 {
			return name, true
		}
	}
	return "", false
}

// apiOwnerKey is the issuance log ownerKey for a given API key name.
func apiOwnerKey(keyName string) string { return "api:" + keyName }

// apiCtx returns a context enriched with the issuer identity for the given
// API key so the registry scopes custom-schema lookups correctly.
func apiCtx(r *http.Request, keyName string) context.Context {
	return backend.WithIssuerIdentity(r.Context(), apiOwnerKey(keyName))
}

// apiJSON writes v as a JSON response with the given status code.
func apiJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// apiError writes {"error":"<msg>"} with the given status code.
func apiError(w http.ResponseWriter, status int, msg string) {
	apiJSON(w, status, map[string]string{"error": msg})
}

// requireAPIAuth is an inline helper used at the top of every API handler.
// Returns keyName and true on success; writes 401 and returns false otherwise.
func (h *H) requireAPIAuth(w http.ResponseWriter, r *http.Request) (string, bool) {
	if len(h.APIKeys) == 0 {
		apiError(w, http.StatusServiceUnavailable, "API not enabled (VERIFIABLY_API_KEYS not set)")
		return "", false
	}
	name, ok := h.APIKeys.Authenticate(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="verifiably"`)
		apiError(w, http.StatusUnauthorized, "invalid or missing API key")
		return "", false
	}
	return name, true
}

// firstIssuerDPG returns the lexicographically first available issuer DPG name,
// or "" if none. Sorted so parallel requests always pick the same DPG.
func (h *H) firstIssuerDPG(ctx context.Context) string {
	dpgs, err := h.Adapter.ListIssuerDpgs(ctx)
	if err != nil || len(dpgs) == 0 {
		return ""
	}
	names := make([]string, 0, len(dpgs))
	for name := range dpgs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names[0]
}

// firstVerifierDPG returns the lexicographically first available verifier DPG
// name, or "". Sorted so parallel requests always pick the same DPG.
func (h *H) firstVerifierDPG(ctx context.Context) string {
	dpgs, err := h.Adapter.ListVerifierDpgs(ctx)
	if err != nil || len(dpgs) == 0 {
		return ""
	}
	names := make([]string, 0, len(dpgs))
	for name := range dpgs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names[0]
}

// apiRecordIssuance writes an audit-log entry for an API-initiated issuance.
func (h *H) apiRecordIssuance(keyName string, schema vctypes.Schema, issuerDpg, offerURI string, subject map[string]string, binding *backend.StatusListBinding) string {
	if h.IssuanceLog == nil {
		return ""
	}
	id := newIssuanceID()
	hint := ""
	for _, k := range []string{"fullName", "name", "given_name", "id", "individualId"} {
		if v := strings.TrimSpace(subject[k]); v != "" {
			hint = v
			break
		}
	}
	format := schema.Std
	for _, v := range schema.Variants {
		if v.ID == schema.ID {
			format = v.Format
			break
		}
	}
	rec := issuance.IssuedCredential{
		ID:            id,
		SchemaID:      schema.ID,
		SchemaName:    schema.Name,
		Std:           schema.Std,
		Format:        format,
		IssuerDpg:     issuerDpg,
		OwnerKey:      apiOwnerKey(keyName),
		HolderHint:    hint,
		SubjectFields: subject,
		OfferURI:      offerURI,
		IssuedAt:      time.Now().UTC(),
	}
	if binding != nil {
		rec.StatusList = &issuance.StatusListEntry{
			Type:   binding.Type,
			ListID: binding.ListID,
			Index:  binding.Index,
		}
	}
	if _, err := h.IssuanceLog.Append(rec); err != nil {
		slog.Warn("api: issuance log append failed", "id", id, "err", err)
		return ""
	}
	return id
}

// ── Issue single ─────────────────────────────────────────────────────────────

type apiIssueRequest struct {
	SchemaID    string            `json:"schema_id"`
	IssuerDpg   string            `json:"issuer_dpg,omitempty"`
	SubjectData map[string]string `json:"subject_data"`
}

type apiIssueResult struct {
	CredentialID string              `json:"credential_id"`
	OfferURI     string              `json:"offer_uri"`
	PIN          string              `json:"pin,omitempty"`
	Flow         string              `json:"flow"`
	StatusList   *apiStatusListRef   `json:"status_list,omitempty"`
}

type apiStatusListRef struct {
	Type   string `json:"type"`
	ListID string `json:"list_id"`
	Index  int    `json:"index"`
}

// APIIssue handles POST /api/v1/credentials/issue.
func (h *H) APIIssue(w http.ResponseWriter, r *http.Request) {
	keyName, ok := h.requireAPIAuth(w, r)
	if !ok {
		return
	}
	if h.RateLimiter != nil && !h.RateLimiter.Allow(keyName, r) {
		w.Header().Set("Retry-After", "60")
		apiError(w, http.StatusTooManyRequests, "rate limit exceeded — retry in 60 s")
		return
	}
	var req apiIssueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.SchemaID == "" {
		apiError(w, http.StatusBadRequest, "schema_id required")
		return
	}
	ctx := apiCtx(r, keyName)
	schemas, err := h.Adapter.ListAllSchemas(ctx)
	if err != nil {
		apiError(w, http.StatusServiceUnavailable, "backend unavailable: "+err.Error())
		return
	}
	schema, ok2 := findSchemaByID(schemas, req.SchemaID)
	if !ok2 {
		apiError(w, http.StatusNotFound, "schema not found: "+req.SchemaID)
		return
	}
	schema = h.resolveFields(schema)
	if req.IssuerDpg == "" {
		req.IssuerDpg = h.firstIssuerDPG(ctx)
	}
	if req.IssuerDpg == "" {
		apiError(w, http.StatusServiceUnavailable, "no issuer DPG available")
		return
	}
	binding, err := h.allocateStatusListBinding(schema)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "status list: "+err.Error())
		return
	}
	issueStart := time.Now()
	res, err := h.Adapter.IssueToWallet(ctx, backend.IssueRequest{
		IssuerDpg:   req.IssuerDpg,
		Schema:      schema,
		SubjectData: req.SubjectData,
		Flow:        "pre_auth",
		StatusList:  binding,
	})
	issueDur := time.Since(issueStart)
	metrics.ObserveDuration("adapter_duration_seconds", issueDur, "dpg", req.IssuerDpg, "op", "issue")
	if err != nil {
		metrics.Inc("credential_issued_total", "dpg", req.IssuerDpg, "schema", schema.Name, "status", "error")
		apiError(w, http.StatusBadGateway, err.Error())
		return
	}
	metrics.Inc("credential_issued_total", "dpg", req.IssuerDpg, "schema", schema.Name, "status", "ok")
	credID := h.apiRecordIssuance(keyName, schema, req.IssuerDpg, res.OfferURI, req.SubjectData, binding)
	slog.Info("api: credential issued",
		"credential_id", credID,
		"schema", req.SchemaID,
		"dpg", req.IssuerDpg,
		"api_key", keyName,
		"duration_ms", issueDur.Milliseconds(),
	)
	out := apiIssueResult{
		CredentialID: credID,
		OfferURI:     res.OfferURI,
		PIN:          res.PIN,
		Flow:         res.Flow,
	}
	if binding != nil {
		out.StatusList = &apiStatusListRef{Type: binding.Type, ListID: binding.ListID, Index: binding.Index}
	}
	apiJSON(w, http.StatusOK, out)
}

// ── Issue bulk ────────────────────────────────────────────────────────────────

type apiIssueBulkRequest struct {
	SchemaID  string              `json:"schema_id"`
	IssuerDpg string              `json:"issuer_dpg,omitempty"`
	Rows      []map[string]string `json:"rows"`
}

type apiIssueBulkResult struct {
	Accepted int              `json:"accepted"`
	Rejected int              `json:"rejected"`
	Rows     []apiBulkRowOut  `json:"rows"`
}

type apiBulkRowOut struct {
	Row          int    `json:"row"`
	CredentialID string `json:"credential_id,omitempty"`
	OfferURI     string `json:"offer_uri,omitempty"`
	PIN          string `json:"pin,omitempty"`
	Status       string `json:"status"`
	Error        string `json:"error,omitempty"`
}

// maxBulkRows caps the number of rows accepted in a single APIIssueBulk call.
const maxBulkRows = 500

// APIIssueBulk handles POST /api/v1/credentials/issue/bulk.
func (h *H) APIIssueBulk(w http.ResponseWriter, r *http.Request) {
	keyName, ok := h.requireAPIAuth(w, r)
	if !ok {
		return
	}
	if h.RateLimiter != nil && !h.RateLimiter.Allow(keyName, r) {
		w.Header().Set("Retry-After", "60")
		apiError(w, http.StatusTooManyRequests, "rate limit exceeded — retry in 60 s")
		return
	}
	var req apiIssueBulkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.SchemaID == "" {
		apiError(w, http.StatusBadRequest, "schema_id required")
		return
	}
	if len(req.Rows) == 0 {
		apiError(w, http.StatusBadRequest, "rows must not be empty")
		return
	}
	if len(req.Rows) > maxBulkRows {
		apiError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("rows exceeds limit (%d max, got %d)", maxBulkRows, len(req.Rows)))
		return
	}
	ctx := apiCtx(r, keyName)
	schemas, err := h.Adapter.ListAllSchemas(ctx)
	if err != nil {
		apiError(w, http.StatusServiceUnavailable, "backend unavailable: "+err.Error())
		return
	}
	schema, ok2 := findSchemaByID(schemas, req.SchemaID)
	if !ok2 {
		apiError(w, http.StatusNotFound, "schema not found: "+req.SchemaID)
		return
	}
	schema = h.resolveFields(schema)
	if req.IssuerDpg == "" {
		req.IssuerDpg = h.firstIssuerDPG(ctx)
	}
	if req.IssuerDpg == "" {
		apiError(w, http.StatusServiceUnavailable, "no issuer DPG available")
		return
	}
	ctx, bulkCancel := context.WithTimeout(ctx, 5*time.Minute)
	defer bulkCancel()
	out := apiIssueBulkResult{Rows: make([]apiBulkRowOut, 0, len(req.Rows))}
	for i, row := range req.Rows {
		binding, berr := h.allocateStatusListBinding(schema)
		if berr != nil {
			out.Rejected++
			out.Rows = append(out.Rows, apiBulkRowOut{Row: i + 1, Status: "failed", Error: berr.Error()})
			continue
		}
		rowStart := time.Now()
		res, ierr := h.Adapter.IssueToWallet(ctx, backend.IssueRequest{
			IssuerDpg:   req.IssuerDpg,
			Schema:      schema,
			SubjectData: row,
			Flow:        "pre_auth",
			StatusList:  binding,
		})
		metrics.ObserveDuration("adapter_duration_seconds", time.Since(rowStart), "dpg", req.IssuerDpg, "op", "issue")
		if ierr != nil {
			metrics.Inc("credential_issued_total", "dpg", req.IssuerDpg, "schema", schema.Name, "status", "error")
			out.Rejected++
			out.Rows = append(out.Rows, apiBulkRowOut{Row: i + 1, Status: "failed", Error: ierr.Error()})
			continue
		}
		metrics.Inc("credential_issued_total", "dpg", req.IssuerDpg, "schema", schema.Name, "status", "ok")
		credID := h.apiRecordIssuance(keyName, schema, req.IssuerDpg, res.OfferURI, row, binding)
		out.Accepted++
		out.Rows = append(out.Rows, apiBulkRowOut{Row: i + 1, CredentialID: credID, OfferURI: res.OfferURI, PIN: res.PIN, Status: "issued"})
	}
	apiJSON(w, http.StatusOK, out)
}

// ── List credentials ──────────────────────────────────────────────────────────

// APIListCredentials handles GET /api/v1/credentials.
func (h *H) APIListCredentials(w http.ResponseWriter, r *http.Request) {
	keyName, ok := h.requireAPIAuth(w, r)
	if !ok {
		return
	}
	if h.IssuanceLog == nil {
		apiError(w, http.StatusServiceUnavailable, "issuance log not configured")
		return
	}
	q := r.URL.Query()
	items := h.IssuanceLog.List(issuance.Filter{
		OwnerKey: apiOwnerKey(keyName),
		Query:    q.Get("q"),
		State:    q.Get("state"),
		Std:      q.Get("std"),
		Format:   q.Get("format"),
	})
	stats := h.IssuanceLog.Summary()
	apiJSON(w, http.StatusOK, map[string]any{
		"total":    stats.Total,
		"active":   stats.Active,
		"revoked":  stats.Revoked,
		"items":    items,
	})
}

// ── Get one credential ────────────────────────────────────────────────────────

// APIGetCredential handles GET /api/v1/credentials/{id}.
func (h *H) APIGetCredential(w http.ResponseWriter, r *http.Request) {
	keyName, ok := h.requireAPIAuth(w, r)
	if !ok {
		return
	}
	if h.IssuanceLog == nil {
		apiError(w, http.StatusServiceUnavailable, "issuance log not configured")
		return
	}
	id := r.PathValue("id")
	rec, found := h.IssuanceLog.Get(id)
	if !found || rec.OwnerKey != apiOwnerKey(keyName) {
		apiError(w, http.StatusNotFound, "credential not found")
		return
	}
	status := "active"
	if rec.RevokedAt != nil {
		status = "revoked"
	}
	// subject_fields is in-memory only (json:"-" on IssuedCredential prevents
	// PII from being written to the on-disk log). It is populated for the
	// current process lifetime but nil after a container restart.
	apiJSON(w, http.StatusOK, map[string]any{
		"id":             rec.ID,
		"schema_id":      rec.SchemaID,
		"schema_name":    rec.SchemaName,
		"issuer_dpg":     rec.IssuerDpg,
		"holder_hint":    rec.HolderHint,
		"subject_fields": rec.SubjectFields,
		"offer_uri":      rec.OfferURI,
		"issued_at":      rec.IssuedAt,
		"status":         status,
		"revoked_at":     rec.RevokedAt,
		"status_list":    rec.StatusList,
	})
}

// ── Revoke ────────────────────────────────────────────────────────────────────

// APIRevoke handles POST /api/v1/credentials/{id}/revoke.
func (h *H) APIRevoke(w http.ResponseWriter, r *http.Request) {
	keyName, ok := h.requireAPIAuth(w, r)
	if !ok {
		return
	}
	if h.IssuanceLog == nil {
		apiError(w, http.StatusServiceUnavailable, "issuance log not configured")
		return
	}
	id := r.PathValue("id")
	owner := apiOwnerKey(keyName)
	rec, found := h.IssuanceLog.Get(id)
	if !found || rec.OwnerKey != owner {
		apiError(w, http.StatusNotFound, "credential not found")
		return
	}
	if rec.StatusList == nil {
		apiError(w, http.StatusUnprocessableEntity, "credential has no status list binding and cannot be revoked")
		return
	}
	store := h.storeForKind(rec.StatusList.Type)
	if store == nil {
		apiError(w, http.StatusServiceUnavailable, "status list store not configured")
		return
	}
	if err := store.Revoke(rec.StatusList.Index); err != nil {
		apiError(w, http.StatusInternalServerError, "revoke: "+err.Error())
		return
	}
	updated, err := h.IssuanceLog.MarkRevoked(id, owner)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "mark revoked: "+err.Error())
		return
	}
	apiJSON(w, http.StatusOK, map[string]any{
		"id":         updated.ID,
		"status":     "revoked",
		"revoked_at": updated.RevokedAt,
	})
}

// ── Reinstate ─────────────────────────────────────────────────────────────────

// APIReinstate handles POST /api/v1/credentials/{id}/reinstate.
func (h *H) APIReinstate(w http.ResponseWriter, r *http.Request) {
	keyName, ok := h.requireAPIAuth(w, r)
	if !ok {
		return
	}
	if h.IssuanceLog == nil {
		apiError(w, http.StatusServiceUnavailable, "issuance log not configured")
		return
	}
	id := r.PathValue("id")
	owner := apiOwnerKey(keyName)
	rec, found := h.IssuanceLog.Get(id)
	if !found || rec.OwnerKey != owner {
		apiError(w, http.StatusNotFound, "credential not found")
		return
	}
	if rec.StatusList == nil {
		apiError(w, http.StatusUnprocessableEntity, "credential has no status list binding")
		return
	}
	store := h.reinstateStoreForKind(rec.StatusList.Type)
	if store == nil {
		apiError(w, http.StatusServiceUnavailable, "status list store not configured")
		return
	}
	if err := store.Reinstate(rec.StatusList.Index); err != nil {
		apiError(w, http.StatusInternalServerError, "reinstate: "+err.Error())
		return
	}
	updated, err := h.IssuanceLog.MarkReinstate(id, owner)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "mark reinstate: "+err.Error())
		return
	}
	apiJSON(w, http.StatusOK, map[string]any{
		"id":         updated.ID,
		"status":     "active",
		"revoked_at": nil,
	})
}

// reinstateStoreForKind returns the store for the given kind.
func (h *H) reinstateStoreForKind(kind string) statuslist.Backend {
	switch kind {
	case "bitstring":
		return h.BitstringStore
	case "token":
		return h.TokenStore
	}
	return nil
}

// ── Verify request ────────────────────────────────────────────────────────────

type apiVerifyRequest struct {
	SchemaID    string                `json:"schema_id"`
	VerifierDpg string                `json:"verifier_dpg,omitempty"`
	Fields      []string              `json:"fields,omitempty"`
	// Template, when provided, is used verbatim and schema_id is used only to
	// look up display metadata. This lets hub nodes pass the full OID4VP
	// template (disclosure, format, field list) without re-deriving it on the
	// member side.
	Template *vctypes.OID4VPTemplate `json:"template,omitempty"`
}

type apiVerifyRequestResult struct {
	RequestURI string `json:"request_uri"`
	State      string `json:"state"`
}

// APIVerifyRequest handles POST /api/v1/verify/request.
func (h *H) APIVerifyRequest(w http.ResponseWriter, r *http.Request) {
	keyName, ok := h.requireAPIAuth(w, r)
	if !ok {
		return
	}
	var req apiVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.SchemaID == "" && req.Template == nil {
		apiError(w, http.StatusBadRequest, "schema_id or template required")
		return
	}
	ctx := apiCtx(r, keyName)
	if req.VerifierDpg == "" {
		req.VerifierDpg = h.firstVerifierDPG(ctx)
	}
	if req.VerifierDpg == "" {
		apiError(w, http.StatusServiceUnavailable, "no verifier DPG available")
		return
	}

	var tpl vctypes.OID4VPTemplate
	if req.Template != nil {
		tpl = *req.Template
	} else {
		schemas, err := h.Adapter.ListAllSchemas(ctx)
		if err != nil {
			apiError(w, http.StatusServiceUnavailable, "backend unavailable: "+err.Error())
			return
		}
		schema, ok2 := findSchemaByID(schemas, req.SchemaID)
		if !ok2 {
			apiError(w, http.StatusNotFound, "schema not found: "+req.SchemaID)
			return
		}
		fields := req.Fields
		if len(fields) == 0 {
			for _, f := range schema.FieldsSpec {
				fields = append(fields, f.Name)
			}
		}
		tpl = vctypes.OID4VPTemplate{
			Title:          schema.Name,
			Fields:         fields,
			Format:         schema.Std,
			CredentialType: schema.Name,
			Vct:            schema.Vct,
			WireFormat:     "dc+sd-jwt",
			Disclosure:     "selective — SD-JWT VC (dc+sd-jwt)",
		}
	}
	verifyStart := time.Now()
	res, err := h.Adapter.RequestPresentation(ctx, backend.PresentationRequest{
		VerifierDpg: req.VerifierDpg,
		TemplateKey: "custom",
		Template:    &tpl,
		Policies:    []string{"signature", "expired", "not-before"},
	})
	metrics.ObserveDuration("adapter_duration_seconds", time.Since(verifyStart), "dpg", req.VerifierDpg, "op", "verify")
	if err != nil {
		metrics.Inc("verification_requested_total", "dpg", req.VerifierDpg, "schema", tpl.Title, "status", "error")
		apiError(w, http.StatusBadGateway, err.Error())
		return
	}
	metrics.Inc("verification_requested_total", "dpg", req.VerifierDpg, "schema", tpl.Title, "status", "ok")
	apiJSON(w, http.StatusOK, apiVerifyRequestResult{
		RequestURI: res.RequestURI,
		State:      res.State,
	})
}

// ── Verify result ─────────────────────────────────────────────────────────────

// APIVerifyResult handles GET /api/v1/verify/result/{state}.
func (h *H) APIVerifyResult(w http.ResponseWriter, r *http.Request) {
	_, ok := h.requireAPIAuth(w, r)
	if !ok {
		return
	}
	state := r.PathValue("state")
	if state == "" {
		apiError(w, http.StatusBadRequest, "state required")
		return
	}
	res, err := h.Adapter.FetchPresentationResult(r.Context(), state, "")
	if err != nil {
		apiError(w, http.StatusBadGateway, err.Error())
		return
	}
	status := "pending"
	if !res.Pending {
		if res.Valid {
			status = "verified"
		} else {
			status = "failed"
		}
	}
	apiJSON(w, http.StatusOK, map[string]any{
		"status":     status,
		"valid":      res.Valid,
		"pending":    res.Pending,
		"method":     res.Method,
		"format":     res.Format,
		"issuer":     res.Issuer,
		"disclosed":  res.DisclosedFields,
		"checked_at": time.Now().UTC(),
	})
}

// ── Async bulk issuance ───────────────────────────────────────────────────────

// APIIssueBulkAsync handles POST /api/v1/credentials/issue/bulk/async.
// It validates the request synchronously, submits a job to the worker pool,
// and returns HTTP 202 immediately with the job ID. The client tracks
// progress via GET /api/v1/bulk/{jobID} or the SSE stream
// GET /api/v1/bulk/{jobID}/events.
func (h *H) APIIssueBulkAsync(w http.ResponseWriter, r *http.Request) {
	keyName, ok := h.requireAPIAuth(w, r)
	if !ok {
		return
	}
	if h.BulkJobQueue == nil {
		apiError(w, http.StatusServiceUnavailable, "async bulk queue not configured")
		return
	}
	if h.RateLimiter != nil && !h.RateLimiter.Allow(keyName, r) {
		w.Header().Set("Retry-After", "60")
		apiError(w, http.StatusTooManyRequests, "rate limit exceeded — retry in 60 s")
		return
	}
	var req apiIssueBulkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.SchemaID == "" {
		apiError(w, http.StatusBadRequest, "schema_id required")
		return
	}
	if len(req.Rows) == 0 {
		apiError(w, http.StatusBadRequest, "rows must not be empty")
		return
	}
	if len(req.Rows) > maxBulkRows {
		apiError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("rows exceeds limit (%d max, got %d)", maxBulkRows, len(req.Rows)))
		return
	}
	ctx := apiCtx(r, keyName)
	schemas, err := h.Adapter.ListAllSchemas(ctx)
	if err != nil {
		apiError(w, http.StatusServiceUnavailable, "backend unavailable: "+err.Error())
		return
	}
	schema, ok2 := findSchemaByID(schemas, req.SchemaID)
	if !ok2 {
		apiError(w, http.StatusNotFound, "schema not found: "+req.SchemaID)
		return
	}
	schema = h.resolveFields(schema)
	if req.IssuerDpg == "" {
		req.IssuerDpg = h.firstIssuerDPG(ctx)
	}
	if req.IssuerDpg == "" {
		apiError(w, http.StatusServiceUnavailable, "no issuer DPG available")
		return
	}

	// Capture loop variables so the closure is safe to call from a goroutine.
	issuerDpg := req.IssuerDpg
	schemaSnap := schema
	workFn := func(rowCtx context.Context, row map[string]string) error {
		binding, berr := h.allocateStatusListBinding(schemaSnap)
		if berr != nil {
			return berr
		}
		res, ierr := h.Adapter.IssueToWallet(rowCtx, backend.IssueRequest{
			IssuerDpg:   issuerDpg,
			Schema:      schemaSnap,
			SubjectData: row,
			Flow:        "pre_auth",
			StatusList:  binding,
		})
		if ierr != nil {
			metrics.Inc("credential_issued_total", "dpg", issuerDpg, "schema", schemaSnap.Name, "status", "error")
			return ierr
		}
		metrics.Inc("credential_issued_total", "dpg", issuerDpg, "schema", schemaSnap.Name, "status", "ok")
		h.apiRecordIssuance(keyName, schemaSnap, issuerDpg, res.OfferURI, row, binding)
		return nil
	}

	jobID, err := h.BulkJobQueue.Submit(r.Context(), req.Rows, workFn)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "submit job: "+err.Error())
		return
	}
	apiJSON(w, http.StatusAccepted, map[string]any{
		"job_id":     jobID,
		"total":      len(req.Rows),
		"status_url": "/api/v1/bulk/" + jobID,
		"events_url": "/api/v1/bulk/" + jobID + "/events",
	})
}

// APIBulkJobStatus handles GET /api/v1/bulk/{jobID}.
// Returns the current job state as JSON.
func (h *H) APIBulkJobStatus(w http.ResponseWriter, r *http.Request) {
	_, ok := h.requireAPIAuth(w, r)
	if !ok {
		return
	}
	if h.BulkJobQueue == nil {
		apiError(w, http.StatusServiceUnavailable, "async bulk queue not configured")
		return
	}
	jobID := r.PathValue("jobID")
	if jobID == "" {
		apiError(w, http.StatusBadRequest, "jobID required")
		return
	}
	job, found := h.BulkJobQueue.Status(r.Context(), jobID)
	if !found {
		apiError(w, http.StatusNotFound, "job not found: "+jobID)
		return
	}
	apiJSON(w, http.StatusOK, map[string]any{
		"job_id":     job.ID,
		"status":     job.Status,
		"total":      job.Total,
		"done":       job.Done,
		"errors":     job.Errors,
		"error_msg":  job.ErrorMsg,
		"created_at": job.CreatedAt,
		"updated_at": job.UpdatedAt,
	})
}

// APIBulkJobEvents handles GET /api/v1/bulk/{jobID}/events.
// Streams Server-Sent Events until the job finishes or the client disconnects.
// Each event: data: {"job_id":"...","status":"...","total":N,"done":M,"errors":K}\n\n
// If the job is already done when the client connects, one final event is sent
// immediately and the stream closes.
func (h *H) APIBulkJobEvents(w http.ResponseWriter, r *http.Request) {
	_, ok := h.requireAPIAuth(w, r)
	if !ok {
		return
	}
	if h.BulkJobQueue == nil {
		apiError(w, http.StatusServiceUnavailable, "async bulk queue not configured")
		return
	}
	jobID := r.PathValue("jobID")
	if jobID == "" {
		apiError(w, http.StatusBadRequest, "jobID required")
		return
	}
	// Verify the job exists before opening the stream.
	job, found := h.BulkJobQueue.Status(r.Context(), jobID)
	if !found {
		apiError(w, http.StatusNotFound, "job not found: "+jobID)
		return
	}

	flusher, ok2 := w.(http.Flusher)
	if !ok2 {
		apiError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering

	// If the job already finished, send one terminal event and close.
	if job.Status == "done" || job.Status == "error" {
		if b, err := json.Marshal(map[string]any{
			"job_id": job.ID, "status": job.Status,
			"total": job.Total, "done": job.Done, "errors": job.Errors,
		}); err == nil {
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		}
		return
	}

	ch := h.BulkJobQueue.Subscribe(r.Context(), jobID)
	for p := range ch {
		b, err := json.Marshal(p)
		if err != nil {
			continue
		}
		fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
		if p.Status == "done" || p.Status == "error" {
			return
		}
	}
}
