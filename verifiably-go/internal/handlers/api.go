package handlers

// api.go — REST API surface for programmatic credential issuance,
// revocation and OID4VP verification requests.
//
// Routes (all under /api/v1/):
//
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
	"net/http"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/issuance"
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

// authenticate extracts and validates the Bearer token. Returns the key name
// on success. Uses constant-time comparison to avoid timing side-channels.
func (km APIKeyMap) authenticate(r *http.Request) (string, bool) {
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
	name, ok := h.APIKeys.authenticate(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="verifiably"`)
		apiError(w, http.StatusUnauthorized, "invalid or missing API key")
		return "", false
	}
	return name, true
}

// firstIssuerDPG returns the first available issuer DPG name, or "" if none.
func (h *H) firstIssuerDPG(ctx context.Context) string {
	dpgs, err := h.Adapter.ListIssuerDpgs(ctx)
	if err != nil || len(dpgs) == 0 {
		return ""
	}
	for name := range dpgs {
		return name
	}
	return ""
}

// firstVerifierDPG returns the first available verifier DPG name, or "".
func (h *H) firstVerifierDPG(ctx context.Context) string {
	dpgs, err := h.Adapter.ListVerifierDpgs(ctx)
	if err != nil || len(dpgs) == 0 {
		return ""
	}
	for name := range dpgs {
		return name
	}
	return ""
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
		fmt.Printf("api issuance log append %s: %v\n", id, err)
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
	schemas, _ := h.Adapter.ListAllSchemas(ctx)
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
	res, err := h.Adapter.IssueToWallet(ctx, backend.IssueRequest{
		IssuerDpg:   req.IssuerDpg,
		Schema:      schema,
		SubjectData: req.SubjectData,
		Flow:        "pre_auth",
		StatusList:  binding,
	})
	if err != nil {
		apiError(w, http.StatusBadGateway, err.Error())
		return
	}
	credID := h.apiRecordIssuance(keyName, schema, req.IssuerDpg, res.OfferURI, req.SubjectData, binding)
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

// APIIssueBulk handles POST /api/v1/credentials/issue/bulk.
func (h *H) APIIssueBulk(w http.ResponseWriter, r *http.Request) {
	keyName, ok := h.requireAPIAuth(w, r)
	if !ok {
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
	ctx := apiCtx(r, keyName)
	schemas, _ := h.Adapter.ListAllSchemas(ctx)
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
	out := apiIssueBulkResult{Rows: make([]apiBulkRowOut, 0, len(req.Rows))}
	for i, row := range req.Rows {
		binding, berr := h.allocateStatusListBinding(schema)
		if berr != nil {
			out.Rejected++
			out.Rows = append(out.Rows, apiBulkRowOut{Row: i + 1, Status: "failed", Error: berr.Error()})
			continue
		}
		res, ierr := h.Adapter.IssueToWallet(ctx, backend.IssueRequest{
			IssuerDpg:   req.IssuerDpg,
			Schema:      schema,
			SubjectData: row,
			Flow:        "pre_auth",
			StatusList:  binding,
		})
		if ierr != nil {
			out.Rejected++
			out.Rows = append(out.Rows, apiBulkRowOut{Row: i + 1, Status: "failed", Error: ierr.Error()})
			continue
		}
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
	apiJSON(w, http.StatusOK, map[string]any{
		"id":            rec.ID,
		"schema_id":     rec.SchemaID,
		"schema_name":   rec.SchemaName,
		"issuer_dpg":    rec.IssuerDpg,
		"holder_hint":   rec.HolderHint,
		"subject_fields": rec.SubjectFields,
		"offer_uri":     rec.OfferURI,
		"issued_at":     rec.IssuedAt,
		"status":        status,
		"revoked_at":    rec.RevokedAt,
		"status_list":   rec.StatusList,
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

// reinstateStoreForKind returns the store if it supports Reinstate. Kept
// separate from storeForKind which only exposes Revoke.
func (h *H) reinstateStoreForKind(kind string) interface {
	Reinstate(int) error
} {
	switch kind {
	case "bitstring":
		if h.BitstringStore != nil {
			return h.BitstringStore
		}
	case "token":
		if h.TokenStore != nil {
			return h.TokenStore
		}
	}
	return nil
}

// ── Verify request ────────────────────────────────────────────────────────────

type apiVerifyRequest struct {
	SchemaID    string   `json:"schema_id"`
	VerifierDpg string   `json:"verifier_dpg,omitempty"`
	Fields      []string `json:"fields,omitempty"`
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
	if req.SchemaID == "" {
		apiError(w, http.StatusBadRequest, "schema_id required")
		return
	}
	ctx := apiCtx(r, keyName)
	schemas, _ := h.Adapter.ListAllSchemas(ctx)
	schema, ok2 := findSchemaByID(schemas, req.SchemaID)
	if !ok2 {
		apiError(w, http.StatusNotFound, "schema not found: "+req.SchemaID)
		return
	}
	if req.VerifierDpg == "" {
		req.VerifierDpg = h.firstVerifierDPG(ctx)
	}
	if req.VerifierDpg == "" {
		apiError(w, http.StatusServiceUnavailable, "no verifier DPG available")
		return
	}
	fields := req.Fields
	if len(fields) == 0 {
		for _, f := range schema.FieldsSpec {
			fields = append(fields, f.Name)
		}
	}
	tpl := vctypes.OID4VPTemplate{
		Title:          schema.Name,
		Fields:         fields,
		Format:         schema.Std,
		CredentialType: schema.Name,
		Vct:            schema.Vct,
		WireFormat:     "dc+sd-jwt",
		Disclosure:     "selective — SD-JWT VC (dc+sd-jwt)",
	}
	res, err := h.Adapter.RequestPresentation(ctx, backend.PresentationRequest{
		VerifierDpg: req.VerifierDpg,
		TemplateKey: "custom",
		Template:    &tpl,
		Policies:    []string{"signature", "expired", "not-before"},
	})
	if err != nil {
		apiError(w, http.StatusBadGateway, err.Error())
		return
	}
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
