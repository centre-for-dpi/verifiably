package handlers

// bulk.go — bulk-issuance source plumbing.
//
// Bulk issuance used to be CSV-only. This file generalizes the source so the
// UI can pull rows from three kinds of places:
//
//   * csv — operator uploads a CSV through the browser (existing SimulateCSV
//     path; still served by /issuer/issue/csv).
//   * api — operator points us at a JSON-returning HTTP endpoint (X-Road
//     secured bridge, REST API, etc.). The handler GETs the URL, decodes an
//     array of objects, and maps each object's keys to schema field names.
//   * db — operator hands us a postgres connection string + SELECT query.
//     The handler opens a pgx connection, runs the query, and coerces each
//     row's columns to strings. Columns must match the schema's FieldsSpec
//     names.
//
// Every source produces the same `[]map[string]string` of rows, which is
// then fed into Adapter.IssueBulk — so the issuance-side code path is
// identical regardless of origin.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/metrics"
)

// isInjiAuthcode reports whether the named issuer DPG drives the Inji
// auth-code (Flow B) path. For those DPGs the bulk sink provisions
// certify.vc_subject (holders then self-claim via eSignet) instead of
// issuing offers through Adapter.IssueBulk. Mirrors the SchemaApply check
// used in ShowSchemaBrowser/SaveSchema.
func (h *H) isInjiAuthcode(ctx context.Context, dpg string) bool {
	dpgs, err := h.Adapter.ListIssuerDpgs(ctx)
	if err != nil {
		return false
	}
	return dpgs[dpg].SchemaApply == "inji_authcode"
}

// BulkSource swaps the active bulk-source chip and renders the corresponding
// mini-form. Separate endpoint from /issuer/issue/csv so the chip row can
// hx-post it without triggering a CSV upload.
func (h *H) BulkSource(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	source := strings.TrimSpace(r.FormValue("source"))
	switch source {
	case "csv", "api", "db", "registry":
		// fall through
	default:
		h.errorToast(w, r, "unknown source: "+source)
		return
	}
	// Enforce the per-DPG whitelist server-side so operators can't reach a
	// source the DPG disclaims by crafting a POST directly (would just fail
	// at issue time with a cryptic error; better to reject up-front).
	dpgs, _ := h.Adapter.ListIssuerDpgs(r.Context())
	dpg := dpgs[sess.IssuerDpg]
	bulkSources := bulkSourcesFor(dpg)
	if !bulkSourceAllowed(source, bulkSources) {
		h.errorToast(w, r, "source '"+source+"' is not supported by the selected issuer DPG")
		return
	}
	sess.BulkSource = source
	// Re-render the whole #bulk-area (chip-row + mini-form) so the active chip
	// highlight moves to the clicked source AND the form switches in one swap.
	schemas, err := h.Adapter.ListAllSchemas(issuerCtx(r, sess))
	if err != nil {
		h.errorToast(w, r, "backend unavailable: "+err.Error())
		return
	}
	schema, _ := findSchemaByID(schemas, sess.SchemaID)
	schema = h.resolveFields(schema)
	h.renderFragment(w, r, "fragment_issue_bulk_area", map[string]any{
		"BulkSources": bulkSources,
		"BulkSource":  sess.BulkSource,
		"Fields":      schemaFieldsOfH(schema),
		"Dpg":         dpg,
	})
}

// BulkFromAPI GETs a JSON array from the operator-provided URL, optionally
// sending an Authorization header, maps each object to a row, and issues
// the credentials in bulk.
func (h *H) BulkFromAPI(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if err := r.ParseForm(); err != nil {
		h.errorToast(w, r, "bad form: "+err.Error())
		return
	}
	url := strings.TrimSpace(r.FormValue("api_url"))
	if url == "" {
		h.errorToast(w, r, "API URL required")
		return
	}
	authHeader := strings.TrimSpace(r.FormValue("api_auth"))
	limitStr := strings.TrimSpace(r.FormValue("api_limit"))

	rows, err := fetchJSONRows(r.Context(), url, authHeader, limitStr)
	if err != nil {
		h.errorToast(w, r, "API fetch failed: "+err.Error())
		return
	}
	h.runBulkIssue(w, r, sess, rows, "api:"+truncateHost(url))
}

// BulkFromDB opens a postgres connection, runs the provided SELECT, and
// feeds each row to IssueBulk. Operator types the connection string + query
// into the UI. For a demo we trust the operator; a real deployment would
// parameterize the query and lock down which tables are readable.
func (h *H) BulkFromDB(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if err := r.ParseForm(); err != nil {
		h.errorToast(w, r, "bad form: "+err.Error())
		return
	}
	conn := strings.TrimSpace(r.FormValue("db_conn"))
	query := strings.TrimSpace(r.FormValue("db_query"))
	if conn == "" || query == "" {
		h.errorToast(w, r, "connection string and query both required")
		return
	}
	rows, err := queryDBRows(r.Context(), conn, query)
	if err != nil {
		h.errorToast(w, r, "DB query failed: "+err.Error())
		return
	}
	h.runBulkIssue(w, r, sess, rows, "db")
}

// BulkFromRegistry pulls every record from the configured Sunbird RC registry
// (VERIFIABLY_REGISTRIES) and feeds them through the bulk tail. No operator
// input — the registry endpoints are deployment config. Only meaningful for
// Inji auth-code, where runBulkIssue diverts to the vc_subject provision sink;
// each record provisions one subject for holders to self-claim via eSignet.
func (h *H) BulkFromRegistry(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	rows, err := fetchRegistryRows(r.Context())
	if err != nil {
		h.errorToast(w, r, "registry pull failed: "+err.Error())
		return
	}
	h.runBulkIssue(w, r, sess, rows, "registry")
}

// runBulkIssue is the common tail shared by SimulateCSV + BulkFromAPI +
// BulkFromDB (+ BulkFromRegistry). For most DPGs it calls the adapter and
// renders the issue preview. Inji auth-code is holder-pull, so "bulk" means
// provisioning the data-provider table (certify.vc_subject) rather than
// minting offers — those DPGs divert to runBulkProvision.
func (h *H) runBulkIssue(w http.ResponseWriter, r *http.Request, sess *Session, rows []map[string]string, label string) {
	if h.isInjiAuthcode(r.Context(), sess.IssuerDpg) {
		h.runBulkProvision(w, r, sess, rows, label)
		return
	}
	schemas, err := h.Adapter.ListAllSchemas(issuerCtx(r, sess))
	if err != nil {
		h.errorToast(w, r, "backend unavailable: "+err.Error())
		return
	}
	schema, _ := findSchemaByID(schemas, sess.SchemaID)
	schema = h.resolveFields(schema)
	bulkStart := time.Now()
	res, err := h.Adapter.IssueBulk(r.Context(), backend.IssueBulkRequest{
		IssuerDpg: sess.IssuerDpg,
		Schema:    schema,
		Rows:      rows,
		RowCount:  len(rows),
	})
	metrics.ObserveDuration("adapter_duration_seconds", time.Since(bulkStart), "dpg", sess.IssuerDpg, "op", "issue")
	if err != nil {
		metrics.Inc("credential_issued_total", "dpg", sess.IssuerDpg, "schema", schema.Name, "status", "error")
		h.errorToast(w, r, err.Error())
		return
	}
	if res.Accepted > 0 {
		metrics.IncN("credential_issued_total", int64(res.Accepted), "dpg", sess.IssuerDpg, "schema", schema.Name, "status", "ok")
	}
	if res.Rejected > 0 {
		metrics.IncN("credential_issued_total", int64(res.Rejected), "dpg", sess.IssuerDpg, "schema", schema.Name, "status", "error")
	}
	header := schemaFieldsOfH(schema)
	vals, _ := h.Adapter.PrefillSubjectFields(r.Context(), schema)
	h.renderFragment(w, r, "fragment_issue_csv_preview", map[string]any{
		"Schema":   schema,
		"Fields":   schemaFieldsOfH(schema),
		"Values":   vals,
		"Header":   header,
		"Total":    len(rows),
		"Accepted": res.Accepted,
		"Rejected": res.Rejected,
		"Errors":   res.Errors,
		"RowsOut":  res.Rows,
		"Label":    label,
	})
}

// injiIdentityFields are the row columns tried, in order, to find the holder's
// identity id — the value fed to esignetSubjectID (the vc_subject key) and the
// individualId the holder later authenticates as via eSignet.
var injiIdentityFields = []string{"individualId", "individual_id", "uin", "id"}

// injiRowIdentity returns the first non-empty identity column in a bulk row.
func injiRowIdentity(row map[string]string) string {
	for _, k := range injiIdentityFields {
		if v := strings.TrimSpace(row[k]); v != "" {
			return v
		}
	}
	return ""
}

// runBulkProvision is the Inji auth-code bulk sink. Each source row is upserted
// into certify.vc_subject keyed by the eSignet PSU-token (esignetSubjectID),
// so that — once the holder signs in via eSignet (auth-code) — Certify's
// Postgres data-provider reads the row and issues the credential carrying these
// claims. This is Model A: claims only. No eSignet identity is created here
// (real eSignet owns identity); holders self-claim at /holder/wallet/inji.
// Mirrors the per-row report shape of runBulkIssue so the UI table is familiar.
func (h *H) runBulkProvision(w http.ResponseWriter, r *http.Request, sess *Session, rows []map[string]string, label string) {
	if h.Subjects == nil {
		h.errorToast(w, r, "subject provisioning not enabled (INJI_CERTIFY_DATABASE_URL not set)")
		return
	}
	ctx := r.Context()
	schemas, err := h.Adapter.ListAllSchemas(issuerCtx(r, sess))
	if err != nil {
		h.errorToast(w, r, "backend unavailable: "+err.Error())
		return
	}
	schema, _ := findSchemaByID(schemas, sess.SchemaID)
	schema = h.resolveFields(schema)
	fields := schemaFieldsOfH(schema)
	clientID := defaultAuthCodeClientID()
	scope, _ := h.Subjects.CredentialScope(ctx, sess.SchemaID)

	out := make([]backend.BulkRowResult, 0, len(rows))
	accepted, rejected := 0, 0
	for i, row := range rows {
		res := backend.BulkRowResult{Row: i + 1, Subject: row}
		id := injiRowIdentity(row)
		if id == "" {
			res.Status, res.Label = "failed", "(no id)"
			res.Error = "no identity column (expected one of: " + strings.Join(injiIdentityFields, ", ") + ")"
			rejected++
			out = append(out, res)
			continue
		}
		res.Label = id
		// Claims = the credential's declared fields present in the row, so the
		// data-provider's extraction view (which reads claims->>'field' per
		// schema field) stays aligned. If the schema fields can't be resolved,
		// fall back to every non-empty column so provisioning still works.
		claims := map[string]string{}
		if len(fields) > 0 {
			for _, f := range fields {
				if v := strings.TrimSpace(row[f]); v != "" {
					claims[f] = v
				}
			}
		} else {
			for k, v := range row {
				if s := strings.TrimSpace(v); s != "" {
					claims[k] = s
				}
			}
		}
		if len(claims) == 0 {
			res.Status = "failed"
			res.Error = "row has none of the credential's fields: " + strings.Join(fields, ", ")
			rejected++
			out = append(out, res)
			continue
		}
		subjectID := esignetSubjectID(id, clientID)
		if err := h.Subjects.ProvisionSubject(ctx, subjectID, claims); err != nil {
			res.Status = "failed"
			res.Error = truncateForLogBulk(err.Error(), 200)
			rejected++
			out = append(out, res)
			continue
		}
		res.Status = "provisioned"
		accepted++
		out = append(out, res)
	}
	if accepted > 0 {
		metrics.IncN("subject_provisioned_total", int64(accepted), "dpg", sess.IssuerDpg, "schema", schema.Name, "status", "ok")
	}
	if rejected > 0 {
		metrics.IncN("subject_provisioned_total", int64(rejected), "dpg", sess.IssuerDpg, "schema", schema.Name, "status", "error")
	}
	h.renderFragment(w, r, "fragment_issue_provision_preview", map[string]any{
		"Schema":      schema,
		"Fields":      fields,
		"Total":       len(rows),
		"Provisioned": accepted,
		"Failed":      rejected,
		"RowsOut":     out,
		"Label":       label,
		"Scope":       scope,
		"ClientID":    clientID,
	})
}

// fetchJSONRows retrieves a JSON array from url and decodes each element as
// a flat object whose string values become a row. Nested objects are
// serialized back to JSON strings for operator inspection; numeric values
// are stringified via fmt.Sprint. A row limit of 0 means "all rows".
func fetchJSONRows(ctx context.Context, url, authHeader, limitStr string) ([]map[string]string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncateForLogBulk(string(body), 200))
	}
	var raw any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}
	// Accept either a bare array or {"rows": [...]} / {"data": [...]}.
	items, ok := raw.([]any)
	if !ok {
		if obj, isObj := raw.(map[string]any); isObj {
			for _, key := range []string{"rows", "data", "items", "results"} {
				if v, has := obj[key]; has {
					if arr, isArr := v.([]any); isArr {
						items = arr
						ok = true
						break
					}
				}
			}
		}
	}
	if !ok {
		return nil, fmt.Errorf("response is not a JSON array or {rows|data|items|results:[...]}")
	}
	limit := 0
	if limitStr != "" {
		_, _ = fmt.Sscan(limitStr, &limit)
	}
	rows := make([]map[string]string, 0, len(items))
	for i, item := range items {
		if limit > 0 && i >= limit {
			break
		}
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		row := make(map[string]string, len(obj))
		for k, v := range obj {
			row[k] = stringifyAny(v)
		}
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("no rows in response (array had %d items, none were objects)", len(items))
	}
	return rows, nil
}

// queryDBRows opens a pgx connection, runs the SELECT, and coerces every
// column to a string. Connection is closed before return. No transactions —
// we only read.
func queryDBRows(ctx context.Context, conn, query string) ([]map[string]string, error) {
	if !strings.EqualFold(strings.TrimSpace(strings.SplitN(query, " ", 2)[0]), "select") {
		return nil, fmt.Errorf("only SELECT queries allowed")
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	pg, err := pgx.Connect(cctx, conn)
	if err != nil {
		return nil, err
	}
	defer pg.Close(ctx)

	rows, err := pg.Query(cctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols := rows.FieldDescriptions()
	colNames := make([]string, len(cols))
	for i, c := range cols {
		colNames[i] = string(c.Name)
	}

	var out []map[string]string
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			return nil, err
		}
		row := make(map[string]string, len(cols))
		for i, name := range colNames {
			row[name] = stringifyAny(vals[i])
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("query returned 0 rows")
	}
	return out, nil
}

func stringifyAny(v any) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	case time.Time:
		return x.Format("2006-01-02")
	default:
		// Fallback: JSON-encode for nested shapes; fmt.Sprint for scalars.
		if b, err := json.Marshal(v); err == nil {
			s := string(b)
			// Unquote single-string JSON so "abc" → abc.
			if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
				return s[1 : len(s)-1]
			}
			return s
		}
		return fmt.Sprint(v)
	}
}

func truncateForLogBulk(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// truncateHost returns just the host component of a URL for logging labels.
func truncateHost(rawURL string) string {
	// Strip scheme + path crudely for display; keep host[:port].
	s := rawURL
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?"); i >= 0 {
		s = s[:i]
	}
	return s
}
