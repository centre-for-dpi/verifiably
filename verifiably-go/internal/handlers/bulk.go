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

// BulkSource swaps the active bulk-source chip and renders the corresponding
// mini-form. Separate endpoint from /issuer/issue/csv so the chip row can
// hx-post it without triggering a CSV upload.
func (h *H) BulkSource(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	source := strings.TrimSpace(r.FormValue("source"))
	switch source {
	case "csv", "api", "db":
		// fall through
	default:
		h.errorToast(w, r, "unknown source: "+source)
		return
	}
	// Enforce the per-DPG whitelist server-side so operators can't reach a
	// source the DPG disclaims by crafting a POST directly (would just fail
	// at issue time with a cryptic error; better to reject up-front).
	dpgs, _ := h.Adapter.ListIssuerDpgs(r.Context())
	if !bulkSourceAllowed(source, bulkSourcesFor(dpgs[sess.IssuerDpg])) {
		h.errorToast(w, r, "source '"+source+"' is not supported by the selected issuer DPG")
		return
	}
	sess.BulkSource = source
	// Re-render the bulk form area with the chosen source's mini-form.
	schemas, err := h.Adapter.ListAllSchemas(issuerCtx(r, sess))
	if err != nil {
		h.errorToast(w, r, "backend unavailable: "+err.Error())
		return
	}
	schema, _ := findSchemaByID(schemas, sess.SchemaID)
	schema = h.resolveFields(schema)
	h.renderFragment(w, r, "fragment_issue_bulk_form", map[string]any{
		"Source": sess.BulkSource,
		"Fields": schemaFieldsOfH(schema),
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

// runBulkIssue is the common tail shared by BulkFromAPI + BulkFromDB (and
// the existing CSV path, via dispatch in SimulateCSV). Calls the adapter
// and renders the preview fragment with the result.
func (h *H) runBulkIssue(w http.ResponseWriter, r *http.Request, sess *Session, rows []map[string]string, label string) {
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
		metrics.Inc("credential_issued_total", "dpg", sess.IssuerDpg, "schema", schema.ID, "status", "error")
		h.errorToast(w, r, err.Error())
		return
	}
	if res.Accepted > 0 {
		metrics.IncN("credential_issued_total", int64(res.Accepted), "dpg", sess.IssuerDpg, "schema", schema.ID, "status", "ok")
	}
	if res.Rejected > 0 {
		metrics.IncN("credential_issued_total", int64(res.Rejected), "dpg", sess.IssuerDpg, "schema", schema.ID, "status", "error")
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
