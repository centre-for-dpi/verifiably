package handlers

import (
	"net/http"
	"strings"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/metrics"
)

// identity.go — the REGISTRAR surface. A registrar (a separate actor from the
// issuer; gated to the standalone admin session) bulk-enrols authoritative
// citizen identities from any data source — CSV / secured API / Postgres /
// Sunbird RC — into the identity registry (certify.identity_registry). It reuses
// the issuer bulk engine's fetchers + column→field mapping verbatim; only the
// SINK differs: each mapped row is upserted as a foundational identity (via
// SubjectProvisioner.UpsertIdentity), NOT a credential claim. The holder later
// ACTIVATES against this registry (see onboard.go) — they never write to it.

// identityFields are the foundational identity attributes a registrar maps a
// data source onto. individualId is the key; the rest feed createMockIdentity
// 1:1 when the holder activates. Order drives the mapping UI.
var identityFields = []string{
	"individualId", "fullName", "givenName", "familyName",
	"dateOfBirth", "gender", "email", "phone",
}

// identityBulkSources is the fixed source palette for the registrar — all four
// (no per-DPG whitelist applies to identity enrolment).
func identityBulkSources() []sourceOption {
	return []sourceOption{
		{Key: "csv", Label: "CSV upload", Hint: "Upload a CSV of citizen identities."},
		{Key: "api", Label: "Secured API", Hint: "Pull identities over HTTPS from a secured API (X-Road, REST, …)."},
		{Key: "db", Label: "Database", Hint: "Run a SELECT against a country-provided postgres database."},
		{Key: "registry", Label: "Sunbird RC registry", Hint: "Read identities from a Sunbird RC entity."},
	}
}

func identitySourceAllowed(s string) bool {
	switch s {
	case "csv", "api", "db", "registry":
		return true
	}
	return false
}

// registrarOK reports whether the session may use the registrar surface (the
// standalone admin session + a configured identity store). On failure it writes
// the appropriate response (redirect for the page, inline error for fragments)
// and returns false.
func (h *H) registrarOK(w http.ResponseWriter, r *http.Request, sess *Session, fragment bool) bool {
	if !sess.IsAdmin {
		if fragment {
			h.identityInlineError(w, r, "Session expired — sign in as the registrar (admin) again.")
		} else {
			h.redirect(w, r, "/admin/login")
		}
		return false
	}
	if h.Subjects == nil {
		msg := "Identity registry not enabled on this deployment (INJI_CERTIFY_DATABASE_URL unset)."
		if fragment {
			h.identityInlineError(w, r, msg)
		} else {
			h.render(w, r, "registrar_identities", h.pageData(sess, map[string]any{"Disabled": msg}))
		}
		return false
	}
	return true
}

func (h *H) identityInlineError(w http.ResponseWriter, r *http.Request, msg string) {
	h.renderFragment(w, r, "fragment_registrar_bulk_error", map[string]any{"Message": msg})
}

// identityAreaData builds the context for fragment_registrar_bulk_area, shared
// by the page (first paint) and IdentityBulkSource (chip switch).
func (h *H) identityAreaData(sess *Session) map[string]any {
	return map[string]any{
		"BulkSources": identityBulkSources(),
		"BulkSource":  sess.IdentityBulkSource,
		"Fields":      identityFields,
		"Registries":  registryProviders(),
	}
}

// ShowRegistrarIdentities renders the registrar's identity-enrolment page.
func (h *H) ShowRegistrarIdentities(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if !sess.IsAdmin {
		h.redirect(w, r, "/admin/login")
		return
	}
	if sess.IdentityBulkSource == "" {
		sess.IdentityBulkSource = "csv"
	}
	body := h.identityAreaData(sess)
	body["Enabled"] = h.Subjects != nil
	h.render(w, r, "registrar_identities", h.pageData(sess, body))
}

// IdentityBulkSource swaps the active source chip and re-renders #identity-area.
func (h *H) IdentityBulkSource(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if !h.registrarOK(w, r, sess, true) {
		return
	}
	source := strings.TrimSpace(r.FormValue("source"))
	if !identitySourceAllowed(source) {
		h.identityInlineError(w, r, "unknown source: "+source)
		return
	}
	sess.IdentityBulkSource = source
	sess.BulkRows, sess.BulkColumns, sess.BulkLabel = nil, nil, ""
	h.renderFragment(w, r, "fragment_registrar_bulk_area", h.identityAreaData(sess))
}

// IdentityBulkPreview is step 1: fetch identity rows from the chosen source,
// detect columns, stash them, and render the column→field mapping for the fixed
// identity fields. Reuses the issuer engine's fetchers + helpers verbatim.
func (h *H) IdentityBulkPreview(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if !h.registrarOK(w, r, sess, true) {
		return
	}
	multipart := strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/")

	var (
		rows   []map[string]string
		header []string
		label  string
		source string
		err    error
	)
	if multipart {
		source = "csv"
		if err = r.ParseMultipartForm(32 << 20); err != nil {
			h.identityInlineError(w, r, "Upload a CSV first.")
			return
		}
	} else {
		if err = r.ParseForm(); err != nil {
			h.identityInlineError(w, r, "Bad form: "+err.Error())
			return
		}
		source = strings.TrimSpace(r.FormValue("source"))
	}
	if !identitySourceAllowed(source) {
		h.identityInlineError(w, r, "Unknown source: "+source)
		return
	}

	switch source {
	case "csv":
		file, _, ferr := r.FormFile("csv_file")
		if ferr != nil {
			h.identityInlineError(w, r, "Choose a CSV file to upload.")
			return
		}
		defer file.Close()
		rows, header, err = parseCSVRows(file)
		label = "csv"
	case "api":
		url := strings.TrimSpace(r.FormValue("api_url"))
		if url == "" {
			h.identityInlineError(w, r, "API URL is required.")
			return
		}
		rows, err = fetchJSONRows(r.Context(), url, strings.TrimSpace(r.FormValue("api_auth")), strings.TrimSpace(r.FormValue("api_limit")))
		label = "api:" + truncateHost(url)
	case "db":
		conn := strings.TrimSpace(r.FormValue("db_conn"))
		query := strings.TrimSpace(r.FormValue("db_query"))
		if conn == "" || query == "" {
			h.identityInlineError(w, r, "Connection string and SELECT query are both required.")
			return
		}
		rows, err = queryDBRows(r.Context(), conn, query)
		label = "db"
	case "registry":
		p, entity := buildRegistryProvider(r, sess)
		if p.URL == "" {
			h.identityInlineError(w, r, "Registry base URL is required (or pick a configured registry).")
			return
		}
		if entity == "" {
			h.identityInlineError(w, r, "Registry entity is required.")
			return
		}
		rows = searchRegistryAll(r.Context(), p, entity)
		if len(rows) == 0 {
			h.identityInlineError(w, r, registryEmptyMessage(r.Context(), p.URL, entity))
			return
		}
		label = "registry:" + entity
	}
	if err != nil {
		h.identityInlineError(w, r, "Fetch failed: "+err.Error())
		return
	}
	if len(rows) == 0 {
		h.identityInlineError(w, r, "No rows returned from the data source — check the connection details and that records exist.")
		return
	}

	truncated := 0
	if len(rows) > maxBulkPreviewRows {
		truncated = len(rows)
		rows = rows[:maxBulkPreviewRows]
	}
	columns := detectColumns(rows, header)
	sess.BulkRows, sess.BulkColumns, sess.BulkLabel = rows, columns, label

	defaults := make(map[string]string, len(identityFields))
	for _, f := range identityFields {
		defaults[f] = defaultColumnFor(f, columns)
	}
	// Help the registrar: if no exact "individualId" column, fall back to the
	// recognised identity-column aliases for that one field.
	if defaults["individualId"] == "" {
		defaults["individualId"] = identityDefault(columns)
	}

	h.renderFragment(w, r, "fragment_registrar_bulk_mapping", map[string]any{
		"Label":     label,
		"Total":     len(rows),
		"Truncated": truncated,
		"Columns":   columns,
		"Sample":    sampleRows(rows, 3),
		"Fields":    identityFields,
		"Defaults":  defaults,
	})
}

// IdentityBulkApply is step 2: remap the stashed rows onto the identity fields
// and run the identity sink.
func (h *H) IdentityBulkApply(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if !h.registrarOK(w, r, sess, true) {
		return
	}
	if err := r.ParseForm(); err != nil {
		h.identityInlineError(w, r, "Bad form: "+err.Error())
		return
	}
	rows := sess.BulkRows
	if len(rows) == 0 {
		h.identityInlineError(w, r, "Preview expired — click Preview &amp; map again.")
		return
	}
	mfields := r.Form["mfield"]
	mcols := r.Form["mcol"]
	mapping := make(map[string]string, len(mfields))
	for i, f := range mfields {
		col := ""
		if i < len(mcols) {
			col = strings.TrimSpace(mcols[i])
		}
		if f != "" && col != "" {
			mapping[f] = col
		}
	}
	newRows := remapRows(rows, mapping)
	label := sess.BulkLabel
	sess.BulkRows, sess.BulkColumns, sess.BulkLabel = nil, nil, ""
	h.runBulkIdentity(w, r, sess, newRows, label)
}

// IdentityRegistryEntities backs the registry "Discover entities" button.
func (h *H) IdentityRegistryEntities(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if !h.registrarOK(w, r, sess, true) {
		return
	}
	if err := r.ParseForm(); err != nil {
		h.renderFragment(w, r, "fragment_registrar_entities", map[string]any{"NeedURL": true})
		return
	}
	p, _ := buildRegistryProvider(r, sess)
	if p.URL == "" {
		h.renderFragment(w, r, "fragment_registrar_entities", map[string]any{"NeedURL": true})
		return
	}
	h.renderFragment(w, r, "fragment_registrar_entities", map[string]any{
		"Entities": sunbirdSchemas(r.Context(), p.URL),
		"URL":      p.URL,
	})
}

// runBulkIdentity is the registrar sink: each mapped row is enrolled as a
// foundational identity in certify.identity_registry, keyed by the raw
// individualId. NO eSignet identity and NO credential claim is created here —
// the holder materialises their eSignet identity (with their own PIN) when they
// ACTIVATE, and credential claims come from the credential registries.
func (h *H) runBulkIdentity(w http.ResponseWriter, r *http.Request, sess *Session, rows []map[string]string, label string) {
	if h.Subjects == nil {
		h.identityInlineError(w, r, "identity registry not enabled (INJI_CERTIFY_DATABASE_URL not set)")
		return
	}
	ctx := r.Context()
	out := make([]backend.BulkRowResult, 0, len(rows))
	enrolled, failed := 0, 0
	for i, row := range rows {
		res := backend.BulkRowResult{Row: i + 1, Subject: row}
		id := injiRowIdentity(row)
		if id == "" {
			res.Status, res.Label = "failed", "(no id)"
			res.Error = "no individualId mapped (map a source column to the individualId field)"
			failed++
			out = append(out, res)
			continue
		}
		res.Label = id
		demo := map[string]string{}
		for _, f := range identityFields {
			if v := strings.TrimSpace(row[f]); v != "" {
				demo[f] = v
			}
		}
		// Need at least one demographic beyond the id for the identity to be useful.
		hasAttr := false
		for k := range demo {
			if k != "individualId" {
				hasAttr = true
				break
			}
		}
		if !hasAttr {
			res.Status = "failed"
			res.Error = "row has no identity attributes (map at least one of: fullName, email, …)"
			failed++
			out = append(out, res)
			continue
		}
		if err := h.Subjects.UpsertIdentity(ctx, id, demo); err != nil {
			res.Status = "failed"
			res.Error = truncateForLogBulk(err.Error(), 200)
			failed++
			out = append(out, res)
			continue
		}
		res.Status = "enrolled"
		enrolled++
		out = append(out, res)
	}
	if enrolled > 0 {
		metrics.IncN("identity_enrolled_total", int64(enrolled), "status", "ok")
	}
	if failed > 0 {
		metrics.IncN("identity_enrolled_total", int64(failed), "status", "error")
	}
	h.renderFragment(w, r, "fragment_registrar_result", map[string]any{
		"Total":    len(rows),
		"Enrolled": enrolled,
		"Failed":   failed,
		"RowsOut":  out,
		"Label":    label,
		"Fields":   identityFields,
	})
}
