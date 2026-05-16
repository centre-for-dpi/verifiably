package handlers

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/vctypes"
)

type modeData struct {
	Dpg         vctypes.DPG
	SelectedScale string
	SelectedDest  string
}

// ShowIssuanceMode renders the scale + destination choice screen.
func (h *H) ShowIssuanceMode(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if sess.IssuerDpg == "" || sess.SchemaID == "" {
		h.redirect(w, r, "/issuer/dpg")
		return
	}
	dpgs, err := h.Adapter.ListIssuerDpgs(r.Context())
	if err != nil {
		h.errorToast(w, r, err.Error())
		return
	}
	data := modeData{
		Dpg:           dpgs[sess.IssuerDpg],
		SelectedScale: sess.Scale,
		SelectedDest:  sess.Dest,
	}
	// Auto-force dest=wallet if DPG doesn't support PDF
	if !data.Dpg.DirectPDF && sess.Dest == "pdf" {
		sess.Dest = "wallet"
		data.SelectedDest = "wallet"
	}
	h.render(w, r, "issuer_mode", h.pageData(sess, data))
}

// SetIssuanceMode accepts scale/dest POST and redirects to /issuer/issue.
func (h *H) SetIssuanceMode(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if scale := r.FormValue("scale"); scale != "" {
		sess.Scale = scale
	}
	if dest := r.FormValue("dest"); dest != "" {
		sess.Dest = dest
	}
	h.redirect(w, r, "/issuer/issue")
}

type issueData struct {
	Schema       vctypes.Schema
	Scale        string
	Dest         string
	IssuerDpg    string
	Dpg          vctypes.DPG
	SingleSource string // "manual" | "api" | "uin_lookup" | "csv_lookup" | "presentation"
	BulkSource   string // "csv" | "api" | "db" — active chip on the bulk form
	FieldValues  map[string]string
	Fields       []string
	Sources      []sourceOption
	// BulkSources lists which bulk-source chips the UI should render, in
	// render order. Derived from the DPG's Kind="bulk_source" capabilities —
	// walt.id declares csv+api+db, Inji Certify Pre-Auth declares csv+db
	// (docs.inji.io lists PostgreSQL + CSV as the supported Data Provider
	// integrations; API is a roadmap item). Legacy DPGs that declare no
	// bulk_source capabilities fall back to all three so existing backends
	// aren't silently blocked.
	BulkSources []sourceOption
}

// sourceOption is one chip on the issue form's "source" picker. Derived from
// the DPG's declared Capabilities (Kind=="data") so the UI never hardcodes
// vendor names.
type sourceOption struct {
	Key   string
	Label string
	Hint  string
}

// ShowIssue renders the issuance-form screen.
func (h *H) ShowIssue(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if sess.IssuerDpg == "" || sess.SchemaID == "" {
		h.redirect(w, r, "/issuer/dpg")
		return
	}
	schemas, _ := h.Adapter.ListAllSchemas(issuerCtx(r, sess))
	schema, ok := findSchemaByID(schemas, sess.SchemaID)
	if !ok {
		h.errorToast(w, r, "selected schema missing")
		return
	}
	schema = h.resolveFields(schema)
	vals, _ := h.Adapter.PrefillSubjectFields(r.Context(), schema)
	dpgs, _ := h.Adapter.ListIssuerDpgs(r.Context())
	dpg := dpgs[sess.IssuerDpg]
	bulkSource := sess.BulkSource
	if bulkSource == "" {
		bulkSource = "csv"
	}
	bulkSources := bulkSourcesFor(dpg)
	// If the stored BulkSource was hidden for this DPG, fall back to the
	// first allowed source so the form doesn't render an empty chip row
	// when the operator switches DPGs.
	if !bulkSourceAllowed(bulkSource, bulkSources) && len(bulkSources) > 0 {
		bulkSource = bulkSources[0].Key
		sess.BulkSource = bulkSource
	}
	data := issueData{
		Schema:       schema,
		Scale:        sess.Scale,
		Dest:         sess.Dest,
		IssuerDpg:    sess.IssuerDpg,
		Dpg:          dpg,
		SingleSource: "manual",
		BulkSource:   bulkSource,
		FieldValues:  vals,
		Fields:       schemaFieldsOfH(schema),
		Sources:      sourcesFromCapabilities(dpg),
		BulkSources:  bulkSources,
	}
	h.render(w, r, "issuer_issue", h.pageData(sess, data))
}

// sourcesFromCapabilities turns DPG.Capabilities (kind "data") into chip
// options, always prepending "Manual entry".
func sourcesFromCapabilities(dpg vctypes.DPG) []sourceOption {
	out := []sourceOption{
		{Key: "manual", Label: "Enter manually", Hint: "Type the subject fields directly into the form."},
	}
	for _, c := range dpg.Capabilities {
		if c.Kind != "data" {
			continue
		}
		out = append(out, sourceOption{Key: c.Key, Label: c.Title, Hint: c.Body})
	}
	return out
}

// SubmitIssue performs the issuance and returns a result fragment. Rejects
// empty submissions: at least every required field in the schema must be
// filled. Falling through without this check used to produce an offer with
// no claims, which looked exactly like demo data and hid the real issuance.
//
// The handler reads IssuerDpg + SchemaID from the form first, then falls
// back to the session. The form values are rendered as hidden inputs by
// the issue template specifically so the page survives a container
// restart: in-memory sessions get wiped on restart, but an already-loaded
// form still has the originally-selected DPG + schema in its hidden
// fields and submits without a cryptic "unknown DPG: issuer \"\"" error.
func (h *H) SubmitIssue(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	_ = r.ParseForm()

	issuerDpg := r.FormValue("issuer_dpg")
	if issuerDpg == "" {
		issuerDpg = sess.IssuerDpg
	}
	schemaID := r.FormValue("schema_id")
	if schemaID == "" {
		schemaID = sess.SchemaID
	}
	if issuerDpg == "" || schemaID == "" {
		h.errorToast(w, r, "Session expired — click Back and restart from Pick a DPG")
		return
	}
	// Re-sync the session so later pages (result fragment, navigation) see
	// the right values even if they were wiped.
	sess.IssuerDpg = issuerDpg
	sess.SchemaID = schemaID

	schemas, _ := h.Adapter.ListAllSchemas(issuerCtx(r, sess))
	schema, _ := findSchemaByID(schemas, schemaID)
	schema = h.resolveFields(schema)
	// Gather subject data from form (falls back to prefill)
	subject := map[string]string{}
	for _, f := range schemaFieldsOfH(schema) {
		v := strings.TrimSpace(r.FormValue("field_" + f))
		subject[f] = v
	}
	// Validate: every Required field must be non-empty. Non-required fields
	// may be left blank.
	var missing []string
	for _, spec := range schema.FieldsSpec {
		if spec.Required && subject[spec.Name] == "" {
			missing = append(missing, spec.Name)
		}
	}
	if len(missing) > 0 {
		h.errorToast(w, r, "Fill in required fields: "+strings.Join(missing, ", "))
		return
	}
	req := backend.IssueRequest{IssuerDpg: sess.IssuerDpg, Schema: schema, SubjectData: subject}

	if sess.Dest == "wallet" {
		// Allocate a status-list index BEFORE the issuance call so the
		// adapter can inject credentialStatus / status.status_list into
		// the credential body. The Store persists nextFree on Allocate, so
		// even if the issuance request fails the index is permanently
		// burned — for now we accept the small drift; an Unallocate path
		// would need transactional semantics across Store + walt.id which
		// isn't worth the complexity for a demo.
		binding, allocErr := h.allocateStatusListBinding(schema)
		if allocErr != nil {
			h.errorToast(w, r, allocErr.Error())
			return
		}
		req.StatusList = binding
		res, err := h.Adapter.IssueToWallet(r.Context(), req)
		if err != nil {
			h.errorToast(w, r, err.Error())
			return
		}
		slog.Info("credential issued to wallet",
			"schema", schema.ID,
			"dpg", sess.IssuerDpg,
			"dest", "wallet",
		)
		h.recordIssuance(sess, schema, sess.IssuerDpg, subject, res.OfferURI, binding)
		h.renderFragment(w, r, "fragment_issue_wallet_result", res)
		return
	}
	// PDF
	res, err := h.Adapter.IssueAsPDF(r.Context(), req)
	if err != nil {
		h.errorToast(w, r, err.Error())
		return
	}
	slog.Info("credential issued as PDF",
		"schema", schema.ID,
		"dpg", sess.IssuerDpg,
		"dest", "pdf",
	)
	h.renderFragment(w, r, "fragment_issue_pdf_result", map[string]any{
		"Schema":    schema,
		"PDFResult": res,
		"Fields":    schemaFieldsOfH(schema),
	})
}

// SetSingleSource switches the issuance form's source (manual/API/MOSIP/DB/PDI).
func (h *H) SetSingleSource(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	source := r.FormValue("source")
	if source == "" {
		source = "manual"
	}
	schemas, _ := h.Adapter.ListAllSchemas(issuerCtx(r, sess))
	schema, _ := findSchemaByID(schemas, sess.SchemaID)
	schema = h.resolveFields(schema)
	vals, _ := h.Adapter.PrefillSubjectFields(r.Context(), schema)
	dpgs, _ := h.Adapter.ListIssuerDpgs(r.Context())
	dpg := dpgs[sess.IssuerDpg]
	data := issueData{
		Schema:       schema,
		IssuerDpg:    sess.IssuerDpg,
		Dpg:          dpg,
		SingleSource: source,
		FieldValues:  vals,
		Fields:       schemaFieldsOfH(schema),
		Sources:      sourcesFromCapabilities(dpg),
	}
	h.renderFragment(w, r, "fragment_issue_single_form", data)
}

// SimulateCSV parses an uploaded CSV, calls IssueBulk per row, and renders
// the preview fragment with real per-row outcomes. The function name stays
// SimulateCSV for route stability; the "simulate" nature is gone — this is
// a live bulk-issue path.
func (h *H) SimulateCSV(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		h.errorToast(w, r, "Upload a CSV first")
		return
	}
	schemas, _ := h.Adapter.ListAllSchemas(issuerCtx(r, sess))
	schema, _ := findSchemaByID(schemas, sess.SchemaID)
	file, _, err := r.FormFile("csv_file")
	if err != nil {
		h.errorToast(w, r, "Upload a CSV file")
		return
	}
	defer file.Close()
	rows, header, parseErr := parseCSVRows(file)
	if parseErr != nil {
		h.errorToast(w, r, "Parse CSV: "+parseErr.Error())
		return
	}
	res, err := h.Adapter.IssueBulk(r.Context(), backend.IssueBulkRequest{
		IssuerDpg: sess.IssuerDpg,
		Schema:    schema,
		Rows:      rows,
		RowCount:  len(rows),
	})
	if err != nil {
		h.errorToast(w, r, err.Error())
		return
	}
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
		"Label":    "csv",
	})
}

// PreviewPDF opens the PDF preview modal.
func (h *H) PreviewPDF(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	schemas, _ := h.Adapter.ListAllSchemas(issuerCtx(r, sess))
	schema, _ := findSchemaByID(schemas, sess.SchemaID)
	vals, _ := h.Adapter.PrefillSubjectFields(r.Context(), schema)
	res, err := h.Adapter.IssueAsPDF(r.Context(), backend.IssueRequest{
		IssuerDpg: sess.IssuerDpg, Schema: schema, SubjectData: vals,
	})
	if err != nil {
		h.errorToast(w, r, err.Error())
		return
	}
	h.renderFragment(w, r, "fragment_pdf_preview_modal", map[string]any{
		"Schema":    schema,
		"Fields":    schemaFieldsOfH(schema),
		"PDFResult": res,
	})
}

// schemaFieldsOfH returns the field names for a schema. Works for both custom
// and pre-configured schemas because both populate FieldsSpec now.
func schemaFieldsOfH(s vctypes.Schema) []string {
	out := make([]string, 0, len(s.FieldsSpec))
	for _, f := range s.FieldsSpec {
		out = append(out, f.Name)
	}
	return out
}

// bulkSourcesFor returns the ordered list of bulk-source chips the UI should
// render for a given DPG. Reads the DPG's Kind="bulk_source" capabilities
// (in the order they appear in backends.json) and renders only those. A DPG
// with zero bulk_source capabilities falls back to all three — preserves
// behaviour for the mock adapter and any not-yet-annotated backends. Labels
// come straight from the capability's Title; Hint from its Body — so the
// operator sees the same per-DPG rationale the DPG-picker card shows.
func bulkSourcesFor(dpg vctypes.DPG) []sourceOption {
	var out []sourceOption
	for _, c := range dpg.Capabilities {
		if c.Kind != "bulk_source" {
			continue
		}
		if c.Key != "csv" && c.Key != "api" && c.Key != "db" {
			continue
		}
		out = append(out, sourceOption{Key: c.Key, Label: c.Title, Hint: c.Body})
	}
	if len(out) == 0 {
		return []sourceOption{
			{Key: "csv", Label: "CSV upload", Hint: "Operator uploads a CSV file from the browser."},
			{Key: "api", Label: "Secured API", Hint: "Pull rows over HTTPS from a secured API (X-Road, REST, etc.)."},
			{Key: "db", Label: "Database", Hint: "Run a SELECT against a country-provided postgres database."},
		}
	}
	return out
}

// bulkSourceAllowed reports whether a stored session BulkSource is still in
// the DPG's whitelist. Used to reset stale selections when the operator
// switches DPGs.
func bulkSourceAllowed(key string, allowed []sourceOption) bool {
	for _, s := range allowed {
		if s.Key == key {
			return true
		}
	}
	return false
}
