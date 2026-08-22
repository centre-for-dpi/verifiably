package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/mdoc"
	"github.com/verifiably/verifiably-go/internal/metrics"
	"github.com/verifiably/verifiably-go/vctypes"
)

type modeData struct {
	Dpg           vctypes.DPG
	SelectedScale string
	SelectedDest  string
	// WalletDestBlocked greys out the "deliver to wallet" option when the
	// current schema can't be delivered to a wallet (Inji Pre-Auth W3C — see
	// injiPreAuthWalletUnsupported). QR-on-PDF stays available.
	WalletDestBlocked bool
	// PdfDestBlocked greys out the QR-on-PDF option when the current schema can't
	// be issued as a PDF (Inji Pre-Auth SD-JWT — see injiPreAuthPdfUnsupported).
	// Wallet stays available. Symmetric to WalletDestBlocked.
	PdfDestBlocked bool
}

// injiPreAuthWalletUnsupported reports whether the DPG+format combination cannot
// be delivered to a wallet over OID4VCI. Inji Certify Pre-Auth issues W3C as
// ldp_vc (JSON-LD); the Credo-TS wallet stores every credential as a compact
// SD-JWT record, so a JSON-LD object throws "undefined is not a function" on
// accept (HEADLESS-PROVEN against centre-for-dpi/vcs-whitelabel-wallet). Only
// QR-on-PDF works for Inji Pre-Auth W3C. SD-JWT and the other DPGs are fine.
func injiPreAuthWalletUnsupported(issuerDpg, std string) bool {
	return issuerDpg == "Inji Certify · Pre-Auth" && strings.HasPrefix(std, "w3c")
}

// injiPreAuthPdfUnsupported reports whether the DPG+format combination cannot be
// issued as a QR-on-PDF. Inji Certify Pre-Auth SD-JWT has no working PDF path
// (only OID4VCI-to-wallet); the operator reported the PDF option produces nothing
// usable. Symmetric to injiPreAuthWalletUnsupported: W3C→PDF-only, SD-JWT→wallet-only.
func injiPreAuthPdfUnsupported(issuerDpg, std string) bool {
	return issuerDpg == "Inji Certify · Pre-Auth" && strings.HasPrefix(std, "sd_jwt")
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
	// Bulk-only DPGs (e.g. Inji auth-code) have no single-subject issuance —
	// the issuer provisions many subjects and holders self-claim. Force
	// Scale=bulk so the greyed single card is never the active selection.
	if data.Dpg.BulkOnly && sess.Scale != "bulk" {
		sess.Scale = "bulk"
		data.SelectedScale = "bulk"
	}
	// Inji Pre-Auth W3C (ldp_vc) can't be delivered to a wallet — grey the wallet
	// option and force QR-on-PDF (F11). Resolve the picked schema's format the
	// same way ShowIssue does; skip silently if it can't be resolved.
	if schemas, err := h.Adapter.ListAllSchemas(issuerCtx(r, sess)); err == nil {
		if schema, ok := findSchemaByID(schemas, sess.SchemaID); ok {
			switch {
			case injiPreAuthWalletUnsupported(sess.IssuerDpg, schema.Std): // W3C → PDF only
				data.WalletDestBlocked = true
				if sess.Dest != "pdf" {
					sess.Dest = "pdf"
					data.SelectedDest = "pdf"
				}
			case injiPreAuthPdfUnsupported(sess.IssuerDpg, schema.Std): // SD-JWT → wallet only (F18)
				data.PdfDestBlocked = true
				if sess.Dest != "wallet" {
					sess.Dest = "wallet"
					data.SelectedDest = "wallet"
				}
			}
		}
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
	// Server-side guard: a bulk-only DPG can never be issued single-subject,
	// even if a crafted POST submits scale=single (the card is greyed client-side).
	if dpgs, err := h.Adapter.ListIssuerDpgs(r.Context()); err == nil && dpgs[sess.IssuerDpg].BulkOnly {
		sess.Scale = "bulk"
	}
	// Server-side guards mirroring the client-side greying: Inji Pre-Auth W3C can't
	// go to a wallet (force PDF, F11); Inji Pre-Auth SD-JWT can't go to PDF (force
	// wallet, F18) — even if a crafted POST submits the blocked dest.
	if schemas, err := h.Adapter.ListAllSchemas(issuerCtx(r, sess)); err == nil {
		if schema, ok := findSchemaByID(schemas, sess.SchemaID); ok {
			switch {
			case injiPreAuthWalletUnsupported(sess.IssuerDpg, schema.Std):
				sess.Dest = "pdf"
			case injiPreAuthPdfUnsupported(sess.IssuerDpg, schema.Std):
				sess.Dest = "wallet"
			}
		}
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
	// DrivingPrivilegeRows is simply [0..n) — Go templates cannot count, so
	// the row indices for the driving_privileges repeater are precomputed.
	DrivingPrivilegeRows []int
	// DrivingPrivilegeValues round-trips the repeater's inputs across a
	// re-render, keyed "<field>_<index>" (e.g. "vehicle_category_code_0").
	DrivingPrivilegeValues map[string]string
	// MaxImageUploadKB is shown in the file input's hint so the limit the
	// server enforces and the limit the operator is told are the same number.
	MaxImageUploadKB int
	Sources          []sourceOption
	// BulkSources lists which bulk-source chips the UI should render, in
	// render order. Derived from the DPG's Kind="bulk_source" capabilities —
	// walt.id declares csv+api+db, Inji Certify Pre-Auth declares csv+db
	// (docs.inji.io lists PostgreSQL + CSV as the supported Data Provider
	// integrations; API is a roadmap item). Legacy DPGs that declare no
	// bulk_source capabilities fall back to all three so existing backends
	// aren't silently blocked.
	BulkSources []sourceOption
	// IsProvision is true for holder-pull DPGs (Inji auth-code) where bulk
	// provisions certify.vc_subject — gates the holder-identity mapping row.
	IsProvision bool
	// Registries are the env-configured Sunbird RC registries (VERIFIABLY_REGISTRIES)
	// offered as a dropdown on the registry source form.
	Registries []registryProvider
	// EntityDefault pre-fills the registry Entity input (= the credential key /
	// Sunbird entity name).
	EntityDefault string
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
	schemas, err := h.Adapter.ListAllSchemas(issuerCtx(r, sess))
	if err != nil {
		h.errorToast(w, r, "backend unavailable: "+err.Error())
		return
	}
	schema, ok := findSchemaByID(schemas, sess.SchemaID)
	if !ok {
		h.errorToast(w, r, "selected schema missing")
		return
	}
	schema = h.resolveFields(schema)
	vals := h.prefillValues(r, schema, sess)
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
		Schema:        schema,
		Scale:         sess.Scale,
		Dest:          sess.Dest,
		IssuerDpg:     sess.IssuerDpg,
		Dpg:           dpg,
		SingleSource:  "manual",
		BulkSource:    bulkSource,
		FieldValues:   vals,
		Fields:        schemaFieldsOfH(schema),
		Sources:       sourcesFromCapabilities(dpg),
		BulkSources:   bulkSources,
		IsProvision:   h.isInjiAuthcode(r.Context(), sess.IssuerDpg),
		Registries:    registryProviders(),
		EntityDefault: sess.SchemaID,
	}
	applyStructuredFieldDefaults(&data, r)
	h.render(w, r, "issuer_issue", h.pageData(sess, data))
}

// prefillValues returns the issuance-form prefill for a schema: the adapter's
// demo/example data with the authenticated citizen's verified OIDC claims
// overlaid on top (identity wins for the fields it covers). Used by every
// handler that renders the single-issue form so National ID prefill is
// consistent across initial render, source switches and PDF preview. When no
// one is authenticated (sess.UserClaims empty) this is exactly the old
// adapter-only behaviour.
func (h *H) prefillValues(r *http.Request, schema vctypes.Schema, sess *Session) map[string]string {
	vals, _ := h.Adapter.PrefillSubjectFields(r.Context(), schema)
	id := identityPrefill(schemaFieldsOfH(schema), sess.UserClaims)
	if len(id) == 0 {
		return vals
	}
	if vals == nil {
		vals = map[string]string{}
	}
	for k, v := range id {
		vals[k] = v
	}
	return vals
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
// normalizeIssuanceTime accepts an RFC3339 timestamp, an HTML datetime-local
// value (2006-01-02T15:04[:05]), or a plain date (2006-01-02) and returns it as
// RFC3339 UTC. Empty or unparseable input yields "".
func normalizeIssuanceTime(s string) string { return normalizeIssuanceTimeTZ(s, 0) }

// normalizeIssuanceTimeTZ is normalizeIssuanceTime with an explicit input zone.
// A bare HTML datetime-local / date value carries no offset, and Go's plain
// time.Parse would assign UTC — pinning a user's local wall-clock (e.g. 17:36)
// to 17:36Z. For a UTC+offset operator that pushes validFrom hours into the
// future, tripping a verifier's not-before gate. offsetEastMin is the minutes
// EAST of UTC the operator selected (e.g. +330 = UTC+05:30); the zone-less
// layouts are interpreted in that fixed zone via ParseInLocation, THEN converted
// to UTC. An RFC3339 input already carries its own zone and is honoured verbatim.
// Empty or unparseable input yields "".
func normalizeIssuanceTimeTZ(s string, offsetEastMin int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// RFC3339 first — it is self-describing, so the selected zone must not
	// override an explicit offset the caller already provided.
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC().Format(time.RFC3339)
	}
	loc := time.FixedZone("user", offsetEastMin*60)
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02T15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, loc); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return ""
}

// isBooleanField reports whether a claim field is a boolean, and is the ONE
// predicate the whole boolean path routes through — the issue form's
// two-input rendering, SubmitIssue's value gathering, and the required-field
// exemption all key off it. Keeping it in one place means the three can never
// disagree about what counts as a boolean, which is the shape of bug this
// area already produced once: the form rendered a checkbox while the server
// read the field as an ordinary string.
func isBooleanField(fs vctypes.FieldSpec) bool { return fs.Datatype == "boolean" }

// isStructuredField reports whether a claim's value is NOT a scalar and so
// cannot travel in the flat map[string]string subject data. Like
// isBooleanField, this is the ONE predicate the structured path routes
// through — the form's rendering, SubmitIssue's value gathering, and the
// required-field check all key off it, so they cannot disagree about which
// fields are structured.
func isStructuredField(fs vctypes.FieldSpec) bool {
	return fs.Format == mdoc.FormatDrivingPrivileges
}

// maxDrivingPrivilegeRows caps how many repeater rows the form renders and
// the handler reads. It is deliberately larger than
// mdoc.DrivingPrivilegesArrayConfigSize: the operator may fill fewer rows
// than the profile's fixed array length (padding handles that), and rendering
// exactly two would make the cap look like a standards limit rather than the
// vendor-profile limit it is.
const maxDrivingPrivilegeRows = 4

// drivingPrivilegeRows reads the repeater inputs the issue form posts —
// dp_<field>_<index> — and returns the entries the operator actually filled.
// Rows left blank are dropped by EncodeDrivingPrivileges, so the form can
// render spare rows without forcing the operator to use them.
//
// Dates are normalized through the same tz-aware helper as every other date
// field, then cut back to the "YYYY-MM-DD" full-date form walt.id's
// `stringToFullDate` conversion expects — an RFC3339 timestamp fails that
// conversion.
func drivingPrivilegeRows(r *http.Request, tzOffset int) []mdoc.DrivingPrivilege {
	var out []mdoc.DrivingPrivilege
	for i := 0; i < maxDrivingPrivilegeRows; i++ {
		suffix := "_" + strconv.Itoa(i)
		code := strings.TrimSpace(r.FormValue("dp_vehicle_category_code" + suffix))
		issue := fullDateOnly(normalizeIssuanceTimeTZ(r.FormValue("dp_issue_date"+suffix), tzOffset))
		expiry := fullDateOnly(normalizeIssuanceTimeTZ(r.FormValue("dp_expiry_date"+suffix), tzOffset))
		if code == "" && issue == "" && expiry == "" {
			continue
		}
		out = append(out, mdoc.DrivingPrivilege{
			VehicleCategoryCode: code,
			IssueDate:           issue,
			ExpiryDate:          expiry,
		})
	}
	return out
}

// fullDateOnly trims an RFC3339 timestamp back to its date part. walt.id's
// `stringToFullDate` conversion parses a bare "YYYY-MM-DD"; handing it a full
// timestamp fails with a DateTimeParseException at signing time.
func fullDateOnly(s string) string {
	if i := strings.IndexByte(s, 'T'); i > 0 {
		return s[:i]
	}
	return s
}

// applyStructuredFieldDefaults fills the template inputs the structured and
// image field renderers need. Called from BOTH render sites (the full page
// and the source-switch fragment) because they share one template: populating
// only the page would make the repeater render zero rows after a source
// switch, silently removing the operator's only way to enter the field.
//
// The repeater's values are echoed back from the request so a submit rejected
// for an unrelated reason (a missing required field elsewhere) re-renders with
// the rows the operator already filled, like every other input on the form.
func applyStructuredFieldDefaults(data *issueData, r *http.Request) {
	data.MaxImageUploadKB = maxImageUploadBytes >> 10
	rows := make([]int, 0, maxDrivingPrivilegeRows)
	for i := 0; i < maxDrivingPrivilegeRows; i++ {
		rows = append(rows, i)
	}
	data.DrivingPrivilegeRows = rows

	vals := make(map[string]string, maxDrivingPrivilegeRows*3)
	for i := 0; i < maxDrivingPrivilegeRows; i++ {
		suffix := "_" + strconv.Itoa(i)
		for _, f := range []string{"vehicle_category_code", "issue_date", "expiry_date"} {
			vals[f+suffix] = strings.TrimSpace(r.FormValue("dp_" + f + suffix))
		}
	}
	data.DrivingPrivilegeValues = vals
}

// isImageField reports whether a claim's value is image BYTES, uploaded as a
// file and sent onward as base64. Same single-predicate discipline as
// isBooleanField / isStructuredField.
func isImageField(fs vctypes.FieldSpec) bool { return fs.Format == mdoc.FormatImage }

// maxImageUploadBytes caps an uploaded image. An ISO portrait is a few KB —
// the standard expects a small face image, not a camera original — but a
// browser will happily post a 12 MB photo, which would be embedded in the
// mdoc and blow past what a QR-delivered credential can carry.
//
// Enforced against the DECODED file size, before base64 expansion, so the
// number in the operator-facing message means what it says.
const maxImageUploadBytes = 512 << 10 // 512 KB

// maxIssueFormMemory bounds what ParseMultipartForm buffers in RAM before
// spilling to a temp file. Comfortably above maxImageUploadBytes so a
// legitimate upload never touches disk.
const maxIssueFormMemory = 2 << 20 // 2 MB

// imageFieldValue resolves an image claim to base64, preferring a freshly
// uploaded file and falling back to the hidden companion input that
// round-trips an earlier upload across a re-render.
//
// It returns base64 of the raw file bytes — NOT a data: URI. walt.id's
// profile maps the field with conversionType "base64StringToByteString" and
// decodes exactly what we send; a "data:image/jpeg;base64," prefix would be
// decoded as part of the payload and corrupt the byte string.
//
// The content type is sniffed from the bytes rather than trusted from the
// multipart header, which a client controls freely.
func imageFieldValue(r *http.Request, name string) (string, error) {
	file, hdr, err := r.FormFile("field_" + name + "__file")
	if err != nil {
		// No new upload — keep whatever the hidden input carried.
		return strings.TrimSpace(r.FormValue("field_" + name)), nil
	}
	defer file.Close()

	if hdr.Size > maxImageUploadBytes {
		return "", fmt.Errorf("%s image is %d KB — the limit is %d KB; use a smaller photo",
			strings.ReplaceAll(name, "_", " "), hdr.Size>>10, maxImageUploadBytes>>10)
	}
	// LimitReader guards the case where Size is absent or lies: it is taken
	// from the multipart header, not measured.
	raw, err := io.ReadAll(io.LimitReader(file, maxImageUploadBytes+1))
	if err != nil {
		return "", fmt.Errorf("could not read the uploaded %s: %v", strings.ReplaceAll(name, "_", " "), err)
	}
	if len(raw) == 0 {
		return strings.TrimSpace(r.FormValue("field_" + name)), nil
	}
	if len(raw) > maxImageUploadBytes {
		return "", fmt.Errorf("%s image exceeds the %d KB limit; use a smaller photo",
			strings.ReplaceAll(name, "_", " "), maxImageUploadBytes>>10)
	}
	switch ct := http.DetectContentType(raw); ct {
	case "image/jpeg", "image/png":
	default:
		return "", fmt.Errorf("%s must be a JPEG or PNG image (got %s)",
			strings.ReplaceAll(name, "_", " "), ct)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// boolFieldValue resolves a boolean claim field to exactly "true" or "false".
//
// An HTML checkbox submits NOTHING when unticked, and the bare string "on"
// (not "true") when ticked. Both are wrong here: the empty case made
// r.FormValue("field_age_over_18") return "" so the required-field check
// rejected a box the operator had actually ticked, and "on" is not what ISO
// 18013-5 (a CBOR boolean) or walt.id's profile mapping (which keys off the
// literals "true"/"false") expects downstream.
//
// The issue form therefore renders a hidden `field_<name>` carrying "false"
// followed by a checkbox `field_<name>__checked` carrying "true". The two
// names are deliberately DISTINCT rather than relying on last-value-wins:
// r.FormValue returns the FIRST value for a repeated key, so a same-named
// pair in document order would always read "false". Reading them separately
// makes the precedence explicit and independent of field ordering.
//
// A checked box wins. Anything else is "false" — including a hand-crafted
// post that omits the hidden input entirely, which keeps the result a valid
// boolean literal rather than an empty string.
func boolFieldValue(r *http.Request, name string) string {
	if v := strings.TrimSpace(r.FormValue("field_" + name + "__checked")); v != "" && v != "false" {
		return "true"
	}
	// Honour an explicit "true" posted directly on the base name too, so an
	// API/bulk caller that sends field_<name>=true (no companion checkbox)
	// still works — the bulk path builds its rows from mapped source columns,
	// not from this form.
	if strings.EqualFold(strings.TrimSpace(r.FormValue("field_"+name)), "true") {
		return "true"
	}
	return "false"
}

// missingRequiredFields returns the names of every Required field the subject
// left empty. Non-required fields may be left blank.
//
// Booleans are exempt from the emptiness test. boolFieldValue always yields
// "true" or "false", and an UNTICKED required boolean is a legitimate answer
// rather than a missing one — `age_over_18=false` is meaningful data about
// the holder, not an unanswered question. Treating "false" as unfilled would
// make a required boolean unsatisfiable in one of its two valid states, which
// is exactly the live-deployment failure this exemption fixes.
//
// Split out of SubmitIssue so the rule is testable directly, without standing
// up a session, an adapter and a full issuance round trip.
// A structured field is satisfied by a non-empty entry in `structured`, not
// by anything in `subject` — it is never written there. Checking it against
// `subject` would report a correctly-filled driving_privileges as missing.
func missingRequiredFields(schema vctypes.Schema, subject map[string]string, structured map[string]json.RawMessage) []string {
	var missing []string
	for _, spec := range schema.FieldsSpec {
		if isBooleanField(spec) {
			continue
		}
		if isStructuredField(spec) {
			if spec.Required && len(structured[spec.Name]) == 0 {
				missing = append(missing, spec.Name)
			}
			continue
		}
		if spec.Required && subject[spec.Name] == "" {
			missing = append(missing, spec.Name)
		}
	}
	return missing
}

func (h *H) SubmitIssue(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	// The issue form posts multipart/form-data so image fields can carry file
	// BYTES (an urlencoded post sends only the filename). ParseMultipartForm
	// populates r.Form with the non-file values too, so every r.FormValue
	// below reads identically to the urlencoded case.
	//
	// It returns ErrNotMultipart for a urlencoded body — which is what an API
	// caller or an older cached page still sends — so fall back rather than
	// failing. Without this fallback the encoding change would break every
	// non-browser caller of this endpoint.
	if err := r.ParseMultipartForm(maxIssueFormMemory); err != nil {
		_ = r.ParseForm()
	}

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

	schemas, err := h.Adapter.ListAllSchemas(issuerCtx(r, sess))
	if err != nil {
		h.errorToast(w, r, "backend unavailable: "+err.Error())
		return
	}
	schema, _ := findSchemaByID(schemas, schemaID)
	schema = h.resolveFields(schema)
	// The operator's local UTC offset (minutes east, from the issue form's
	// timezone selector). datetime-local/date inputs carry no zone, so this tells
	// normalizeIssuanceTimeTZ which wall-clock the entered times are in — else
	// they'd be pinned to UTC and a validFrom would land hours in the future.
	tzOffset, _ := strconv.Atoi(r.FormValue("tz_offset"))
	// Gather subject data from form (falls back to prefill)
	subject := map[string]string{}
	structured := map[string]json.RawMessage{}
	for _, fs := range schema.FieldsSpec {
		if isBooleanField(fs) {
			// Booleans come from a hidden "false" + a checkbox carrying
			// "true", never a single input — see boolFieldValue.
			subject[fs.Name] = boolFieldValue(r, fs.Name)
			continue
		}
		if isImageField(fs) {
			// Image bytes arrive as a file upload and travel onward as
			// base64 — a plain string, so this one DOES belong in `subject`.
			b64, imgErr := imageFieldValue(r, fs.Name)
			if imgErr != nil {
				h.errorToast(w, r, imgErr.Error())
				return
			}
			subject[fs.Name] = b64
			continue
		}
		if isStructuredField(fs) {
			// Structured claims never enter `subject`: it is map[string]string
			// and stringifying an array here is exactly the bug this path
			// exists to fix (TODO.md F4). They travel in StructuredData, which
			// only the mdoc adapter reads.
			// Tell the operator when they filled more categories than the
			// vendor profile can carry, instead of silently dropping the
			// extras. EncodeDrivingPrivileges truncates as a backstop, and a
			// truncation nobody is told about is exactly the class of quiet
			// data loss this whole change set exists to remove: the operator
			// would see a successful issuance and a credential missing a
			// category they entered.
			if filled := drivingPrivilegeRows(r, tzOffset); len(filled) > mdoc.DrivingPrivilegesArrayConfigSize {
				h.errorToast(w, r, fmt.Sprintf(
					"Solo se pueden emitir %d categorías de conducción por credencial (ingresaste %d). El perfil de walt.id declara un arreglo de tamaño fijo — quita las categorías sobrantes.",
					mdoc.DrivingPrivilegesArrayConfigSize, len(filled)))
				return
			}
			raw, encErr := mdoc.EncodeDrivingPrivileges(drivingPrivilegeRows(r, tzOffset))
			if encErr != nil {
				h.errorToast(w, r, encErr.Error())
				return
			}
			if len(raw) > 0 {
				structured[fs.Name] = raw
			}
			continue
		}
		v := strings.TrimSpace(r.FormValue("field_" + fs.Name))
		// Date/datetime fields (e.g. a delegation's valid_until capability
		// expiry) are normalized to RFC3339 UTC so the claim is well-formed
		// regardless of the browser's datetime-local wire format. Every other
		// field is stored verbatim — this stays generic, keyed on the field's
		// declared Format, not its name.
		if fs.Format == "date" || fs.Format == "datetime" {
			v = normalizeIssuanceTimeTZ(v, tzOffset)
		}
		subject[fs.Name] = v
	}
	missing := missingRequiredFields(schema, subject, structured)
	if len(missing) > 0 {
		h.errorToast(w, r, "Fill in required fields: "+strings.Join(missing, ", "))
		return
	}
	req := backend.IssueRequest{
		IssuerDpg:      sess.IssuerDpg,
		Schema:         schema,
		SubjectData:    subject,
		StructuredData: structured,
	}
	// Issuance-time validity window. The adapter pins it into the credential's
	// own envelope — validFrom/validUntil (W3C) or nbf/exp (SD-JWT) — which is
	// what every verifier's temporal gate reads.
	validFrom, validUntil, verr := resolveIssuanceWindow(
		schema,
		normalizeIssuanceTimeTZ(r.FormValue("valid_from"), tzOffset),
		normalizeIssuanceTimeTZ(r.FormValue("valid_until"), tzOffset),
		time.Now(),
	)
	if verr != nil {
		h.errorToast(w, r, verr.Error())
		return
	}
	req.ValidFrom, req.ValidUntil = validFrom, validUntil

	if sess.Dest == "wallet" {
		// Allocate a status-list index BEFORE the issuance call so the
		// adapter can inject credentialStatus / status.status_list into
		// the credential body. The Store persists nextFree on Allocate, so
		// even if the issuance request fails the index is permanently
		// burned — for now we accept the small drift; an Unallocate path
		// would need transactional semantics across Store + walt.id which
		// isn't worth the complexity for a demo.
		binding, allocErr := h.allocateStatusListBinding(issuerDpg, schema)
		if allocErr != nil {
			h.errorToast(w, r, allocErr.Error())
			return
		}
		req.StatusList = binding
		issueStart := time.Now()
		res, err := h.Adapter.IssueToWallet(r.Context(), req)
		metrics.ObserveDuration("adapter_duration_seconds", time.Since(issueStart), "dpg", issuerDpg, "op", "issue")
		if err != nil {
			metrics.Inc("credential_issued_total", "dpg", issuerDpg, "schema", schema.Name, "status", "error")
			h.errorToast(w, r, err.Error())
			return
		}
		metrics.Inc("credential_issued_total", "dpg", issuerDpg, "schema", schema.Name, "status", "ok")
		slog.Info("credential issued to wallet",
			"schema", schema.ID,
			"dpg", sess.IssuerDpg,
			"dest", "wallet",
			"duration_ms", time.Since(issueStart).Milliseconds(),
		)
		h.recordIssuance(sess, schema, sess.IssuerDpg, subject, res.OfferURI, binding)
		h.renderFragment(w, r, "fragment_issue_wallet_result", res)
		return
	}
	// PDF
	// Allocate a status-list index BEFORE the PDF issuance, exactly like the wallet
	// branch above (F16). The PDF path is the ONLY Inji W3C delivery since F11 greyed
	// out wallet for W3C, and the adapter needs the binding to resolve the
	// credentialStatus / status.status_list markers into a real, revocable pointer —
	// without it certify renders the literal ${statusUri}/${statusIdx} and the
	// credential fails verification everywhere.
	binding, allocErr := h.allocateStatusListBinding(issuerDpg, schema)
	if allocErr != nil {
		h.errorToast(w, r, allocErr.Error())
		return
	}
	req.StatusList = binding
	pdfStart := time.Now()
	res, err := h.Adapter.IssueAsPDF(r.Context(), req)
	metrics.ObserveDuration("adapter_duration_seconds", time.Since(pdfStart), "dpg", issuerDpg, "op", "issue")
	if err != nil {
		metrics.Inc("credential_issued_total", "dpg", issuerDpg, "schema", schema.Name, "status", "error")
		h.errorToast(w, r, err.Error())
		return
	}
	metrics.Inc("credential_issued_total", "dpg", issuerDpg, "schema", schema.Name, "status", "ok")
	slog.Info("credential issued as PDF",
		"schema", schema.ID,
		"dpg", sess.IssuerDpg,
		"dest", "pdf",
		"duration_ms", time.Since(pdfStart).Milliseconds(),
	)
	// Record the issuance so the PDF credential shows in /issuer/credentials and is
	// revocable via its allocated status-list index (F17). No offer URI for PDF.
	h.recordIssuance(sess, schema, sess.IssuerDpg, subject, "", binding)
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
	schemas, err := h.Adapter.ListAllSchemas(issuerCtx(r, sess))
	if err != nil {
		h.errorToast(w, r, "backend unavailable: "+err.Error())
		return
	}
	schema, _ := findSchemaByID(schemas, sess.SchemaID)
	schema = h.resolveFields(schema)
	vals := h.prefillValues(r, schema, sess)
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
	applyStructuredFieldDefaults(&data, r)
	h.renderFragment(w, r, "fragment_issue_single_form", data)
}

// PreviewPDF opens the PDF preview modal.
func (h *H) PreviewPDF(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	schemas, err := h.Adapter.ListAllSchemas(issuerCtx(r, sess))
	if err != nil {
		h.errorToast(w, r, "backend unavailable: "+err.Error())
		return
	}
	schema, _ := findSchemaByID(schemas, sess.SchemaID)
	vals := h.prefillValues(r, schema, sess)
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
		if c.Key != "csv" && c.Key != "api" && c.Key != "db" && c.Key != "registry" {
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
