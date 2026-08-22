package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/internal/mdoc"
	"github.com/verifiably/verifiably-go/vctypes"
)

// findSchemaByID scans schemas for one whose ID or any variant ID matches id,
// returning the Schema with the chosen variant applied. The grouped-by-name
// refactor means handlers get one Schema per credential type; looking up by
// variant id therefore has to scan each Schema's Variants list, not just ID.
func findSchemaByID(schemas []vctypes.Schema, id string) (vctypes.Schema, bool) {
	for _, s := range schemas {
		if s.HasVariantID(id) {
			return s.ApplyVariant(id), true
		}
	}
	return vctypes.Schema{}, false
}

// schemaFieldResolver is the optional capability an adapter declares when
// it can enrich a schema's FieldsSpec lazily. ListSchemas deliberately
// returns cheap placeholders so the DPG/schema grid renders fast;
// handlers that need full fields (issue form, verifier field picker)
// call this once for the specific picked schema.
type schemaFieldResolver interface {
	ResolveSchemaFields(schema vctypes.Schema) vctypes.Schema
}

// resolveFields runs the adapter's lazy field resolver if it implements
// schemaFieldResolver, otherwise returns the schema unchanged.
func (h *H) resolveFields(s vctypes.Schema) vctypes.Schema {
	if r, ok := h.Adapter.(schemaFieldResolver); ok {
		return r.ResolveSchemaFields(s)
	}
	return s
}

// schemaHasStd reports whether the schema or any of its variants surface under
// the given Std. Used so the Std filter chip doesn't exclude a card whose
// default variant differs from what the user selected.
func schemaHasStd(s vctypes.Schema, std string) bool {
	if s.Std == std {
		return true
	}
	for _, v := range s.Variants {
		if v.Std == std {
			return true
		}
	}
	return false
}

// promoteVariantOfStd returns a copy of s whose ID + Std have been swapped to
// the first variant matching the given Std. Used when the user filters by a
// specific Std — the card should surface the variant in that format so the
// Select button selects a matching configuration id.
func promoteVariantOfStd(s vctypes.Schema, std string) vctypes.Schema {
	if s.Std == std {
		return s
	}
	for _, v := range s.Variants {
		if v.Std == std {
			return s.ApplyVariant(v.ID)
		}
	}
	return s
}

// ShowSchemaBrowser renders the schema-browse page.
func (h *H) ShowSchemaBrowser(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if sess.IssuerDpg == "" {
		h.redirect(w, r, "/issuer/dpg")
		return
	}
	// Inji auth-code DPGs now flow through the shared wizard like walt.id:
	// schemaBrowserData sources their cards from the issuer's live
	// credential_configs (owner-scoped) since the Inji adapter can't drive
	// ListSchemas. (The owner-scoped /issuer/schema/mine view still exists as
	// a secondary listing; it's just no longer on the wizard path.)
	data := h.schemaBrowserData(w, r, sess)
	h.render(w, r, "issuer_schema", h.pageData(sess, data))
}

type schemaBrowserData struct {
	Schemas      []vctypes.Schema
	Stds         []string
	Filter       string
	Query        string
	ExpandedID   string
	SelectedID   string
	ExpandedJSON string
	// HasAnyCustom is true when the issuer has saved at least one custom
	// schema, regardless of the active filter/query. Lets the template
	// distinguish "no results because filter hides them" from "user has
	// not built any custom schema yet" and pick the right empty-state copy.
	HasAnyCustom bool
	// HasIssueOnlyFormat is true when a displayed card carries a verifier-
	// unfilterable (CanPresent==false) variant — i.e. a ⚠ "issue-only" format
	// is selectable in the current view. Gates the issue-only legend so it
	// shows only for walt.id (the only DPG that sets per-format CanPresent) and
	// only when such a format is actually on screen.
	HasIssueOnlyFormat bool
	// Provisioning is the credential_config key of a schema just saved via the
	// Inji auth-code apply (from ?provisioning=). When set, the grid renders a
	// self-dismissing banner that polls /issuer/schema/ready until certify+eSignet
	// finish restarting and the schema is claimable. ProvName is its display name.
	Provisioning string
	ProvName     string
	// Notice is a soft error banner the page renders inline, used when the
	// vendor's catalog endpoint is briefly unreachable (e.g. walt.id is
	// restarting after a custom-schema save). Custom schemas saved in the
	// session still appear in Schemas; the banner explains why stock walt.id
	// types are temporarily missing. Without this, the old error path called
	// errorToast → http.Error(500) which wrote a plain-text response body
	// THEN the template render appended HTML — the user saw the error
	// message followed by the page, all rendered as one wall of text.
	Notice string
}

// injiFormatToStd maps a Certify credential_format to the Std label the schema
// grid + filter chips use. Mirrors injicertify.formatToStd (unexported there);
// kept tiny and local so handlers don't import the adapter package.
func injiFormatToStd(format string) string {
	switch format {
	case "vc+sd-jwt", "dc+sd-jwt":
		return "sd_jwt_vc (IETF)"
	default: // ldp_vc, jwt_vc_json
		return "w3c_vcdm_2"
	}
}

// injiOwnerSchemas builds schema-grid cards from the issuer's live Inji
// credential_configs (owner-scoped via SubjectStore.ListMyCredentials). The
// Inji adapter can't drive ListSchemas, so the shared browser is fed from the
// subject store instead; each credential maps to a Custom card so it survives
// the customOnly filter and the shared search/filter/select/Continue flow
// drives it exactly like a walt.id schema. FieldsSpec is populated from the
// stored display_order so the card's "Show JSON" preview renders.
func (h *H) injiOwnerSchemas(ctx context.Context, sess *Session) []vctypes.Schema {
	creds, err := h.Subjects.ListMyCredentials(ctx, sessionOwnerKey(sess))
	if err != nil {
		return []vctypes.Schema{}
	}
	out := make([]vctypes.Schema, 0, len(creds))
	for _, c := range creds {
		name := c["displayName"]
		if name == "" {
			name = c["key"]
		}
		desc := "Live Inji Certify credential"
		if c["scope"] != "" {
			desc += " · scope " + c["scope"]
		}
		s := vctypes.Schema{
			ID:     c["key"],
			Name:   name,
			Std:    injiFormatToStd(c["format"]),
			Desc:   desc,
			Custom: true,
		}
		if fields, ferr := h.Subjects.CredentialFields(ctx, c["key"]); ferr == nil {
			for _, fn := range fields {
				s.FieldsSpec = append(s.FieldsSpec, vctypes.FieldSpec{Name: fn, Datatype: "string"})
			}
		}
		out = append(out, s)
	}
	return out
}

func (h *H) schemaBrowserData(w http.ResponseWriter, r *http.Request, sess *Session) schemaBrowserData {
	ctx := issuerCtx(r, sess)
	var schemas []vctypes.Schema
	notice := ""
	if h.isInjiAuthcode(ctx, sess.IssuerDpg) && h.Subjects != nil {
		// Inji auth-code has no walt.id-style catalog; its "schemas" are the
		// issuer's live credential_configs. Source the grid from SubjectStore.
		schemas = h.injiOwnerSchemas(ctx, sess)
	} else {
		var err error
		schemas, err = h.Adapter.ListSchemas(ctx, sess.IssuerDpg)
		if err != nil {
			// Registry.ListSchemas returns the custom-schema slice alongside the
			// error so we can render gracefully. Show a banner instead of
			// blowing up the response.
			notice = transientCatalogNotice(err)
			// Defensive: a stricter caller (no resilience layer) would return
			// nil; treat that as an empty list so the template still renders.
			if schemas == nil {
				schemas = []vctypes.Schema{}
			}
		}
	}
	// Show only user-built schemas in the issuance flow. The walt.id catalog
	// returns its stock credential types alongside any user-saved ones; for
	// the issuer UX we only want the latter. Doing this here (not at the
	// adapter layer) keeps stock schemas reachable for code paths that need
	// them (e.g. config dumps, debugging) without re-plumbing.
	customOnly := schemas[:0]
	for _, s := range schemas {
		if s.Custom {
			customOnly = append(customOnly, s)
		}
	}
	schemas = customOnly
	hasAnyCustom := len(schemas) > 0
	// Build the std-chip list from EVERY variant's Std — after grouping a
	// card may carry several variants, so filtering by Std needs to consider
	// all of them.
	stds := []string{"all"}
	seen := map[string]bool{"all": true}
	for _, s := range schemas {
		if !seen[s.Std] {
			seen[s.Std] = true
			stds = append(stds, s.Std)
		}
		for _, v := range s.Variants {
			if !seen[v.Std] {
				seen[v.Std] = true
				stds = append(stds, v.Std)
			}
		}
	}

	if sess.SchemaFilter == "" {
		sess.SchemaFilter = "all"
	}
	q := strings.ToLower(sess.SchemaQuery)
	filtered := []vctypes.Schema{}
	for _, s := range schemas {
		if sess.SchemaFilter != "all" && !schemaHasStd(s, sess.SchemaFilter) {
			continue
		}
		// When filtering by a specific Std, surface the matching variant as
		// the card's default so the user clicking Select picks a sensible
		// configuration id.
		if sess.SchemaFilter != "all" {
			s = promoteVariantOfStd(s, sess.SchemaFilter)
		}
		if q != "" {
			hay := strings.ToLower(s.Name + " " + s.Desc + " " + s.Std)
			if !strings.Contains(hay, q) {
				continue
			}
		}
		filtered = append(filtered, s)
	}

	// Look up expanded JSON against the full list, not the filtered one,
	// so a currently-expanded card keeps its preview even if filter/search would hide it.
	expandedJSON := ""
	if sess.ExpandedSchemaID != "" {
		for _, s := range schemas {
			if s.ID == sess.ExpandedSchemaID {
				expandedJSON = buildJSONSchema(s)
				break
			}
		}
	}
	// hasIssueOnly is true when a currently-displayed card carries a variant
	// the verifier can't filter for (CanPresent==false) — i.e. a ⚠ format is
	// actually selectable in this view. Only walt.id's catalog populates
	// per-format CanPresent (other DPGs build no variants), so this naturally
	// scopes the issue-only legend to walt.id and hides it when no ⚠ format
	// is on screen.
	hasIssueOnly := false
	for _, s := range filtered {
		for _, v := range s.Variants {
			if !v.CanPresent {
				hasIssueOnly = true
				break
			}
		}
		if hasIssueOnly {
			break
		}
	}
	return schemaBrowserData{
		Schemas:            filtered,
		Stds:               stds,
		Filter:             sess.SchemaFilter,
		Query:              sess.SchemaQuery,
		ExpandedID:         sess.ExpandedSchemaID,
		SelectedID:         sess.SchemaID,
		ExpandedJSON:       expandedJSON,
		Notice:             notice,
		HasAnyCustom:       hasAnyCustom,
		HasIssueOnlyFormat: hasIssueOnly,
		Provisioning:       r.URL.Query().Get("provisioning"),
		ProvName:           r.URL.Query().Get("pname"),
	}
}

// transientCatalogNotice turns a vendor catalog fetch error into a
// human-readable banner. Connection-refused / connection-reset patterns
// almost always mean walt.id is restarting (which the catalog-edit hook
// itself triggers), so we hint at that case explicitly. Anything else
// surfaces the underlying error verbatim so an actual misconfiguration
// (wrong URL, auth failure) doesn't get hidden.
func transientCatalogNotice(err error) string {
	msg := err.Error()
	if strings.Contains(msg, "connection refused") || strings.Contains(msg, "connection reset") {
		return "Walt.id catalog is briefly unavailable (issuer-api may be restarting after a custom-schema save). Refresh in a few seconds."
	}
	return "Couldn't fetch catalog from walt.id: " + msg
}

// SchemaSearch handles HTMX search requests. Updates session query and returns the list fragment.
func (h *H) SchemaSearch(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	sess.SchemaQuery = r.URL.Query().Get("q")
	data := h.schemaBrowserData(w, r, sess)
	h.renderFragment(w, r, "fragment_schema_list", data)
}

// SetSchemaFilter updates the active chip filter.
func (h *H) SetSchemaFilter(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	f := r.FormValue("filter")
	if f == "" {
		f = r.URL.Query().Get("filter")
	}
	if f == "" {
		f = "all"
	}
	sess.SchemaFilter = f
	data := h.schemaBrowserData(w, r, sess)
	// Re-render the whole browser body so chip active state + list stay in sync
	h.renderFragment(w, r, "fragment_schema_browser_body", data)
}

// ToggleSchemaExpand toggles a schema card's expanded state and re-renders the list.
func (h *H) ToggleSchemaExpand(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	id := r.FormValue("id")
	if sess.ExpandedSchemaID == id {
		sess.ExpandedSchemaID = ""
	} else {
		sess.ExpandedSchemaID = id
	}
	data := h.schemaBrowserData(w, r, sess)
	h.renderFragment(w, r, "fragment_schema_list", data)
}

// SelectSchema marks a schema as chosen for the downstream issuance flow.
// Re-renders the browser body AND pushes an OOB update for the page-level
// Continue button (its enabled state depends on SelectedID).
func (h *H) SelectSchema(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	id := r.FormValue("id")
	sess.SchemaID = id
	data := h.schemaBrowserData(w, r, sess)
	w.Header().Set("HX-Trigger", `{"toast":"Schema selected — click Continue"}`)
	h.renderFragments(w, r, data, "fragment_schema_browser_body", "fragment_schema_continue_oob")
}

// ShowSchemaBuilder renders the schema-builder page.
func (h *H) ShowSchemaBuilder(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if sess.IssuerDpg == "" {
		h.redirect(w, r, "/issuer/dpg")
		return
	}
	// Default: two blank fields
	data := builderData{
		Fields:        []vctypes.FieldSpec{{Datatype: "string", Required: true}, {Datatype: "string", Required: true}},
		Std:           "w3c_vcdm_2",
		Scenarios:     delegationScenarios,
		KnownDocTypes: mdoc.KnownDocTypes(),
	}
	data.PreviewJSON = buildJSONSchema(currentBuilderSchema(sess, data))
	h.render(w, r, "issuer_schema_builder", h.pageData(sess, data))
}

type builderData struct {
	Name              string
	Desc              string
	IssuerDisplayName string
	ExtraType         string
	Std               string
	Fields            []vctypes.FieldSpec
	PreviewJSON       string
	Delegation        bool   // delegated-access credential (carries a capability)
	Expiry            bool   // opt-in: this credential expires (adds a valid_until datetime claim)
	Scenario          string // selected delegation scenario key (poa/director/teacher/…)
	Scenarios         []delegationScenario
	// DocType is the selected ISO docType when Std == "mso_mdoc" — e.g.
	// "org.iso.18013.5.1.mDL". Empty when no docType has been picked yet
	// (or the format isn't mso_mdoc). Drives which mandatory fields get
	// preloaded and locked; see mdoc.MandatoryFields.
	DocType string
	// KnownDocTypes lists the selector's options. Populated on every
	// builder render so the template can draw the dropdown regardless of
	// which handler produced this builderData.
	KnownDocTypes []mdoc.DocTypeInfo
	// BlankLangRows[fieldIdx] is how many EMPTY language rows that field
	// should render below its filled ones.
	//
	// A language row with a blank locale or a blank label deliberately
	// produces no FieldSpec.Labels entry (absent means "derive from the
	// identifier" downstream), so such a row cannot survive a round trip
	// through the map alone — the operator would click "Add language", the
	// form would re-render, and the new row would have vanished. This
	// carries the count separately so a just-added, not-yet-filled row
	// persists across the re-renders the builder does on every keystroke.
	BlankLangRows map[int]int
}

// blankRowsFor reports how many empty language rows field i should render.
// A nil map (any handler that didn't populate it) yields zero, so every
// non-builder caller renders only the rows the labels map produces.
func (d builderData) blankRowsFor(i int) int { return d.BlankLangRows[i] }

// delegationScenario is a real-world delegated-access relationship preset so an
// operator picks "Power of Attorney" or "Teacher" rather than hand-assembling the
// abstract capability schema. It shapes the credential's identity + field set and
// surfaces the suggested issue-time role/action values as inline guidance.
type delegationScenario struct {
	Key, Label, TypeName, Name, Desc string
	Role, Actions                    string
	ExtraFields                      []vctypes.FieldSpec
}

var delegationScenarios = []delegationScenario{
	{Key: "poa", Label: "Lawyer — power of attorney for a person/entity", TypeName: "PowerOfAttorney",
		Name: "Power of Attorney", Desc: "An attorney is authorised to act on behalf of a client.",
		Role: "Attorney", Actions: "represent, sign, file",
		ExtraFields: []vctypes.FieldSpec{{Name: "matterReference", Datatype: "string"}}},
	{Key: "director", Label: "Director — acts for a business", TypeName: "DirectorAuthority",
		Name: "Company Director Authority", Desc: "A director is authorised to bind and transact for a company.",
		Role: "Director", Actions: "bind, sign, transact",
		ExtraFields: []vctypes.FieldSpec{{Name: "companyRegistrationNumber", Datatype: "string"}}},
	{Key: "teacher", Label: "Teacher — acts for a student", TypeName: "TeacherDelegation",
		Name: "Teacher Delegation", Desc: "A teacher is authorised to manage records for a student.",
		Role: "Teacher", Actions: "viewRecords, submitGrades",
		ExtraFields: []vctypes.FieldSpec{{Name: "institution", Datatype: "string"}}},
	{Key: "guardian", Label: "Parent / guardian — acts for a minor", TypeName: "GuardianConsent",
		Name: "Parental / Guardian Consent", Desc: "A guardian is authorised to consent and collect on behalf of a minor.",
		Role: "Guardian", Actions: "consent, collect, authorize"},
	{Key: "healthcare", Label: "Healthcare proxy — acts for a patient", TypeName: "HealthcareProxy",
		Name: "Healthcare Proxy", Desc: "A healthcare agent is authorised to consent to treatment for a patient.",
		Role: "HealthcareAgent", Actions: "consent:treatment, access:records"},
}

func scenarioByKey(k string) (delegationScenario, bool) {
	for _, s := range delegationScenarios {
		if s.Key == k {
			return s, true
		}
	}
	return delegationScenario{}, false
}

// applyDelegationPreset configures the builder for a delegated-access credential:
// SD-JWT so the capability is carried as flat, evaluator-readable top-level claims,
// the DelegatedAccessCredential type, and the capability fields (onBehalfOf +
// allowedAction the verifier's evaluator keys off; role + valid_until for display/caveat).
func applyDelegationPreset(d *builderData) {
	d.Std = "sd_jwt_vc (IETF)"
	// Delegation expiry (`valid_until`) is OPT-IN — NOT a forced field. It is added
	// only when the operator ticks "This credential expires" (Expiry), which
	// currentBuilderSchema appends as a datetime field. The preset must not force it
	// on: an issuer shouldn't discover a valid_until field they never created, which
	// (unprovisioned) Certify renders as ${valid_until} and the holder's wallet then
	// rejects at claim time. The capability fields below ARE the delegation's
	// semantics (onBehalfOf/role/allowedAction); the evaluator reads valid_until only
	// when it is present.
	base := []vctypes.FieldSpec{
		{Name: "onBehalfOf", Datatype: "string", Required: true},
		{Name: "role", Datatype: "string"},
		{Name: "allowedAction", Datatype: "string", Required: true},
	}
	// A recognised scenario FORCES its identity + fields so switching scenarios
	// updates the form; the generic preset GUARDS so a custom operator's edits survive.
	if sc, ok := scenarioByKey(d.Scenario); ok {
		d.ExtraType = sc.TypeName
		d.Name = sc.Name
		d.Desc = sc.Desc + " (suggested role: " + sc.Role + "; allowedAction: " + sc.Actions + ")"
		d.Fields = append(base, sc.ExtraFields...)
		return
	}
	if strings.TrimSpace(d.ExtraType) == "" {
		d.ExtraType = "DelegatedAccessCredential"
	}
	if strings.TrimSpace(d.Name) == "" {
		d.Name = "Delegated Access Credential"
	}
	if strings.TrimSpace(d.Desc) == "" {
		d.Desc = "Delegated-access capability — the holder acts onBehalfOf a subject"
	}
	d.Fields = base
}

// BuildDelegationToggle re-renders the builder form when the delegated-access
// toggle changes — applying the capability preset when it is turned on.
//
// POST /issuer/schema/build/delegation
func (h *H) BuildDelegationToggle(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	_ = r.ParseForm()
	data := extractBuilderData(r)
	if data.Delegation {
		applyDelegationPreset(&data)
	}
	data.PreviewJSON = buildJSONSchema(currentBuilderSchema(sess, data))
	h.renderFragment(w, r, "fragment_schema_builder_form", data)
}

// BuildStdChange re-renders the builder form when the Format (`std`) selector
// changes.
//
// The <select name="std"> used to carry no htmx attributes of its own, so
// changing it only fired the FORM's hx-trigger, which posts to
// /issuer/schema/build/preview and swaps #json-preview — the JSON panel, not
// the form. The docType block is behind {{if eq .Std "mso_mdoc"}}, so picking
// "ISO mDL" left the docType selector invisible and the standard's mandatory
// fields never loaded. (Deleting a field appeared to "fix" it only because
// RemoveSchemaField re-renders the whole form.) This is the sibling of
// BuildDelegationToggle / BuildDocTypeChange: re-render
// fragment_schema_builder_form with fresh builder data.
//
// Field preservation on a format switch — what happens to rows the operator
// already typed:
//   - Switching TO mso_mdoc: the docType defaults to the first entry in
//     mdoc.KnownDocTypes() (nothing is selected yet, and the <select> renders
//     with the first option pre-selected, so the data and the markup must
//     agree — otherwise the form shows mDL while the builder holds ""), which
//     preloads that docType's mandatory fields. extractBuilderData's merge
//     already APPENDS every submitted non-mandatory row after the mandatory
//     set, so the operator's own fields are kept, not discarded; only rows
//     that collide by name with a mandatory element are replaced by the
//     canonical (locked, Required) version.
//   - Switching AWAY from mso_mdoc: fields are left exactly as submitted. The
//     previously-preloaded ISO rows stay as ordinary editable fields rather
//     than vanishing — silently deleting eleven rows an operator may have
//     since edited would lose work, and they can remove any they don't want
//     with the existing × button.
//
// POST /issuer/schema/build/std
func (h *H) BuildStdChange(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	_ = r.ParseForm()
	data := extractBuilderData(r)
	data.PreviewJSON = buildJSONSchema(currentBuilderSchema(sess, data))
	h.renderFragment(w, r, "fragment_schema_builder_form", data)
}

// BuildDocTypeChange re-renders the builder form when the mdoc docType
// selector changes. Unlike the plain preview endpoint (which only swaps
// #json-preview), this must refresh the field rows themselves: picking a
// docType preloads and locks that standard's mandatory fields (done inside
// extractBuilderData), and those rows have to actually appear for the lock
// to be visible — an operator can't tell a field is mandatory from the JSON
// preview alone. Mirrors BuildDelegationToggle/AddSchemaField/
// RemoveSchemaField, which re-render the same fragment for the same reason.
//
// POST /issuer/schema/build/doctype
func (h *H) BuildDocTypeChange(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	_ = r.ParseForm()
	data := extractBuilderData(r)
	data.PreviewJSON = buildJSONSchema(currentBuilderSchema(sess, data))
	h.renderFragment(w, r, "fragment_schema_builder_form", data)
}

// SchemaPreview is called on every keystroke in the builder — returns the updated JSON preview
// and re-renders the field rows if the fields array changed (add/remove).
func (h *H) SchemaPreview(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	data := extractBuilderData(r)
	data.PreviewJSON = buildJSONSchema(currentBuilderSchema(sess, data))
	h.renderFragment(w, r, "fragment_schema_preview", data)
}

// AddSchemaField adds a blank field row and re-renders.
func (h *H) AddSchemaField(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	_ = r.ParseForm()
	data := extractBuilderData(r)
	data.Fields = append(data.Fields, vctypes.FieldSpec{Datatype: "string"})
	data.PreviewJSON = buildJSONSchema(currentBuilderSchema(sess, data))
	h.renderFragment(w, r, "fragment_schema_builder_form", data)
}

// AddFieldLanguage appends one empty language row to a single field and
// re-renders the builder form — the same htmx round-trip pattern as
// AddSchemaField / RemoveSchemaField / BuildDelegationToggle.
//
// It has to be a server round-trip rather than a bit of client-side DOM
// cloning because the row's input NAMES are index-derived
// (field_lang_N_J / field_label_N_J); the server is what knows what J the
// next row gets, and re-rendering the whole form keeps every other row's
// indices consistent with it.
//
// POST /issuer/schema/build/add-language  (idx = the field's row index)
func (h *H) AddFieldLanguage(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	_ = r.ParseForm()
	data := extractBuilderData(r)
	idx, err := strconv.Atoi(r.FormValue("idx"))
	if err == nil && idx >= 0 && idx < len(data.Fields) {
		if data.BlankLangRows == nil {
			data.BlankLangRows = map[int]int{}
		}
		data.BlankLangRows[idx]++
	}
	data.PreviewJSON = buildJSONSchema(currentBuilderSchema(sess, data))
	h.renderFragment(w, r, "fragment_schema_builder_form", data)
}

// RemoveSchemaField removes a field row by index.
func (h *H) RemoveSchemaField(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	_ = r.ParseForm()
	data := extractBuilderData(r)
	idx, _ := strconv.Atoi(r.FormValue("idx"))
	if idx >= 0 && idx < len(data.Fields) {
		data.Fields = append(data.Fields[:idx], data.Fields[idx+1:]...)
	}
	data.PreviewJSON = buildJSONSchema(currentBuilderSchema(sess, data))
	h.renderFragment(w, r, "fragment_schema_builder_form", data)
}

// SaveSchema persists a custom schema and returns to the browser.
// ?use=1 also selects it.
func (h *H) SaveSchema(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	_ = r.ParseForm()
	data := extractBuilderData(r)
	if strings.TrimSpace(data.Name) == "" {
		h.errorToast(w, r, "Schema needs a name")
		return
	}
	if len(data.Fields) == 0 || allBlank(data.Fields) {
		h.errorToast(w, r, "Add at least one claim field")
		return
	}
	for _, f := range data.Fields {
		if f.Name != "" && !validFieldName(f.Name) {
			h.errorToast(w, r, fmt.Sprintf("Nombre de campo inválido: %q — solo letras (a-z, A-Z), dígitos y guión bajo, sin caracteres especiales.", f.Name))
			return
		}
	}
	if bad := firstInvalidLocaleCode(r.Form); bad != "" {
		h.errorToast(w, r, fmt.Sprintf("Código de idioma inválido: %q — solo letras (a-z, A-Z), dígitos y guión, sin espacios ni caracteres especiales.", bad))
		return
	}
	schema := currentBuilderSchema(sess, data)
	// Inji auth-code DPGs apply via the Flow B path (multi-format credential_config
	// + extraction view + scope-query + eSignet scope + restart certify/esignet)
	// instead of the default adapter — the builder UI is shared, the save is not.
	authcode := false
	if dpgs, err := h.Adapter.ListIssuerDpgs(r.Context()); err == nil {
		authcode = dpgs[sess.IssuerDpg].SchemaApply == "inji_authcode"
	}
	if authcode {
		key, err := h.applyAuthcodeSchema(issuerCtx(r, sess), schema, sessionOwnerKey(sess))
		if err != nil {
			h.errorToast(w, r, err.Error())
			return
		}
		// Land back on the shared schema grid with the freshly-built credential
		// pre-selected, so the issuer can Continue → Mode → bulk-provision —
		// the same wizard tail walt.id uses. The ?provisioning marker makes the
		// grid show a self-dismissing banner that polls until certify+eSignet
		// finish restarting and the schema is actually claimable (see SchemaReady).
		sess.SchemaID = key
		sess.ExpandedSchemaID = key
		h.redirect(w, r, "/issuer/schema?provisioning="+url.QueryEscape(key)+"&pname="+url.QueryEscape(schema.Name))
		return
	}
	if err := h.Adapter.SaveCustomSchema(issuerCtx(r, sess), schema); err != nil {
		h.errorToast(w, r, err.Error())
		return
	}
	sess.ExpandedSchemaID = schema.ID
	if r.URL.Query().Get("use") == "1" {
		sess.SchemaID = schema.ID
	}
	h.redirect(w, r, "/issuer/schema")
}

// SchemaReady is polled by the provisioning banner after an Inji auth-code
// schema is saved (GET /issuer/schema/ready?key=&name=). It reports whether the
// schema is actually claimable yet — certify + eSignet restart on a schema save,
// so there's a ~20–40s window where the credential exists in the DB but Certify
// isn't advertising it. Not ready → re-render the banner (keeps the poll alive);
// ready → an empty body (the outerHTML swap removes the banner) plus an HX-Trigger
// that pops a "ready" toast and refreshes the grid.
func (h *H) SchemaReady(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	key := strings.TrimSpace(r.URL.Query().Get("key"))
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		name = key
	}
	if h.schemaAvailable(r.Context(), key) {
		payload, _ := json.Marshal(map[string]any{
			"toast":        "✓ \"" + name + "\" is ready to use",
			"schemasReady": true,
		})
		w.Header().Set("HX-Trigger", string(payload))
		w.WriteHeader(http.StatusOK) // empty body → hx-swap:outerHTML removes the banner
		return
	}
	h.renderFragment(w, r, "fragment_provisioning_banner", map[string]any{
		"Provisioning": key, "ProvName": name, "Lang": h.langFor(r),
	})
	_ = sess
}

// schemaAvailable reports whether Certify is advertising the given credential
// config key in its well-known issuer metadata — i.e. the schema is claimable.
// During the certify restart the fetch fails fast (connection refused) → not
// ready; once certify is back and has reloaded the config → ready.
func (h *H) schemaAvailable(ctx context.Context, key string) bool {
	if key == "" {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		injiCertifyUpstream()+"/v1/certify/.well-known/openid-credential-issuer", nil)
	if err != nil {
		return false
	}
	cl := &http.Client{Timeout: 5 * time.Second}
	resp, err := cl.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return false
	}
	defer resp.Body.Close()
	var meta struct {
		Configs map[string]json.RawMessage `json:"credential_configurations_supported"`
	}
	if json.NewDecoder(resp.Body).Decode(&meta) != nil {
		return false
	}
	_, ok := meta.Configs[key]
	return ok
}

// DeleteSchema removes a custom schema from the session.
// Deleting the currently-selected schema clears the selection, so this also
// pushes an OOB update for the page-level Continue button.
func (h *H) DeleteSchema(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	ctx := issuerCtx(r, sess)
	id := r.FormValue("id")
	// walt.id/credebl custom schemas are tracked in the registry adapter's
	// in-memory list (DeleteCustomSchema dispatches to their DPG adapters).
	_ = h.Adapter.DeleteCustomSchema(ctx, id)
	// Inji auth-code credentials are DB-backed — the schema browser lists them via
	// SubjectStore.ListMyCredentials, NOT the registry's in-memory schemas, so the
	// adapter delete above is a no-op for them. Tear down ALL the artifacts
	// applyAuthcodeSchema created so the delete is persistent: the credential_config
	// + owner rows + the per-credential extraction view (DeleteCredential), the
	// Certify scope-query mapping + the two eSignet scope registrations, then reload
	// Certify — otherwise a same-named rebuild inherits a stale view/mapping (→ the
	// 42P16 column-rename failure) and the deleted config lingers in Certify's cache.
	if h.Subjects != nil {
		_, slug := injiConfigKeySlug(vctypes.Schema{AdditionalTypes: []string{id}})
		// Read the scope BEFORE deleting the config row. "" ⇒ not an auth-code
		// credential (e.g. a walt.id/CREDEBL schema) ⇒ skip the Certify teardown +
		// restart, so those deletes don't needlessly bounce inji-certify.
		scope, _ := h.Subjects.CredentialScope(ctx, id)
		if err := h.Subjects.DeleteCredential(ctx, id, sessionOwnerKey(sess), slug); err == nil && scope != "" {
			_ = removeBraceEntry(certifyScopeQueryFile(),
				"mosip.certify.data-provider-plugin.postgres.scope-query-mapping", scope)
			_ = removeBraceEntry(esignetScopeFile(),
				"mosip.esignet.supported.credential.scopes", scope)
			_ = removeBraceEntry(esignetScopeFile(),
				"mosip.esignet.credential.scope-resource-mapping", scope)
			for _, c := range []string{"inji-certify", "injiweb-esignet"} {
				_ = dockerRestart(c)
			}
		}
	}
	if sess.SchemaID == id {
		sess.SchemaID = ""
	}
	if sess.ExpandedSchemaID == id {
		sess.ExpandedSchemaID = ""
	}
	data := h.schemaBrowserData(w, r, sess)
	h.renderFragments(w, r, data, "fragment_schema_browser_body", "fragment_schema_continue_oob")
}

// canonicalStd normalises the schema-builder dropdown's `std` form value to
// the canonical Std taxonomy used by adapters (vctypes.Schema.Std). The
// dropdown emits short keys like "sd_jwt_vc" because parentheses + spaces
// in <option value=...> are awkward, but adapters key off the longer form
// "sd_jwt_vc (IETF)" used in walt.id's metadata. Mismatches surface as
// "unsupported schema standard" errors at issue time — observed for the
// SD-JWT path on 2026-04-29.
func canonicalStd(raw string) string {
	switch strings.TrimSpace(raw) {
	case "sd_jwt_vc", "sd_jwt_vc (IETF)":
		return "sd_jwt_vc (IETF)"
	default:
		return strings.TrimSpace(raw)
	}
}

func extractBuilderData(r *http.Request) builderData {
	d := builderData{
		Name:              r.FormValue("name"),
		Desc:              r.FormValue("desc"),
		IssuerDisplayName: r.FormValue("issuer_display_name"),
		ExtraType:         r.FormValue("extra_type"),
		Std:               canonicalStd(r.FormValue("std")),
		Delegation:        r.FormValue("delegation") == "on",
		Expiry:            r.FormValue("expiry") == "on",
		Scenario:          r.FormValue("scenario"),
		Scenarios:         delegationScenarios,
		DocType:           r.FormValue("doctype"),
		KnownDocTypes:     mdoc.KnownDocTypes(),
	}
	if d.Std == "" {
		d.Std = "w3c_vcdm_2"
	}
	// mso_mdoc without a docType is not a renderable state: the docType
	// <select> has no empty option, so a browser renders it with the FIRST
	// option pre-selected. If the builder data held "" the markup would show
	// mDL while the server believed nothing was picked, and the mandatory
	// fields would never preload — exactly the symptom the format selector
	// showed before it re-rendered the form at all. Defaulting here keeps the
	// two in agreement for every entry point (format switch, add-field,
	// preview, save) rather than only the one that noticed.
	if d.Std == "mso_mdoc" && strings.TrimSpace(d.DocType) == "" {
		if known := d.KnownDocTypes; len(known) > 0 {
			d.DocType = known[0].DocType
		}
	}
	// r.FormValue above already parses the request body into r.Form; this
	// call just makes that explicit before we hand r.Form to the helper.
	_ = r.ParseForm()
	d.Fields = parseFieldSpecsFromForm(r.Form)
	d.BlankLangRows = blankLangRowsFromForm(r.Form, d.Fields)

	// For mdoc, the standard's mandatory elements are preloaded and locked:
	// the docType defines them, so an operator cannot omit or rename one and
	// still have a conformant credential. Their labels stay editable.
	if d.Std == "mso_mdoc" && d.DocType != "" {
		mandatory := mdoc.MandatoryFields(d.DocType)
		var merged []vctypes.FieldSpec
		for _, m := range mandatory {
			if submitted, ok := findFieldByName(d.Fields, m.Name); ok {
				// Overlay the operator's labels ONTO the curated ones, per
				// locale — never replace the map wholesale. mdoc.MandatoryFields
				// ships curated English ("UN Distinguishing Sign"), and the
				// template re-posts every row on each re-render, so a submitted
				// row essentially always exists. Replacing the map meant the
				// curated "en" died the moment the operator touched anything,
				// leaving the catalog to fall through to DeriveLabel and degrade
				// it to "Un Distinguishing Sign" in the holder's wallet. Worse,
				// an operator who filled in only a Spanish label lost English —
				// the base-language fallback for every other locale.
				//
				// Safe to mutate m.Labels in place: MandatoryFields returns a
				// deep copy, so this touches no package-level state.
				if m.Labels == nil {
					m.Labels = map[string]string{}
				}
				for loc, label := range submitted.Labels {
					m.Labels[loc] = label
				}
			}
			merged = append(merged, m)
		}
		for _, f := range d.Fields {
			if !isMandatoryName(mandatory, f.Name) {
				merged = append(merged, f)
			}
		}
		d.Fields = merged
	}
	return d
}

func findFieldByName(fields []vctypes.FieldSpec, name string) (vctypes.FieldSpec, bool) {
	for _, f := range fields {
		if f.Name == name {
			return f, true
		}
	}
	return vctypes.FieldSpec{}, false
}

func isMandatoryName(mandatory []vctypes.FieldSpec, name string) bool {
	for _, m := range mandatory {
		if m.Name == name {
			return true
		}
	}
	return false
}

// parseFieldSpecsFromForm reads the indexed field rows (field_name_0,
// field_datatype_0, field_required_0, ...) the schema builder submits.
// Takes url.Values rather than *http.Request so it can be tested directly.
func parseFieldSpecsFromForm(form url.Values) []vctypes.FieldSpec {
	var out []vctypes.FieldSpec
	// Field rows come as field_name_0, field_datatype_0, field_required_0, ...
	for i := 0; i < 50; i++ {
		name := form.Get(fmt.Sprintf("field_name_%d", i))
		dt := form.Get(fmt.Sprintf("field_datatype_%d", i))
		if dt == "" && name == "" && form[fmt.Sprintf("field_name_%d", i)] == nil {
			break
		}
		req := form.Get(fmt.Sprintf("field_required_%d", i)) == "on"
		if dt == "" {
			dt = "string"
		}
		f := vctypes.FieldSpec{Name: strings.TrimSpace(name), Datatype: dt, Required: req}
		if strings.Contains(dt, ":") {
			parts := strings.SplitN(dt, ":", 2)
			f.Datatype = parts[0]
			f.Format = parts[1]
		}

		// Labels arrive as PARALLEL indexed inputs: field_lang_N_J carries the
		// locale code and field_label_N_J the text, for J = 0, 1, 2, ... Row J=0
		// is the field's first language row, pre-filled with "en" but freely
		// editable — a deployment issuing only in Spanish sets it to "es" and
		// carries no English at all.
		//
		// The locale is a VALUE, never part of a field name. The previous
		// scheme encoded it in the name (field_label_N_<locale>), which forced
		// a separate "new locale" row and let a locale containing a space
		// truncate the HTML attribute — the browser then resubmitted a
		// different, shorter key and the label silently landed under the wrong
		// locale. With the index-based scheme no operator text reaches an
		// attribute name, so an arbitrary number of languages round-trips
		// cleanly whatever the operator types.
		if labels := parseFieldLabels(form, i); len(labels) > 0 {
			f.Labels = labels
		}

		out = append(out, f)
	}
	return out
}

// LangRow is one language row of a field's label editor: a freely-editable
// locale code beside the label text in that language. The template renders
// these as parallel indexed inputs (field_lang_N_J / field_label_N_J), so the
// operator's locale text never becomes part of an HTML attribute NAME.
type LangRow struct {
	Lang  string
	Label string
}

// FieldLangRows turns a field's Labels map into the ordered rows the builder
// renders, and is exposed to templates as `fieldLangRows`.
//
// Ordering rules, in order of application:
//
//  1. "en" first when the field HAS an English label. This is not a claim
//     that English is privileged — it is the only stable anchor available.
//     mdoc.MandatoryFields ships curated English labels ("Family Name",
//     "UN Distinguishing Sign") and vctypes.FieldSpec.Label falls back to
//     "en" for any locale it cannot resolve, so surfacing it first keeps the
//     curated text in the row the operator sees without hunting.
//  2. Every other locale sorted, so the form is deterministic across
//     re-renders. A map has no order of its own, and the builder re-renders
//     on every keystroke — unsorted rows would visibly reshuffle as the
//     operator types.
//  3. A field with NO labels at all still gets one row, pre-filled with "en"
//     and an empty label. The first language row is freely editable, not
//     locked to English: a deployment issuing only in Spanish overwrites it
//     with "es" and carries no English at all. "en" is a starting value, not
//     a constraint.
func FieldLangRows(f vctypes.FieldSpec) []LangRow {
	if len(f.Labels) == 0 {
		return []LangRow{{Lang: "en"}}
	}
	rest := make([]string, 0, len(f.Labels))
	for loc := range f.Labels {
		if loc == "en" {
			continue
		}
		rest = append(rest, loc)
	}
	sort.Strings(rest)
	out := make([]LangRow, 0, len(f.Labels))
	if en, ok := f.Labels["en"]; ok {
		out = append(out, LangRow{Lang: "en", Label: en})
	}
	for _, loc := range rest {
		out = append(out, LangRow{Lang: loc, Label: f.Labels[loc]})
	}
	return out
}

// IntRange returns []int{from, from+1, ..., from+n-1}, and is exposed to
// templates as `intRange` so a block can repeat n times while still knowing
// each repetition's ABSOLUTE index — something text/template cannot express
// on its own. The schema builder numbers its not-yet-filled language rows
// with it, continuing from the filled ones; those numbers ARE the input names
// (field_lang_N_J), so a restart at 0 would collide with an existing row and
// silently overwrite its label.
//
// n is `any` rather than `int` because the template feeds it `index` into a
// map[int]int, which yields an untyped nil for an absent key — and for a nil
// map, which is every caller that renders a field row without a blank count.
// text/template will not coerce that to an int, so a plain int parameter
// would turn an ordinary "this field has no pending language rows" into a
// render error. Anything that isn't a positive int count yields no rows.
func IntRange(from int, n any) []int {
	count, ok := n.(int)
	if !ok || count <= 0 {
		return nil
	}
	out := make([]int, count)
	for i := range out {
		out[i] = from + i
	}
	return out
}

// maxLangRowsPerField bounds the language-row scan for one field. Language
// rows are added one at a time through a server round-trip, so this is a
// sanity ceiling on a crafted post rather than a product limit the operator
// can reach by clicking.
const maxLangRowsPerField = 50

// parseFieldLabels reads field i's parallel language rows — field_lang_i_J
// (locale code) alongside field_label_i_J (the text) — into a locale-keyed
// map.
//
// Both halves are trimmed. A blank label leaves NO map entry regardless of
// what locale sits beside it: absent means "derive from the identifier"
// downstream (vctypes.FieldSpec.Label), and an empty-string entry would be a
// different, worse thing — a present key whose value renders as nothing. A
// blank locale is skipped for the same reason, and an invalid locale code is
// dropped here (firstInvalidLocaleCode is the path that reports it to the
// operator, since this function has no request/response to surface an error
// through).
//
// Later rows win on a duplicate locale, which is the only sane reading of
// two rows claiming the same language.
//
// Returns a nil map when nothing usable was submitted, so the caller can
// leave FieldSpec.Labels nil rather than assigning an empty map.
func parseFieldLabels(form url.Values, i int) map[string]string {
	var labels map[string]string
	for j := 0; j < maxLangRowsPerField; j++ {
		langKey := fmt.Sprintf("field_lang_%d_%d", i, j)
		labelKey := fmt.Sprintf("field_label_%d_%d", i, j)
		// Stop at the first row the form doesn't carry at all. Both halves are
		// always rendered together, so an absent lang key means no more rows.
		if _, ok := form[langKey]; !ok {
			if _, ok := form[labelKey]; !ok {
				break
			}
		}
		loc := strings.TrimSpace(form.Get(langKey))
		label := strings.TrimSpace(form.Get(labelKey))
		if loc == "" || label == "" || !validLocaleCode(loc) {
			continue
		}
		if labels == nil {
			labels = map[string]string{}
		}
		labels[loc] = label
	}
	return labels
}

// blankLangRowsFromForm counts, per field, how many language rows the form
// submitted that produced NO label entry — i.e. rows the operator has added
// but not yet filled in (or filled in only half of).
//
// Without this the builder would eat its own "Add language" click: the new
// row is empty, an empty row makes no map entry by design, and the very next
// keystroke re-renders the form from the map — so the row the operator just
// asked for would disappear before they could type in it.
//
// Only rows the form actually carried are counted, so a handler that never
// saw a language row (or a caller passing a synthetic form) gets zero rather
// than phantom rows.
func blankLangRowsFromForm(form url.Values, fields []vctypes.FieldSpec) map[int]int {
	out := map[int]int{}
	for i := range fields {
		submitted, kept := 0, 0
		for j := 0; j < maxLangRowsPerField; j++ {
			langKey := fmt.Sprintf("field_lang_%d_%d", i, j)
			labelKey := fmt.Sprintf("field_label_%d_%d", i, j)
			_, hasLang := form[langKey]
			_, hasLabel := form[labelKey]
			if !hasLang && !hasLabel {
				break
			}
			submitted++
			loc := strings.TrimSpace(form.Get(langKey))
			label := strings.TrimSpace(form.Get(labelKey))
			if loc != "" && label != "" && validLocaleCode(loc) {
				kept++
			}
		}
		// FieldLangRows renders one implicit row for a field with no labels
		// at all, so only count beyond that to avoid drawing it twice.
		blank := submitted - kept
		if kept == 0 && blank > 0 {
			blank--
		}
		if blank > 0 {
			out[i] = blank
		}
	}
	return out
}

// firstInvalidLocaleCode re-scans the raw submitted form for a locale code
// that fails validLocaleCode, returning it so SaveSchema can tell the
// operator why their label silently didn't make it into the saved schema.
// parseFieldLabels itself just drops invalid codes rather than erroring,
// since it has no path back to the request/response to surface one — this is
// that path. Returns "" when every locale code submitted is valid (including
// when none were submitted at all).
//
// A malformed code alongside a BLANK label is not reported: that pair
// produces no map entry either way, so there is nothing the operator lost.
func firstInvalidLocaleCode(form url.Values) string {
	for i := 0; i < 50; i++ {
		for j := 0; j < maxLangRowsPerField; j++ {
			langKey := fmt.Sprintf("field_lang_%d_%d", i, j)
			labelKey := fmt.Sprintf("field_label_%d_%d", i, j)
			if _, ok := form[langKey]; !ok {
				if _, ok := form[labelKey]; !ok {
					break
				}
			}
			loc := strings.TrimSpace(form.Get(langKey))
			if loc == "" || strings.TrimSpace(form.Get(labelKey)) == "" {
				continue
			}
			if !validLocaleCode(loc) {
				return loc
			}
		}
	}
	return ""
}

func currentBuilderSchema(sess *Session, d builderData) vctypes.Schema {
	name := strings.TrimSpace(d.Name)
	if name == "" {
		name = "Untitled schema"
	}
	desc := strings.TrimSpace(d.Desc)
	if desc == "" {
		desc = "—"
	}
	s := vctypes.Schema{
		ID:                "custom-" + strconv.FormatInt(time.Now().UnixNano(), 36),
		Name:              name,
		Desc:              desc,
		IssuerDisplayName: strings.TrimSpace(d.IssuerDisplayName),
		Std:               d.Std,
		DPGs:              []string{sess.IssuerDpg},
		Custom:            true,
		AdditionalTypes:   []string{},
	}
	if strings.TrimSpace(d.ExtraType) != "" {
		s.AdditionalTypes = []string{strings.TrimSpace(d.ExtraType)}
	}
	// For mdoc, the operator's selected docType IS the credential type, and it
	// must reach the saved schema. AdditionalTypes[0] is what
	// customSchemaTypeName returns, which becomes the catalog configID
	// "<docType>_mso_mdoc"; BaseType() strips that suffix back to the docType,
	// and buildIssuer2Offer (via mdocDocTypeFor) resolves the issuer-api2
	// profile from it. Without this the schema kept its generated
	// "custom-<nano>" ID as the base type, so every builder-made mdoc schema
	// failed at issuance with `no issuer-api2 profile for docType "custom-..."`,
	// and buildMDocEntry fell through to typeName and emitted a garbage
	// namespace in the claim paths.
	//
	// The docType deliberately WINS over ExtraType here rather than appending:
	// ExtraType is a free-text box, while the docType is a validated selection
	// from mdoc.KnownDocTypes() that is pinned against the profile table
	// (TestKnownDocTypesResolveInProfiles). Letting free text either precede it
	// or sit alongside it would put an unvalidated string where BaseType()
	// looks, reintroducing exactly the unresolvable-profile failure above.
	if d.Std == "mso_mdoc" && strings.TrimSpace(d.DocType) != "" {
		s.AdditionalTypes = []string{strings.TrimSpace(d.DocType)}
	}
	for _, f := range d.Fields {
		if strings.TrimSpace(f.Name) != "" {
			s.FieldsSpec = append(s.FieldsSpec, f)
		}
	}
	// Opt-in expiry: "This credential expires" (d.Expiry) marks the SCHEMA as
	// carrying a validity window, which the issuer then sets per-issuance.
	//
	// This sets a flag rather than appending a valid_until CLAIM (which is what
	// it used to do). A validity window is credential metadata, not a subject
	// attribute, so it belongs in the envelope — SD-JWT's registered nbf/exp,
	// W3C's top-level validFrom/validUntil — which every format already defines
	// and backend.TemporalBounds already reads. Two things follow: a holder
	// cannot withhold the expiry under selective disclosure (registered claims
	// are never selectively disclosable), and the window can't collide with a
	// subject's own date attributes. Schemas built the old way keep working —
	// ExpiresWithWindow() also honours a legacy valid_until field.
	//
	// Delegation schemas do NOT force expiry; it only appears if the operator
	// explicitly opts in.
	s.Expires = d.Expiry
	return s
}

// hasField reports whether fs already contains a field with the given name
// (case-sensitive, trimmed) — used to keep the derived valid_until claim from
// being appended twice when composed with the delegation preset.
func hasField(fs []vctypes.FieldSpec, name string) bool {
	for _, f := range fs {
		if strings.TrimSpace(f.Name) == name {
			return true
		}
	}
	return false
}

func allBlank(fs []vctypes.FieldSpec) bool {
	for _, f := range fs {
		if strings.TrimSpace(f.Name) != "" {
			return false
		}
	}
	return true
}

var reValidFieldName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

func validFieldName(name string) bool {
	return reValidFieldName.MatchString(name)
}

// reValidLocaleCode is deliberately permissive — locale codes are free-form
// operator text, not a fixed BCP-47 dropdown, so any deployment can serve a
// language no predefined list would carry. What it excludes is not language
// choice but characters that corrupt the round trip: the locale becomes both
// an HTML form field *name* (in field_label_N_<locale>) and a map key, so
// whitespace/newlines truncate the attribute early — the browser then
// resubmits a different, shorter key, silently landing the label under the
// wrong locale and overwriting whatever was there. No markup or quote
// characters are allowed either, for the same reason (they'd break the
// attribute rather than XSS — html/template already escapes those safely,
// but a truncated attribute name still corrupts data before escaping ever
// sees it).
var reValidLocaleCode = regexp.MustCompile(`^[A-Za-z0-9-]{1,35}$`)

func validLocaleCode(loc string) bool {
	return reValidLocaleCode.MatchString(loc)
}

// buildJSONSchema returns a pretty-printed JSON Schema (draft 2020-12) for the given schema.
// Mirrors the JS buildJsonSchema function. Returns the string so templates can put it
// straight into a <pre> block (escaping happens via html/template).
func buildJSONSchema(s vctypes.Schema) string {
	isW3C := strings.HasPrefix(s.Std, "w3c_vcdm")
	v2 := s.Std == "w3c_vcdm_2"

	types := []string{"VerifiableCredential"}
	types = append(types, s.AdditionalTypes...)

	fields := s.FieldsSpec

	// Build credentialSubject properties
	props := orderedMap{}
	required := []string{}
	for _, f := range fields {
		if f.Name == "" {
			continue
		}
		prop := orderedMap{{"type", f.Datatype}}
		if f.Format != "" {
			prop = append(prop, kv{"format", f.Format})
		}
		props = append(props, kv{f.Name, prop})
		if f.Required {
			required = append(required, f.Name)
		}
	}

	// Build root schema
	schema := orderedMap{
		{"$schema", "https://json-schema.org/draft/2020-12/schema"},
		{"$id", "https://schemas.verifiably.local/" + s.ID + ".json"},
		{"title", s.Name},
		{"description", s.Desc},
		{"type", "object"},
	}

	properties := orderedMap{}

	if isW3C {
		contextURL := "https://www.w3.org/2018/credentials/v1"
		if v2 {
			contextURL = "https://www.w3.org/ns/credentials/v2"
		}
		vocabMap := orderedMap{{"@vocab", "https://vocab.verifiably.local/"}}
		for _, f := range fields {
			if f.Name != "" {
				vocabMap = append(vocabMap, kv{f.Name, "https://vocab.verifiably.local/" + f.Name})
			}
		}
		properties = append(properties,
			kv{"@context", orderedMap{
				{"type", "array"},
				{"const", []any{contextURL, vocabMap}},
			}},
			kv{"type", orderedMap{
				{"type", "array"},
				{"items", orderedMap{{"type", "string"}}},
				{"const", types},
			}},
			kv{"issuer", orderedMap{
				{"type", []string{"string", "object"}},
				{"description", "DID or URL of the issuer"},
			}},
		)
		dateKey := "issuanceDate"
		if v2 {
			dateKey = "validFrom"
		}
		properties = append(properties,
			kv{dateKey, orderedMap{{"type", "string"}, {"format", "date-time"}}},
			kv{"credentialSubject", orderedMap{
				{"type", "object"},
				{"properties", props},
				{"required", required},
			}},
		)
	} else if strings.HasPrefix(s.Std, "sd_jwt_vc") {
		properties = append(properties,
			kv{"type", orderedMap{{"type", "array"}, {"const", types}}},
			kv{"vct", orderedMap{{"type", "string"}, {"const", "https://vct.verifiably.local/" + s.ID}}},
			kv{"iss", orderedMap{{"type", "string"}, {"description", "Issuer identifier"}}},
			kv{"iat", orderedMap{{"type", "integer"}}},
		)
		for _, p := range props {
			properties = append(properties, p)
		}
	} else if s.Std == "jwt_vc" {
		properties = append(properties,
			kv{"type", orderedMap{{"type", "array"}, {"const", types}}},
			kv{"iss", orderedMap{{"type", "string"}}},
			kv{"sub", orderedMap{{"type", "string"}}},
			kv{"vc", orderedMap{
				{"type", "object"},
				{"properties", orderedMap{
					{"type", orderedMap{{"type", "array"}}},
					{"credentialSubject", orderedMap{{"type", "object"}, {"properties", props}}},
				}},
			}},
		)
	} else if s.Std == "mso_mdoc" {
		nsKey := "org.verifiably." + s.ID
		properties = append(properties,
			kv{"type", orderedMap{{"type", "array"}, {"const", types}}},
			kv{"docType", orderedMap{{"type", "string"}, {"const", nsKey}}},
			kv{"nameSpaces", orderedMap{
				{"type", "object"},
				{"properties", orderedMap{{nsKey, orderedMap{{"type", "object"}, {"properties", props}}}}},
			}},
		)
	} else {
		properties = append(properties, kv{"type", orderedMap{{"type", "array"}, {"const", types}}})
	}

	schema = append(schema, kv{"properties", properties})
	if isW3C {
		schema = append(schema, kv{"required", []string{"@context", "type", "issuer", "credentialSubject"}})
	} else {
		schema = append(schema, kv{"required", []string{"type"}})
	}

	b, _ := json.MarshalIndent(schema, "", "  ")
	return string(b)
}

// orderedMap is a [][2]any alias that marshals JSON in insertion order.
// Used so the generated JSON Schema fields appear in a deterministic, readable order.
type orderedMap []kv
type kv struct {
	K string
	V any
}

// MarshalJSON for orderedMap and kv — emits a JSON object.
func (o orderedMap) MarshalJSON() ([]byte, error) {
	var b strings.Builder
	b.WriteString("{")
	for i, entry := range o {
		if i > 0 {
			b.WriteString(",")
		}
		key, _ := json.Marshal(entry.K)
		b.Write(key)
		b.WriteString(":")
		val, err := json.Marshal(entry.V)
		if err != nil {
			return nil, err
		}
		b.Write(val)
	}
	b.WriteString("}")
	return []byte(b.String()), nil
}

// MarshalJSON for kv — never called directly (kv is always inside an orderedMap),
// but present so encoding/json doesn't complain if someone marshals one.
func (k kv) MarshalJSON() ([]byte, error) {
	return json.Marshal(orderedMap{k})
}
