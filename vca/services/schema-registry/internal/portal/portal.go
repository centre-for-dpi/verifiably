// SPDX-License-Identifier: Apache-2.0

// Package portal renders the staff pages of the schema registry with the
// vca UI kit (ADR-013 decision 6). The pages are list, search and filter,
// detail, version history, publish, and retire. Every action calls a
// SchemaService RPC, so the pages and the API cannot diverge.
//
// Paths, under the configured prefix:
//
//	GET  /                        the list page with search and filters
//	GET  /publish                 the publish from a file page
//	POST /publish                 store an uploaded document, then publish it
//	GET  /schemas/{id}            the detail page of one version
//	GET  /schemas/{id}/versions   the version history page
//	POST /schemas/{id}/publish    publish one draft version
//	POST /schemas/{id}/retire     retire one or every published version
//	POST /schemas/{id}/delete     delete one draft version
//	GET  /schemas/{id}/mapping    the context and mapping page of a version
//	POST /schemas/{id}/mapping    save the mapping as the next draft version
package portal

import (
	"context"
	"encoding/json"
	"errors"

	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/jsonschema"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1/schemav1connect"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// DefaultPrefix is the URL prefix of the portal pages.
const DefaultPrefix = "/portal"

// MaxReasonLength caps the retire reason a form can send.
const MaxReasonLength = 500

// Options configure the portal.
type Options struct {
	// Client calls the SchemaService. The service satisfies it in process.
	Client schemav1connect.SchemaServiceClient
	// Kit renders the components. Nil builds a new kit.
	Kit *components.Kit
	// Prefix is the URL prefix of the pages. Empty means DefaultPrefix.
	Prefix string
	// BuilderURL links to the schema builder, when the deployment has one.
	BuilderURL string
	// Shell draws the issuer frame around every page (ADR-044 decision
	// 5). Nil draws the pages with their own navigation.
	Shell *staffshell.Shell
	// SignOut answers the sign out form of the shell at <prefix>/signout.
	// Nil leaves the path unrouted.
	SignOut http.Handler
	// Issued counts the issued credentials of each schema. Nil shows no
	// count.
	Issued Issued
	// IssueURL is the issue page of the issuer. Empty means
	// DefaultIssueURL.
	IssueURL string
}

// Issued is the part of the IssuedService client the list page calls.
type Issued interface {
	List(context.Context, *connect.Request[issuedv1.ListRequest]) (*connect.Response[issuedv1.ListResponse], error)
}

// Portal serves the staff pages.
type Portal struct {
	opts Options
}

// New builds the portal.
func New(opts Options) (*Portal, error) {
	if opts.Client == nil {
		return nil, errors.New("portal: a SchemaService client is required")
	}
	if opts.Prefix == "" {
		opts.Prefix = DefaultPrefix
	}
	opts.Prefix = "/" + strings.Trim(opts.Prefix, "/")
	if opts.IssueURL == "" {
		opts.IssueURL = DefaultIssueURL
	}
	if opts.Kit == nil {
		kit, err := components.New()
		if err != nil {
			return nil, err
		}
		opts.Kit = kit
	}
	return &Portal{opts: opts}, nil
}

// Prefix returns the URL prefix of the pages.
func (p *Portal) Prefix() string { return p.opts.Prefix }

// Register adds the pages to mux.
func (p *Portal) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+p.opts.Prefix+"/{$}", p.handle(p.list))
	mux.HandleFunc("GET "+p.opts.Prefix+"/publish", p.handle(p.publishPage))
	mux.HandleFunc("POST "+p.opts.Prefix+"/publish", p.handle(p.publishFile))
	mux.HandleFunc("POST "+p.opts.Prefix+"/schemas/{id}/delete", p.handle(p.deleteDraft))
	mux.HandleFunc("GET "+p.opts.Prefix+"/schemas/{id}/mapping", p.handle(p.mappingPage))
	mux.HandleFunc("POST "+p.opts.Prefix+"/schemas/{id}/mapping", p.handle(p.saveMapping))
	mux.HandleFunc("GET "+p.opts.Prefix+"/schemas/{id}", p.handle(p.detail))
	mux.HandleFunc("GET "+p.opts.Prefix+"/schemas/{id}/versions", p.handle(p.versions))
	mux.HandleFunc("POST "+p.opts.Prefix+"/schemas/{id}/publish", p.handle(p.publish))
	mux.HandleFunc("POST "+p.opts.Prefix+"/schemas/{id}/retire", p.handle(p.retire))
	if p.opts.SignOut != nil {
		mux.Handle("POST "+p.opts.Prefix+"/signout", p.opts.SignOut)
	}
}

// SignOutPath returns the action of the sign out form of the shell.
func (p *Portal) SignOutPath() string { return p.opts.Prefix + "/signout" }

// render writes a page: inside the issuer shell when the portal has one,
// else with the navigation of the registry marked at current.
func (p *Portal) render(w http.ResponseWriter, r *http.Request, current string, page components.Page) error {
	if p.opts.Shell != nil {
		return p.renderFrame(w, r, p.frame(r), page)
	}
	page.Nav = p.nav(current)
	return p.opts.Kit.RenderPage(w, r, page)
}

// renderFrame writes a page with a probe the handler already read.
func (p *Portal) renderFrame(w http.ResponseWriter, r *http.Request, f staffshell.Frame, page components.Page) error {
	if p.opts.Shell != nil {
		return p.opts.Shell.Render(p.opts.Kit, w, r, f, page)
	}
	page.Nav = p.nav("")
	return p.opts.Kit.RenderPage(w, r, page)
}

// handle answers 500 when the page fails. The error text stays in the
// response only as a short sentence, never as a stack or an internal path.
func (p *Portal) handle(fn func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := fn(w, r); err != nil {
			http.Error(w, "the page could not render", statusOf(err))
		}
	}
}

// statusOf maps a Connect code to an HTTP status.
func statusOf(err error) int {
	var cerr *connect.Error
	if errors.As(err, &cerr) {
		switch cerr.Code() {
		case connect.CodeNotFound:
			return http.StatusNotFound
		case connect.CodeInvalidArgument, connect.CodeFailedPrecondition:
			return http.StatusBadRequest
		}
	}
	return http.StatusInternalServerError
}

// States lists the state filter choices in life cycle order.
var States = []schemav1.State{schemav1.State_STATE_DRAFT, schemav1.State_STATE_PUBLISHED, schemav1.State_STATE_RETIRED}

// Formats lists the format filter choices in enum order.
var Formats = []commonv1.Format{
	commonv1.Format_FORMAT_VC_SD_JWT, commonv1.Format_FORMAT_DC_SD_JWT,
	commonv1.Format_FORMAT_JWT_VC_JSON, commonv1.Format_FORMAT_LDP_VC, commonv1.Format_FORMAT_MSO_MDOC,
}

// StateText returns the reader facing name of a state.
func StateText(s schemav1.State) string {
	switch s {
	case schemav1.State_STATE_DRAFT:
		return "Draft"
	case schemav1.State_STATE_PUBLISHED:
		return "Published"
	case schemav1.State_STATE_RETIRED:
		return "Retired"
	}
	return msg.T("issuer.schemas.status.any.label")
}

// StateStatus returns the badge status of a state.
func StateStatus(s schemav1.State) string {
	switch s {
	case schemav1.State_STATE_PUBLISHED:
		return "ok"
	case schemav1.State_STATE_RETIRED:
		return "warn"
	}
	return "info"
}

// StateValue returns the query value of a state.
func StateValue(s schemav1.State) string {
	switch s {
	case schemav1.State_STATE_DRAFT:
		return "draft"
	case schemav1.State_STATE_PUBLISHED:
		return "published"
	case schemav1.State_STATE_RETIRED:
		return "retired"
	}
	return ""
}

// ParseState reads a state query value. An unknown value means any state.
func ParseState(v string) schemav1.State {
	for _, s := range States {
		if StateValue(s) == strings.ToLower(strings.TrimSpace(v)) {
			return s
		}
	}
	return schemav1.State_STATE_UNSPECIFIED
}

// FormatValue returns the OID4VCI identifier of a format.
func FormatValue(f commonv1.Format) string {
	switch f {
	case commonv1.Format_FORMAT_VC_SD_JWT:
		return "vc+sd-jwt"
	case commonv1.Format_FORMAT_DC_SD_JWT:
		return "dc+sd-jwt"
	case commonv1.Format_FORMAT_JWT_VC_JSON:
		return "jwt_vc_json"
	case commonv1.Format_FORMAT_LDP_VC:
		return "ldp_vc"
	case commonv1.Format_FORMAT_MSO_MDOC:
		return "mso_mdoc"
	}
	return ""
}

// ParseFormat reads a format query value. An unknown value means any format.
func ParseFormat(v string) commonv1.Format {
	for _, f := range Formats {
		if FormatValue(f) == strings.TrimSpace(v) {
			return f
		}
	}
	return commonv1.Format_FORMAT_UNSPECIFIED
}

// FormatList joins the format identifiers of a schema with commas.
func FormatList(m *schemav1.Schema) string {
	var out []string
	for _, f := range m.GetFormats() {
		out = append(out, FormatValue(f))
	}
	return strings.Join(out, ", ")
}

// Notices maps a notice code to the sentence the page shows.
var Notices = map[string]components.Toast{
	"published": {Level: "ok", Text: "The version is published. The DPG can issue it now."},
	"retired":   {Level: "warn", Text: "The version is retired. Issuance with it stopped."},
	"deleted":   {Level: "ok", Text: msg.T("issuer.schemas.deleted")},
	"uploaded":  {Level: "ok", Text: msg.T("issuer.schemas.uploaded")},
	"mapped":    {Level: "ok", Text: msg.T("issuer.mapping.saved")},
}

// notice returns the toast of the notice query value, when the code is known.
func notice(v string) []components.Toast {
	if t, ok := Notices[v]; ok {
		return []components.Toast{t}
	}
	return nil
}

// Name returns the first display name of a schema, or its type.
func Name(m *schemav1.Schema) string {
	if d := m.GetDisplay(); len(d) > 0 && d[0].GetName() != "" {
		return d[0].GetName()
	}
	return m.GetType()
}

// Matches reports whether a schema passes the state and format filters.
func Matches(m *schemav1.Schema, state schemav1.State, format commonv1.Format) bool {
	if state != schemav1.State_STATE_UNSPECIFIED && m.GetState() != state {
		return false
	}
	if format == commonv1.Format_FORMAT_UNSPECIFIED {
		return true
	}
	for _, f := range m.GetFormats() {
		if f == format {
			return true
		}
	}
	return false
}

// Filter keeps the schemas that pass the filters.
func Filter(list []*schemav1.Schema, state schemav1.State, format commonv1.Format) []*schemav1.Schema {
	out := make([]*schemav1.Schema, 0, len(list))
	for _, m := range list {
		if Matches(m, state, format) {
			out = append(out, m)
		}
	}
	return out
}

// link renders one anchor. text is escaped and href is built from escaped parts.
func link(href, text string) template.HTML {
	return template.HTML(`<a href="` + template.HTMLEscapeString(href) + `">` + template.HTMLEscapeString(text) + `</a>`) //nolint:gosec // both parts are escaped
}

// detailURL returns the page URL of one version. Version zero omits it.
func (p *Portal) detailURL(id string, version int32) string {
	u := p.opts.Prefix + "/schemas/" + url.PathEscape(id)
	if version > 0 {
		u += "?version=" + strconv.Itoa(int(version))
	}
	return u
}

func (p *Portal) versionsURL(id string) string {
	return p.opts.Prefix + "/schemas/" + url.PathEscape(id) + "/versions"
}

// nav returns the navigation of every page.
func (p *Portal) nav(current string) components.Nav {
	n := components.Nav{
		Label: "Schema registry",
		Brand: components.Link{Href: p.opts.Prefix + "/", Text: "Schema registry"},
		Links: []components.Link{{Href: p.opts.Prefix + "/", Text: "Schemas", Current: current == "list"}},
	}
	if p.opts.BuilderURL != "" {
		n.Links = append(n.Links, components.Link{Href: p.opts.BuilderURL, Text: "Builder"})
	}
	return n
}

// list renders the list page: the search and the filters, then one row
// per schema with its latest version, its formats, its status badge, the
// count of issued credentials, the last change, and the row actions.
func (p *Portal) list(w http.ResponseWriter, r *http.Request) error {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	state := ParseState(r.URL.Query().Get("state"))
	format := ParseFormat(r.URL.Query().Get("format"))
	var found []*schemav1.Schema
	if q != "" {
		resp, err := p.opts.Client.Search(r.Context(), connect.NewRequest(&schemav1.SearchRequest{Query: q}))
		if err != nil {
			return err
		}
		found = Filter(resp.Msg.GetSchemas(), state, format)
	} else {
		resp, err := p.opts.Client.List(r.Context(), connect.NewRequest(&schemav1.ListRequest{State: state, Format: format}))
		if err != nil {
			return err
		}
		found = resp.Msg.GetSchemas()
	}
	b := &blocks{kit: p.opts.Kit}
	csrf := staffsession.HiddenField(r.Context())
	rows := make([]components.Row, 0, len(found))
	for _, m := range found {
		rows = append(rows, components.Row{
			{HTML: p.schemaCell(m)},
			{Text: "v" + strconv.Itoa(int(m.GetVersion()))},
			{Text: FormatLabels(m)},
			{HTML: b.add("badge", components.Badge{Status: StateStatus(m.GetState()), Text: StateText(m.GetState())})},
			{Text: p.issuedCount(r, m.GetId())},
			dateCell(Updated(m)),
			{HTML: p.rowActions(b, m, csrf)},
		})
	}
	filters, err := p.filterForm(q, state, format)
	if err != nil {
		return err
	}
	var body template.HTML
	if len(rows) == 0 && q == "" && state == schemav1.State_STATE_UNSPECIFIED && format == commonv1.Format_FORMAT_UNSPECIFIED {
		body = b.add("empty", components.Empty{Title: msg.T("issuer.schemas.empty.title"), Text: msg.T("issuer.schemas.empty.text"),
			Action: components.Button{Text: msg.T("issuer.schemas.publish.label"), Href: p.opts.Prefix + "/publish", Variant: "primary"}})
	} else {
		body = components.Join(b.add("table", components.Table{
			ID: "schemas", Caption: msg.T("issuer.schemas.caption.label", strconv.Itoa(len(rows))),
			Columns: []string{
				msg.T("issuer.schemas.column.schema.label"), msg.T("issuer.schemas.column.version.label"),
				msg.T("issuer.schemas.column.format.label"), msg.T("issuer.schemas.column.status.label"),
				msg.T("issuer.schemas.column.issued.label"), msg.T("issuer.schemas.column.updated.label"),
				msg.T("issuer.schemas.column.actions.label"),
			},
			Rows: rows, Empty: msg.T("issuer.schemas.none_match"),
		}), template.HTML(`<p class="hint">`+template.HTMLEscapeString(msg.T("issuer.schemas.rule"))+`</p>`)) //nolint:gosec // the text is escaped
	}
	var actions []template.HTML
	if p.opts.BuilderURL != "" {
		actions = append(actions, b.add("button", components.Button{Text: msg.T("issuer.schemas.builder.label"), Href: p.opts.BuilderURL}))
	}
	actions = append(actions, b.add("button", components.Button{Text: msg.T("issuer.schemas.publish.label"), Href: p.opts.Prefix + "/publish", Variant: "primary"}))
	if b.err != nil {
		return b.err
	}
	return p.render(w, r, "list", components.Page{
		Title:       msg.T("issuer.nav.schemas.label"),
		Lead:        msg.T("issuer.schemas.lead"),
		Actions:     components.Join(actions...),
		Description: "Search, filter, and open the credential schemas of this issuer.",
		Content:     components.Join(filters, body),
		Toasts:      notice(r.URL.Query().Get("notice")),
	})
}

// filterForm renders the search and filter form of the list page.
func (p *Portal) filterForm(q string, state schemav1.State, format commonv1.Format) (template.HTML, error) {
	stateOptions := []components.Option{{Value: "", Text: msg.T("issuer.schemas.status.any.label"), Selected: state == schemav1.State_STATE_UNSPECIFIED}}
	for _, s := range States {
		stateOptions = append(stateOptions, components.Option{Value: StateValue(s), Text: StateText(s), Selected: s == state})
	}
	formatOptions := []components.Option{{Value: "", Text: msg.T("issuer.schemas.format.any.label"), Selected: format == commonv1.Format_FORMAT_UNSPECIFIED}}
	for _, f := range Formats {
		formatOptions = append(formatOptions, components.Option{Value: FormatValue(f), Text: FormatLabel(f) + " (" + FormatValue(f) + ")", Selected: f == format})
	}
	parts := []struct {
		name string
		data any
	}{
		{"field", components.Field{ID: "q", Label: msg.T("issuer.schemas.search.label"), Value: q, Type: "search", Attrs: map[string]string{"autocomplete": "off"}}},
		{"field", components.Field{ID: "state", Label: msg.T("issuer.schemas.status.label"), Type: "select", Options: stateOptions}},
		{"field", components.Field{ID: "format", Label: msg.T("issuer.schemas.format.label"), Type: "select", Options: formatOptions}},
		{"button", components.Button{Text: msg.T("issuer.schemas.apply.label"), Type: "submit"}},
	}
	out := []template.HTML{template.HTML(`<form class="filters" action="` + template.HTMLEscapeString(p.opts.Prefix) + `/" method="get">`)} //nolint:gosec // the prefix is escaped
	for _, part := range parts {
		h, err := p.opts.Kit.HTML(part.name, part.data)
		if err != nil {
			return "", err
		}
		out = append(out, h)
	}
	out = append(out, template.HTML(`</form>`)) //nolint:gosec // literal
	return components.Join(out...), nil
}

// version reads the version query value. Zero means the latest version.
func version(r *http.Request) int32 {
	n, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("version")), 10, 32)
	if err != nil || n < 0 {
		return 0
	}
	return int32(n)
}

// detail renders one version with its actions.
func (p *Portal) detail(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	resp, err := p.opts.Client.Get(r.Context(), connect.NewRequest(&schemav1.GetRequest{Id: id, Version: version(r)}))
	if err != nil {
		return err
	}
	m := resp.Msg.GetSchema()
	summary, err := p.summaryCard(m)
	if err != nil {
		return err
	}
	claims, err := p.claimsCard(m)
	if err != nil {
		return err
	}
	f := p.frame(r)
	actions, err := p.actionsCard(m, staffsession.HiddenField(r.Context()), targetOf(f))
	if err != nil {
		return err
	}
	document, err := p.opts.Kit.HTML("json", components.JSON{
		ID: "document", Summary: "JSON Schema 2020-12 document", Data: rawJSON(m.GetJsonSchema()),
	})
	if err != nil {
		return err
	}
	return p.renderFrame(w, r, f, components.Page{
		Title:       Name(m) + ", version " + strconv.Itoa(int(m.GetVersion())),
		Heading:     Name(m),
		Description: "The detail of one schema version.",
		Content:     components.Join(summary, claims, document, actions),
		Toasts:      notice(r.URL.Query().Get("notice")),
	})
}

// rawJSON decodes a JSON document for the JSON component. A document that
// does not decode shows as its text.
func rawJSON(doc string) any {
	var out any
	if err := json.Unmarshal([]byte(doc), &out); err != nil {
		return doc
	}
	return out
}

// Claim is one top level property of a JSON Schema document.
type Claim struct {
	Name     string
	Title    string
	Type     string
	Required bool
}

// Claims lists the top level properties of doc in document order. A
// document that does not parse gives no claims.
func Claims(doc string) []Claim {
	parsed, err := jsonschema.Parse([]byte(doc))
	if err != nil {
		return nil
	}
	required := map[string]bool{}
	for _, name := range parsed.Required() {
		required[name] = true
	}
	var out []Claim
	for _, name := range parsed.Properties() {
		c := Claim{Name: name, Title: name, Required: required[name]}
		if sub, ok := parsed.Property(name); ok {
			if title, ok := sub["title"].(string); ok && title != "" {
				c.Title = title
			}
			if typ, ok := sub["type"].(string); ok {
				c.Type = typ
			}
		}
		out = append(out, c)
	}
	return out
}

// summaryCard renders the identity and the life cycle of one version.
func (p *Portal) summaryCard(m *schemav1.Schema) (template.HTML, error) {
	badge, err := p.opts.Kit.HTML("badge", components.Badge{Status: StateStatus(m.GetState()), Text: StateText(m.GetState())})
	if err != nil {
		return "", err
	}
	rows := []components.Row{
		{{Text: "Schema id"}, {Text: m.GetId()}},
		{{Text: "Version"}, {Text: strconv.Itoa(int(m.GetVersion()))}},
		{{Text: "Credential type"}, {Text: m.GetType()}},
		{{Text: "State"}, {HTML: badge}},
		{{Text: "Formats"}, {Text: FormatList(m)}},
		{{Text: "Created"}, {Text: stamp(m.GetCreatedAt().AsTime().String(), m.GetCreatedAt() != nil)}},
		{{Text: "Published"}, {Text: stamp(m.GetPublishedAt().AsTime().String(), m.GetPublishedAt() != nil)}},
		{{Text: "Retired"}, {Text: stamp(m.GetRetiredAt().AsTime().String(), m.GetRetiredAt() != nil)}},
		{{Text: "Version history"}, {HTML: link(p.versionsURL(m.GetId()), "Every version of this schema")}},
		{{Text: msg.T("issuer.mapping.title.label")}, {HTML: link(p.mappingURL(m.GetId(), m.GetVersion()), msg.T("issuer.schemas.action.mapping.label"))}},
	}
	table, err := p.opts.Kit.HTML("table", components.Table{
		ID: "summary-table", Caption: "Schema summary", Columns: []string{"Field", "Value"}, Rows: rows,
	})
	if err != nil {
		return "", err
	}
	return p.opts.Kit.HTML("card", components.Card{ID: "summary", Title: "Summary", Body: table})
}

// stamp shows a timestamp, or a dash when the message has none.
func stamp(text string, present bool) string {
	if !present {
		return "-"
	}
	return text
}

// claimsCard lists the top level properties with the required and the
// selective disclosure flags.
func (p *Portal) claimsCard(m *schemav1.Schema) (template.HTML, error) {
	sd := map[string]bool{}
	for _, name := range m.GetSdClaims() {
		sd[name] = true
	}
	searchable := map[string]bool{}
	for _, name := range m.GetSearchableClaims() {
		searchable[name] = true
	}
	rows := make([]components.Row, 0)
	for _, c := range Claims(m.GetJsonSchema()) {
		rows = append(rows, components.Row{
			{Text: c.Name}, {Text: c.Title}, {Text: c.Type},
			{Text: yesNo(c.Required)}, {Text: yesNo(sd[c.Name])}, {Text: yesNo(searchable[c.Name])},
		})
	}
	table, err := p.opts.Kit.HTML("table", components.Table{
		ID: "claims-table", Caption: "Claims of this version",
		Columns: []string{"Property", "Label", "Type", "Required", "Selectively disclosable", "Searchable"},
		Rows:    rows, Empty: "The document declares no property.",
	})
	if err != nil {
		return "", err
	}
	return p.opts.Kit.HTML("card", components.Card{ID: "claims", Title: "Claims", Body: table})
}

func yesNo(v bool) string {
	if v {
		return "Yes"
	}
	return "No"
}

// actionsCard renders the publish and the retire forms that the state
// allows. csrf is the hidden field that binds each form to the session.
// A draft publishes only on a stack that takes schemas in every format
// of the version.
func (p *Portal) actionsCard(m *schemav1.Schema, csrf template.HTML, t target) (template.HTML, error) {
	action := p.opts.Prefix + "/schemas/" + url.PathEscape(m.GetId())
	hidden := csrf + template.HTML(`<input type="hidden" name="version" value="`+strconv.Itoa(int(m.GetVersion()))+`">`) //nolint:gosec // the value is a number
	switch m.GetState() {
	case schemav1.State_STATE_DRAFT:
		if text, ok := t.blocked(m); !ok {
			return p.opts.Kit.HTML("card", components.Card{ID: "actions", Title: "Actions", Text: text})
		}
		button, err := p.opts.Kit.HTML("button", components.Button{Text: "Publish this version", Type: "submit", Variant: "primary"})
		if err != nil {
			return "", err
		}
		body := components.Join(
			template.HTML(`<form action="`+template.HTMLEscapeString(action)+`/publish" method="post">`), //nolint:gosec // the action is escaped
			hidden, button, template.HTML(`</form>`))
		text := "Publish registers this version with the DPG. A published version cannot change."
		if t.name != "" {
			text = msg.T("issuer.schemas.target.text", t.name)
		}
		return p.opts.Kit.HTML("card", components.Card{ID: "actions", Title: "Actions", Text: text, Body: body})
	case schemav1.State_STATE_PUBLISHED:
		reason, err := p.opts.Kit.HTML("field", components.Field{
			ID: "reason", Label: "Reason", Hint: "The reason goes to the audit log.", Required: true,
			Attrs: map[string]string{"maxlength": strconv.Itoa(MaxReasonLength)},
		})
		if err != nil {
			return "", err
		}
		button, err := p.opts.Kit.HTML("button", components.Button{Text: "Retire this version", Type: "submit", Variant: "danger"})
		if err != nil {
			return "", err
		}
		body := components.Join(
			template.HTML(`<form action="`+template.HTMLEscapeString(action)+`/retire" method="post">`), //nolint:gosec // the action is escaped
			hidden, reason, button, template.HTML(`</form>`))
		return p.opts.Kit.HTML("card", components.Card{
			ID: "actions", Title: "Actions",
			Text: "Retire stops issuance with this version. Verifiers can still read it.",
			Body: body,
		})
	}
	return p.opts.Kit.HTML("card", components.Card{
		ID: "actions", Title: "Actions",
		Text: "This version is retired. It has no action left.",
	})
}

// versions renders the version history of one schema.
func (p *Portal) versions(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	resp, err := p.opts.Client.ListVersions(r.Context(), connect.NewRequest(&schemav1.ListVersionsRequest{Id: id}))
	if err != nil {
		return err
	}
	list := resp.Msg.GetSchemas()
	rows := make([]components.Row, 0, len(list))
	for _, m := range list {
		badge, badgeErr := p.opts.Kit.HTML("badge", components.Badge{Status: StateStatus(m.GetState()), Text: StateText(m.GetState())})
		if badgeErr != nil {
			return badgeErr
		}
		rows = append(rows, components.Row{
			{HTML: link(p.detailURL(m.GetId(), m.GetVersion()), "Version "+strconv.Itoa(int(m.GetVersion())))},
			{HTML: badge},
			{Text: stamp(m.GetCreatedAt().AsTime().String(), m.GetCreatedAt() != nil)},
			{Text: stamp(m.GetPublishedAt().AsTime().String(), m.GetPublishedAt() != nil)},
			{Text: stamp(m.GetRetiredAt().AsTime().String(), m.GetRetiredAt() != nil)},
			{Text: m.GetCreatedBy()},
		})
	}
	table, err := p.opts.Kit.HTML("table", components.Table{
		ID: "versions", Caption: "Version history, newest first",
		Columns: []string{"Version", "State", "Created", "Published", "Retired", "Created by"},
		Rows:    rows, Empty: "This schema has no version.",
	})
	if err != nil {
		return err
	}
	back, err := p.opts.Kit.HTML("button", components.Button{Text: "Back to the schema", Href: p.detailURL(id, 0)})
	if err != nil {
		return err
	}
	name := id
	if len(list) > 0 {
		name = Name(list[0])
	}
	return p.render(w, r, "versions", components.Page{
		Title:       "Version history of " + name,
		Heading:     "Version history",
		Description: "Every version of one schema, newest first.",
		Content:     components.Join(table, back),
	})
}

// publish moves one draft version to published.
func (p *Portal) publish(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	v, err := formVersion(r)
	if err != nil {
		return err
	}
	resp, err := p.opts.Client.Publish(r.Context(), connect.NewRequest(&schemav1.PublishRequest{Id: id, Version: v}))
	if err != nil {
		return err
	}
	p.redirect(w, r, id, resp.Msg.GetSchema().GetVersion(), "published")
	return nil
}

// retire moves one published version to retired.
func (p *Portal) retire(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	v, err := formVersion(r)
	if err != nil {
		return err
	}
	reason := strings.TrimSpace(r.FormValue("reason"))
	if len(reason) > MaxReasonLength {
		reason = reason[:MaxReasonLength]
	}
	if _, err := p.opts.Client.Retire(r.Context(), connect.NewRequest(&schemav1.RetireRequest{Id: id, Version: v, Reason: reason})); err != nil {
		return err
	}
	p.redirect(w, r, id, v, "retired")
	return nil
}

// formVersion reads the version field of an action form.
func formVersion(r *http.Request) (int32, error) {
	if err := r.ParseForm(); err != nil {
		return 0, connect.NewError(connect.CodeInvalidArgument, err)
	}
	raw := strings.TrimSpace(r.PostFormValue("version"))
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(raw, 10, 32)
	if err != nil || n < 0 {
		return 0, connect.NewError(connect.CodeInvalidArgument, errors.New("portal: the version must be a number"))
	}
	return int32(n), nil
}

// redirect sends the browser back to the detail page with a notice.
// An htmx request gets the target in the HX-Redirect header.
func (p *Portal) redirect(w http.ResponseWriter, r *http.Request, id string, v int32, code string) {
	target := p.detailURL(id, v)
	if strings.Contains(target, "?") {
		target += "&notice=" + code
	} else {
		target += "?notice=" + code
	}
	if components.IsHTMX(r) {
		w.Header().Set("HX-Redirect", target)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}
