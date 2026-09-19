// SPDX-License-Identifier: Apache-2.0

// Package portal renders the verifier pages of the discovery service
// with the vca UI kit (ADR-022 decision 2). Staff browse the issuers and
// the credential types, inspect the fields of one type, tick the claims
// a request asks for, and save the selection as a presentation template.
//
// Paths, under the configured prefix:
//
//	GET  /                      the issuer list with the crawl action
//	POST /crawl                 run a crawl now
//	GET  /types                 the credential type list with filters
//	GET  /fields                the fields of one type with a save form
//	POST /templates             save the selection as a new template
//	GET  /templates             the template list
//	GET  /templates/{id}        one template with its DCQL and its history
//	POST /templates/{id}/delete remove every version of one template
//
// Every action calls a DiscoveryService RPC, so the pages and the API
// cannot diverge.
package portal

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"connectrpc.com/connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1/discoveryv1connect"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/catalog"
	tmpl "github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/template"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// DefaultPrefix is the URL prefix of the pages.
const DefaultPrefix = "/portal"

// MaxFormBytes caps a posted form.
const MaxFormBytes = 1 << 20

// Options configure the portal.
type Options struct {
	// Client calls the DiscoveryService. The service satisfies it in
	// process.
	Client discoveryv1connect.DiscoveryServiceClient
	// Kit renders the components. Nil builds a new kit.
	Kit *components.Kit
	// Prefix is the URL prefix of the pages. Empty means DefaultPrefix.
	Prefix string
}

// Portal serves the verifier pages.
type Portal struct {
	opts Options
}

// New builds the portal.
func New(opts Options) (*Portal, error) {
	if opts.Client == nil {
		return nil, errors.New("portal: a DiscoveryService client is required")
	}
	if opts.Prefix == "" {
		opts.Prefix = DefaultPrefix
	}
	opts.Prefix = "/" + strings.Trim(opts.Prefix, "/")
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
	mux.HandleFunc("GET "+p.opts.Prefix+"/{$}", p.handle(p.issuers))
	mux.HandleFunc("POST "+p.opts.Prefix+"/crawl", p.handle(p.crawl))
	mux.HandleFunc("GET "+p.opts.Prefix+"/types", p.handle(p.types))
	mux.HandleFunc("GET "+p.opts.Prefix+"/fields", p.handle(p.fields))
	mux.HandleFunc("GET "+p.opts.Prefix+"/templates", p.handle(p.templates))
	mux.HandleFunc("POST "+p.opts.Prefix+"/templates", p.handle(p.saveTemplate))
	mux.HandleFunc("GET "+p.opts.Prefix+"/templates/{id}", p.handle(p.templateDetail))
	mux.HandleFunc("POST "+p.opts.Prefix+"/templates/{id}/delete", p.handle(p.deleteTemplate))
}

// handle answers with a short sentence when a page fails. The error text
// never leaves the server log.
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
		case connect.CodeInvalidArgument, connect.CodeFailedPrecondition, connect.CodeAlreadyExists:
			return http.StatusBadRequest
		}
	}
	return http.StatusInternalServerError
}

// Formats lists the format filter choices in enum order.
var Formats = []commonv1.Format{
	commonv1.Format_FORMAT_VC_SD_JWT, commonv1.Format_FORMAT_DC_SD_JWT,
	commonv1.Format_FORMAT_JWT_VC_JSON, commonv1.Format_FORMAT_LDP_VC, commonv1.Format_FORMAT_MSO_MDOC,
}

// ParseFormat reads a format query value. An unknown value means any
// format.
func ParseFormat(value string) commonv1.Format {
	for _, f := range Formats {
		if catalog.FormatName(f) == strings.TrimSpace(value) {
			return f
		}
	}
	return commonv1.Format_FORMAT_UNSPECIFIED
}

// TrustText returns the reader facing words of a trust outcome.
func TrustText(outcome trustv1.TrustLookupResponse_Outcome) string {
	switch outcome {
	case trustv1.TrustLookupResponse_OUTCOME_TRUSTED:
		return "Trusted"
	case trustv1.TrustLookupResponse_OUTCOME_UNTRUSTED:
		return "Not trusted"
	case trustv1.TrustLookupResponse_OUTCOME_UNAVAILABLE:
		return "Registry unavailable"
	}
	return "Unknown"
}

// Notices maps a notice code to the sentence the page shows.
var Notices = map[string]components.Toast{
	"crawled": {Level: "ok", Text: "The crawl finished. The catalogue shows the new metadata."},
	"saved":   {Level: "ok", Text: "The template is saved. The ingestion service can use it now."},
	"deleted": {Level: "warn", Text: "The template is removed. Every version is gone."},
}

// notice returns the toast of a notice query value.
func notice(value string) []components.Toast {
	if t, ok := Notices[value]; ok {
		return []components.Toast{t}
	}
	return nil
}

// nav returns the navigation of every page.
func (p *Portal) nav(current string) components.Nav {
	return components.Nav{
		Label: "Verifier discovery",
		Brand: components.Link{Href: p.opts.Prefix + "/", Text: "Verifier discovery"},
		Links: []components.Link{
			{Href: p.opts.Prefix + "/", Text: "Issuers", Current: current == "issuers"},
			{Href: p.opts.Prefix + "/types", Text: "Credential types", Current: current == "types"},
			{Href: p.opts.Prefix + "/templates", Text: "Templates", Current: current == "templates"},
		},
	}
}

// link renders one anchor. Both parts are escaped.
func link(href, text string) template.HTML {
	return template.HTML(`<a href="` + template.HTMLEscapeString(href) + `">` + template.HTMLEscapeString(text) + `</a>`) //nolint:gosec // both parts are escaped
}

// blocks renders components and keeps the first error. A component
// fails only when its data is wrong, which is a programming fault, so
// one check for each page is enough.
type blocks struct {
	kit *components.Kit
	err error
}

// add renders one component and returns its markup.
func (b *blocks) add(name string, data any) template.HTML {
	if b.err != nil {
		return ""
	}
	h, err := b.kit.HTML(name, data)
	if err != nil {
		b.err = err
	}
	return h
}

// blocks returns a renderer over the kit of the portal.
func (p *Portal) blocks() *blocks { return &blocks{kit: p.opts.Kit} }

// form wraps content in a form element.
func form(action, method string, content ...template.HTML) template.HTML {
	open := `<form class="filters" action="` + template.HTMLEscapeString(action) + `" method="` + template.HTMLEscapeString(method) + `">`
	parts := append([]template.HTML{template.HTML(open)}, content...) //nolint:gosec // both parts are escaped
	return components.Join(append(parts, template.HTML(`</form>`))...)
}

// issuers renders the issuer list.
func (p *Portal) issuers(w http.ResponseWriter, r *http.Request) error {
	resp, err := p.opts.Client.ListIssuers(r.Context(), connect.NewRequest(&discoveryv1.ListIssuersRequest{}))
	if err != nil {
		return err
	}
	b := p.blocks()
	rows := make([]components.Row, 0, len(resp.Msg.GetIssuers()))
	for _, issuer := range resp.Msg.GetIssuers() {
		badge := b.add("badge", components.Badge{Status: trustStatus(issuer.GetTrust()), Text: TrustText(issuer.GetTrust())})
		name := issuer.GetDisplayName()
		if name == "" {
			name = issuer.GetCredentialIssuer()
		}
		rows = append(rows, components.Row{
			{HTML: link(p.opts.Prefix+"/types?credential_issuer="+url.QueryEscape(issuer.GetCredentialIssuer()), name)},
			{Text: issuer.GetCredentialIssuer()},
			{HTML: badge},
			{Text: strconv.Itoa(int(issuer.GetTypeCount()))},
			{Text: crawledText(issuer)},
		})
	}
	table := b.add("table", components.Table{
		ID: "issuers", Caption: fmt.Sprintf("Trusted issuers, %d found", len(rows)),
		Columns: []string{"Issuer", "URL", "Trust", "Types", "Last crawl"},
		Rows:    rows, Empty: "The catalogue is empty. Run a crawl to read the trusted issuers.",
	})
	action := b.add("button", components.Button{Text: "Crawl now", Type: "submit", Variant: "primary"})
	if b.err != nil {
		return b.err
	}
	return p.opts.Kit.RenderPage(w, r, components.Page{
		Title:       "Trusted issuers",
		Description: "Browse the issuers the trust registry lists and the credential types each one offers.",
		Nav:         p.nav("issuers"),
		Content:     components.Join(form(p.opts.Prefix+"/crawl", "post", action), table),
		Toasts:      notice(r.URL.Query().Get("notice")),
	})
}

// crawledText returns the reader facing time of the last crawl.
func crawledText(issuer *discoveryv1.Issuer) string {
	if issuer.GetLastError() != "" {
		return "Failed: " + issuer.GetLastError()
	}
	if issuer.GetCrawledAt() == nil {
		return "Never"
	}
	return issuer.GetCrawledAt().AsTime().UTC().Format("2006-01-02 15:04 UTC")
}

// trustStatus returns the badge status of a trust outcome.
func trustStatus(outcome trustv1.TrustLookupResponse_Outcome) string {
	switch outcome {
	case trustv1.TrustLookupResponse_OUTCOME_TRUSTED:
		return "ok"
	case trustv1.TrustLookupResponse_OUTCOME_UNTRUSTED:
		return "bad"
	case trustv1.TrustLookupResponse_OUTCOME_UNAVAILABLE:
		return "warn"
	}
	return "info"
}

// crawl runs one crawl and returns to the issuer list.
func (p *Portal) crawl(w http.ResponseWriter, r *http.Request) error {
	if _, err := p.opts.Client.Crawl(r.Context(), connect.NewRequest(&discoveryv1.CrawlRequest{})); err != nil {
		return err
	}
	http.Redirect(w, r, p.opts.Prefix+"/?notice=crawled", http.StatusSeeOther)
	return nil
}

// types renders the credential type list with its filters.
func (p *Portal) types(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	req := &discoveryv1.ListCredentialTypesRequest{
		CredentialIssuer: strings.TrimSpace(q.Get("credential_issuer")),
		Format:           ParseFormat(q.Get("format")),
		Query:            strings.TrimSpace(q.Get("q")),
	}
	resp, err := p.opts.Client.ListCredentialTypes(r.Context(), connect.NewRequest(req))
	if err != nil {
		return err
	}
	rows := make([]components.Row, 0, len(resp.Msg.GetTypes()))
	for _, t := range resp.Msg.GetTypes() {
		href := p.opts.Prefix + "/fields?credential_issuer=" + url.QueryEscape(t.GetCredentialIssuer()) +
			"&type=" + url.QueryEscape(t.GetType()) + "&format=" + url.QueryEscape(catalog.FormatName(t.GetFormat()))
		rows = append(rows, components.Row{
			{HTML: link(href, displayName(t))},
			{Text: t.GetType()},
			{Text: catalog.FormatName(t.GetFormat())},
			{Text: t.GetCredentialIssuer()},
		})
	}
	b := p.blocks()
	filters := p.typeFilters(b, req)
	table := b.add("table", components.Table{
		ID: "types", Caption: fmt.Sprintf("Credential types, %d found", len(rows)),
		Columns: []string{"Name", "Type", "Format", "Issuer"},
		Rows:    rows, Empty: "No credential type matches the filters.",
	})
	if b.err != nil {
		return b.err
	}
	return p.opts.Kit.RenderPage(w, r, components.Page{
		Title:       "Credential types",
		Description: "Find the credential type a presentation request asks for.",
		Nav:         p.nav("types"),
		Content:     components.Join(filters, table),
	})
}

// displayName returns the first display name of a type, or its type name.
func displayName(t *discoveryv1.CredentialType) string {
	if d := t.GetDisplay(); len(d) > 0 && d[0].GetName() != "" {
		return d[0].GetName()
	}
	return t.GetType()
}

// typeFilters renders the filter form of the type list.
func (p *Portal) typeFilters(b *blocks, req *discoveryv1.ListCredentialTypesRequest) template.HTML {
	options := []components.Option{{Value: "", Text: "Any format", Selected: req.GetFormat() == commonv1.Format_FORMAT_UNSPECIFIED}}
	for _, f := range Formats {
		name := catalog.FormatName(f)
		options = append(options, components.Option{Value: name, Text: name, Selected: f == req.GetFormat()})
	}
	return form(p.opts.Prefix+"/types", "get",
		b.add("field", components.Field{ID: "q", Label: "Search", Value: req.GetQuery(), Hint: "The search matches the type name and the display name."}),
		b.add("field", components.Field{ID: "credential_issuer", Label: "Issuer URL", Value: req.GetCredentialIssuer(), Hint: "Leave it empty to see every issuer."}),
		b.add("field", components.Field{ID: "format", Label: "Format", Type: "select", Options: options}),
		b.add("button", components.Button{Text: "Apply", Type: "submit", Variant: "primary"}),
	)
}

// fields renders the claims of one type with the save form.
func (p *Portal) fields(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	issuer := strings.TrimSpace(q.Get("credential_issuer"))
	typeName := strings.TrimSpace(q.Get("type"))
	resp, err := p.opts.Client.GetFields(r.Context(), connect.NewRequest(&discoveryv1.GetFieldsRequest{
		CredentialIssuer: issuer, Type: typeName,
	}))
	if err != nil {
		return err
	}
	b := p.blocks()
	selection := p.selectionForm(b, issuer, typeName, q.Get("format"), resp.Msg.GetFields())
	schema := b.add("json", components.JSON{
		ID: "schema", Summary: "JSON Schema document of the credential type", Data: rawJSON(resp.Msg.GetJsonSchema()),
	})
	if b.err != nil {
		return b.err
	}
	return p.opts.Kit.RenderPage(w, r, components.Page{
		Title:       "Claims of " + typeName,
		Heading:     "Claims of " + typeName,
		Description: "Tick the claims the presentation request asks for, then save the request as a template.",
		Nav:         p.nav("types"),
		Content:     components.Join(selection, schema),
	})
}

// selectionForm renders the claim tick boxes and the template fields.
func (p *Portal) selectionForm(b *blocks, issuer, typeName, format string, fields []*discoveryv1.Field) template.HTML {
	if format == "" {
		format = "dc+sd-jwt"
	}
	options := make([]components.Option, 0, len(Formats))
	for _, f := range Formats {
		name := catalog.FormatName(f)
		options = append(options, components.Option{Value: name, Text: name, Selected: name == format})
	}
	parts := []template.HTML{
		template.HTML(`<input type="hidden" name="credential_issuer" value="` + template.HTMLEscapeString(issuer) + `">`), //nolint:gosec // the value is escaped
		template.HTML(`<input type="hidden" name="type" value="` + template.HTMLEscapeString(typeName) + `">`),            //nolint:gosec // the value is escaped
		b.add("field", components.Field{ID: "display_name", Label: "Template name", Required: true, Hint: "Staff see this name in the template list."}),
		b.add("field", components.Field{ID: "purpose", Label: "Purpose", Hint: "The citizen reads this sentence before the wallet shares the claims."}),
		b.add("field", components.Field{ID: "format", Label: "Format", Type: "select", Options: options}),
	}
	for i, f := range fields {
		label := f.GetTitle()
		if label == "" {
			label = f.GetPath()
		}
		hint := f.GetType()
		if f.GetMandatory() {
			hint += ", the schema lists it as required"
		}
		if f.GetSelectivelyDisclosable() {
			hint += ", the holder can disclose it alone"
		}
		parts = append(parts, b.add("field", components.Field{
			ID: "claim-" + strconv.Itoa(i), Name: "claim", Label: label, Type: "checkbox", Value: f.GetPath(), Hint: hint,
		}))
	}
	parts = append(parts, b.add("button", components.Button{Text: "Save template", Type: "submit", Variant: "primary"}))
	return form(p.opts.Prefix+"/templates", "post", parts...)
}

// saveTemplate stores the selection of the fields page.
func (p *Portal) saveTemplate(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, MaxFormBytes)
	if err := r.ParseForm(); err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	query := &discoveryv1.PresentationTemplate_CredentialQuery{
		Type:   strings.TrimSpace(r.PostForm.Get("type")),
		Format: ParseFormat(r.PostForm.Get("format")),
		Claims: r.PostForm["claim"],
	}
	if issuer := strings.TrimSpace(r.PostForm.Get("credential_issuer")); issuer != "" {
		query.Issuers = []string{issuer}
	}
	req := &discoveryv1.CreateTemplateRequest{Template: &discoveryv1.PresentationTemplate{
		DisplayName: strings.TrimSpace(r.PostForm.Get("display_name")),
		Purpose:     strings.TrimSpace(r.PostForm.Get("purpose")),
		Queries:     []*discoveryv1.PresentationTemplate_CredentialQuery{query},
	}}
	resp, err := p.opts.Client.CreateTemplate(r.Context(), connect.NewRequest(req))
	if err != nil {
		return err
	}
	http.Redirect(w, r, p.opts.Prefix+"/templates/"+url.PathEscape(resp.Msg.GetTemplate().GetId())+"?notice=saved", http.StatusSeeOther)
	return nil
}

// templates renders the template list.
func (p *Portal) templates(w http.ResponseWriter, r *http.Request) error {
	resp, err := p.opts.Client.ListTemplates(r.Context(), connect.NewRequest(&discoveryv1.ListTemplatesRequest{}))
	if err != nil {
		return err
	}
	rows := make([]components.Row, 0, len(resp.Msg.GetTemplates()))
	for _, t := range resp.Msg.GetTemplates() {
		rows = append(rows, components.Row{
			{HTML: link(p.opts.Prefix+"/templates/"+url.PathEscape(t.GetId()), t.GetDisplayName())},
			{Text: strconv.Itoa(int(t.GetVersion()))},
			{Text: queryText(t)},
			{Text: t.GetPurpose()},
		})
	}
	b := p.blocks()
	table := b.add("table", components.Table{
		ID: "templates", Caption: fmt.Sprintf("Presentation templates, %d found", len(rows)),
		Columns: []string{"Name", "Latest version", "Asks for", "Purpose"},
		Rows:    rows, Empty: "No template exists. Open a credential type and tick the claims to make one.",
	})
	if b.err != nil {
		return b.err
	}
	return p.opts.Kit.RenderPage(w, r, components.Page{
		Title:       "Presentation templates",
		Description: "Reuse a saved presentation request in the ingestion service and the combined presentation service.",
		Nav:         p.nav("templates"),
		Content:     table,
		Toasts:      notice(r.URL.Query().Get("notice")),
	})
}

// queryText summarises what a template asks for.
func queryText(t *discoveryv1.PresentationTemplate) string {
	var parts []string
	for _, q := range t.GetQueries() {
		parts = append(parts, fmt.Sprintf("%s (%d claims)", q.GetType(), len(q.GetClaims())))
	}
	return strings.Join(parts, ", ")
}

// templateDetail renders one template with its DCQL and its history.
func (p *Portal) templateDetail(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	version := 0
	if n, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("version"))); err == nil && n > 0 {
		version = n
	}
	resp, err := p.opts.Client.GetTemplate(r.Context(), connect.NewRequest(&discoveryv1.GetTemplateRequest{
		Id: id, Version: int32(version),
	}))
	if err != nil {
		return err
	}
	t := resp.Msg.GetTemplate()
	b := p.blocks()
	summary := b.add("card", components.Card{
		ID: "summary", Title: t.GetDisplayName(),
		Text:   t.GetPurpose(),
		Footer: fmt.Sprintf("Version %d, asks for %s", t.GetVersion(), queryText(t)),
	})
	claims := p.claimsTable(b, t)
	query := b.add("json", components.JSON{ID: "dcql", Summary: "DCQL query the wallet receives", Open: true, Data: rawJSON(t.GetDcql())})
	exchange := p.presentationExchange(b, t)
	remove := b.add("button", components.Button{Text: "Delete template", Type: "submit", Variant: "danger"})
	if b.err != nil {
		return b.err
	}
	return p.opts.Kit.RenderPage(w, r, components.Page{
		Title:       t.GetDisplayName(),
		Description: "Read the stored presentation request and remove it when no service uses it.",
		Nav:         p.nav("templates"),
		Content: components.Join(summary, claims, query, exchange,
			form(p.opts.Prefix+"/templates/"+url.PathEscape(id)+"/delete", "post", remove)),
		Toasts: notice(r.URL.Query().Get("notice")),
	})
}

// claimsTable lists the claims of every credential query.
func (p *Portal) claimsTable(b *blocks, t *discoveryv1.PresentationTemplate) template.HTML {
	var rows []components.Row
	for _, q := range t.GetQueries() {
		for _, claim := range q.GetClaims() {
			rows = append(rows, components.Row{
				{Text: q.GetType()},
				{Text: catalog.FormatName(q.GetFormat())},
				{Text: claim},
				{Text: strings.Join(q.GetIssuers(), ", ")},
			})
		}
	}
	return b.add("table", components.Table{
		ID: "claims", Caption: "Claims the request asks for",
		Columns: []string{"Credential type", "Format", "Claim", "Issuers"},
		Rows:    rows, Empty: "The request asks for every claim of the credential.",
	})
}

// presentationExchange renders the generated Presentation Exchange 2.0
// definition, for a Digital Public Good that needs the older language.
func (p *Portal) presentationExchange(b *blocks, t *discoveryv1.PresentationTemplate) template.HTML {
	record := tmpl.Template{ID: t.GetId(), DCQL: t.GetDcql(), Purpose: t.GetPurpose()}
	data, err := record.PresentationExchange()
	if err != nil {
		return b.add("card", components.Card{
			ID: "exchange", Title: "Presentation Exchange 2.0",
			Text: "The service cannot generate the older query language from this template.",
		})
	}
	return b.add("json", components.JSON{
		ID: "exchange", Summary: "Presentation Exchange 2.0 definition for older wallets", Data: rawJSON(string(data)),
	})
}

// deleteTemplate removes one template and returns to the list.
func (p *Portal) deleteTemplate(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	if _, err := p.opts.Client.DeleteTemplate(r.Context(), connect.NewRequest(&discoveryv1.DeleteTemplateRequest{Id: id})); err != nil {
		return err
	}
	http.Redirect(w, r, p.opts.Prefix+"/templates?notice=deleted", http.StatusSeeOther)
	return nil
}

// rawJSON turns a JSON string into a value the json component renders.
func rawJSON(text string) any {
	if strings.TrimSpace(text) == "" {
		return map[string]any{}
	}
	var v any
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		return map[string]any{"document": text}
	}
	return v
}
