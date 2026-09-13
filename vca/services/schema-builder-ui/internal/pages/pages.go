// SPDX-License-Identifier: Apache-2.0

// Package pages renders the schema builder with the vca UI kit
// (ADR-014). The builder form posts to the preview endpoint on every
// edit, with the htmx trigger "input changed delay:250ms". The preview
// region is an aria-live region, so a screen reader hears the new preview
// (ADR-014 decision 4). Every control is a plain form control, so the
// pages work with the keyboard and without JavaScript.
//
// Paths, under the configured prefix:
//
//	GET  /                the builder page, with ?id= to open a stored schema
//	POST /preview         the live preview region
//	POST /fields          add or remove one field
//	POST /sample          fill the sample values from the schema
//	POST /save            save the draft in the schema registry
//	GET  /import          the import page
//	POST /import          import a JSON Schema document or a catalogue entry
package pages

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
	"github.com/centre-for-dpi/vc-adapters/core/preview"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1/schemav1connect"
	schemabuilderv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schemabuilder/v1"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/draft"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/pdfcache"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/wire"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// DefaultPrefix is the URL prefix of the builder pages.
const DefaultPrefix = "/builder"

// Debounce is the htmx trigger of the live preview (ADR-014 decision 1).
const Debounce = "input changed delay:250ms"

// MaxFormBytes caps the body of one form post.
const MaxFormBytes = 1 << 20

// Options configure the pages.
type Options struct {
	// Builder renders the previews and saves the drafts.
	Builder *service.Service
	// Registry opens a stored schema version in the builder.
	Registry schemav1connect.SchemaServiceClient
	// Kit renders the components. Nil builds a new kit.
	Kit *components.Kit
	// Prefix is the URL prefix of the pages. Empty means DefaultPrefix.
	Prefix string
	// RegistryURL links to the schema registry portal, when there is one.
	RegistryURL string
	// Catalog tells the import page that a DPG catalogue is configured.
	Catalog bool
}

// Pages serves the builder pages.
type Pages struct {
	opts Options
}

// New builds the pages.
func New(opts Options) (*Pages, error) {
	if opts.Builder == nil {
		return nil, errors.New("pages: a schema builder service is required")
	}
	if opts.Registry == nil {
		return nil, errors.New("pages: a SchemaService client is required")
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
	return &Pages{opts: opts}, nil
}

// Prefix returns the URL prefix of the pages.
func (p *Pages) Prefix() string { return p.opts.Prefix }

// Register adds the pages to mux.
func (p *Pages) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+p.opts.Prefix+"/{$}", p.handle(p.builder))
	mux.HandleFunc("POST "+p.opts.Prefix+"/preview", p.handle(p.preview))
	mux.HandleFunc("POST "+p.opts.Prefix+"/fields", p.handle(p.fields))
	mux.HandleFunc("POST "+p.opts.Prefix+"/sample", p.handle(p.sample))
	mux.HandleFunc("POST "+p.opts.Prefix+"/save", p.handle(p.save))
	mux.HandleFunc("GET "+p.opts.Prefix+"/import", p.handle(p.importPage))
	mux.HandleFunc("POST "+p.opts.Prefix+"/import", p.handle(p.runImport))
}

// handle answers with a short sentence when the page fails.
func (p *Pages) handle(fn func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
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

// form reads the posted form with a bounded body.
func form(r *http.Request) (url.Values, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, MaxFormBytes)
	if err := r.ParseForm(); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return r.PostForm, nil
}

// nav returns the navigation of every page.
func (p *Pages) nav(current string) components.Nav {
	n := components.Nav{
		Label: "Schema builder",
		Brand: components.Link{Href: p.opts.Prefix + "/", Text: "Schema builder"},
		Links: []components.Link{
			{Href: p.opts.Prefix + "/", Text: "Builder", Current: current == "builder"},
			{Href: p.opts.Prefix + "/import", Text: "Import", Current: current == "import"},
		},
	}
	if p.opts.RegistryURL != "" {
		n.Links = append(n.Links, components.Link{Href: p.opts.RegistryURL, Text: "Registry"})
	}
	return n
}

// state is everything one builder page shows.
type state struct {
	Draft  draft.Draft
	Sample string
	Format string
	Locale string
	Toasts []components.Toast
}

// read builds the state from a posted form.
func read(values url.Values) state {
	return state{
		Draft:  draft.Parse(values),
		Sample: values.Get("sample"),
		Format: values.Get("format"),
		Locale: values.Get("locale"),
	}
}

// builder renders the builder page. The id query value opens a stored
// version. An empty id starts a new schema.
func (p *Pages) builder(w http.ResponseWriter, r *http.Request) error {
	s := state{Draft: draft.Empty().Normalize()}
	if id := strings.TrimSpace(r.URL.Query().Get("id")); id != "" {
		resp, err := p.opts.Registry.Get(r.Context(), connect.NewRequest(&schemav1.GetRequest{Id: id, Version: version(r)}))
		if err != nil {
			return err
		}
		d, warnings, err := wire.DraftFromProto(resp.Msg.GetSchema())
		if err != nil {
			return connect.NewError(connect.CodeInvalidArgument, err)
		}
		s.Draft = d
		s.Toasts = warn(warnings)
	}
	s.Toasts = append(s.Toasts, notice(r.URL.Query().Get("notice"))...)
	return p.render(w, r, s)
}

// version reads the version query value. Zero means the latest version.
func version(r *http.Request) int32 {
	n, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("version")))
	if err != nil || n < 0 {
		return 0
	}
	return int32(n)
}

// Notices maps a notice code to the sentence the page shows.
var Notices = map[string]components.Toast{
	"saved":    {Level: "ok", Text: "The draft version is saved. Publish it in the schema registry."},
	"imported": {Level: "ok", Text: "The import is done. Check the draft, then save it."},
}

// notice returns the toast of a notice code, when the code is known.
func notice(code string) []components.Toast {
	if t, ok := Notices[code]; ok {
		return []components.Toast{t}
	}
	return nil
}

// warn turns import warnings into toasts.
func warn(list []string) []components.Toast {
	var out []components.Toast
	for _, text := range list {
		out = append(out, components.Toast{Level: "warn", Text: text})
	}
	return out
}

// fields adds or removes one field, then renders the page again.
func (p *Pages) fields(w http.ResponseWriter, r *http.Request) error {
	values, err := form(r)
	if err != nil {
		return err
	}
	s := read(values)
	if values.Get("add") != "" {
		s.Draft.Fields = append(s.Draft.Fields, draft.Field{
			Name: newName(s.Draft), Label: "New field", Type: "string",
		})
	}
	if raw := values.Get("remove"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 0 && n < len(s.Draft.Fields) {
			s.Draft.Fields = append(s.Draft.Fields[:n], s.Draft.Fields[n+1:]...)
		}
	}
	s.Draft = s.Draft.Normalize()
	return p.render(w, r, s)
}

// newName returns a field name the draft does not use yet.
func newName(d draft.Draft) string {
	used := map[string]bool{}
	for _, f := range d.Fields {
		used[f.Name] = true
	}
	for i := 1; ; i++ {
		n := "field_" + strconv.Itoa(i)
		if !used[n] {
			return n
		}
	}
}

// sample fills the sample values from the schema document.
func (p *Pages) sample(w http.ResponseWriter, r *http.Request) error {
	values, err := form(r)
	if err != nil {
		return err
	}
	s := read(values)
	s.Sample = ""
	return p.render(w, r, s)
}

// save stores the draft in the schema registry (ADR-014 decision 5).
func (p *Pages) save(w http.ResponseWriter, r *http.Request) error {
	values, err := form(r)
	if err != nil {
		return err
	}
	s := read(values)
	stored, err := p.opts.Builder.Save(r.Context(), s.Draft)
	if err != nil {
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			return err
		}
		s.Toasts = []components.Toast{{Level: "bad", Text: Message(err)}}
		return p.render(w, r, s)
	}
	target := p.opts.Prefix + "/?id=" + url.QueryEscape(stored.GetId()) +
		"&version=" + strconv.Itoa(int(stored.GetVersion())) + "&notice=saved"
	if components.IsHTMX(r) {
		w.Header().Set("HX-Redirect", target)
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
	return nil
}

// Message returns the sentence of a Connect error, without the code.
func Message(err error) string {
	var cerr *connect.Error
	if errors.As(err, &cerr) {
		return cerr.Message()
	}
	return err.Error()
}

// frag collects rendered components. It keeps the first render error in
// the shared error slot, so one page builds its whole body and checks the
// error once.
type frag struct {
	kit *components.Kit
	err *error
	out []template.HTML
}

// frag starts a fragment that reports into err.
func (p *Pages) frag(err *error) *frag {
	return &frag{kit: p.opts.Kit, err: err}
}

// add renders one component and appends it.
func (f *frag) add(name string, data any) *frag {
	h, err := f.kit.HTML(name, data)
	if err != nil && *f.err == nil {
		*f.err = err
	}
	f.out = append(f.out, h)
	return f
}

// raw appends markup the caller built.
func (f *frag) raw(h template.HTML) *frag {
	f.out = append(f.out, h)
	return f
}

// html returns everything the fragment holds.
func (f *frag) html() template.HTML { return components.Join(f.out...) }

// card wraps the fragment in a card component.
func (f *frag) card(c components.Card) template.HTML {
	c.Body = components.Join(append([]template.HTML{c.Body}, f.out...)...)
	out := f.kit
	h, err := out.HTML("card", c)
	if err != nil && *f.err == nil {
		*f.err = err
	}
	return h
}

// preview renders only the live view region.
func (p *Pages) preview(w http.ResponseWriter, r *http.Request) error {
	values, err := form(r)
	if err != nil {
		return err
	}
	var renderErr error
	region := p.previewRegion(&renderErr, read(values))
	if renderErr != nil {
		return renderErr
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err = w.Write([]byte(region))
	return err
}

// values returns the sample values of the state. An empty sample box
// takes the values the schema generates.
func (s state) values() (map[string]any, string) {
	if strings.TrimSpace(s.Sample) != "" {
		out := map[string]any{}
		_ = json.Unmarshal([]byte(s.Sample), &out)
		return out, s.Sample
	}
	out, err := preview.SampleData(s.Draft.Document())
	if err != nil {
		return map[string]any{}, ""
	}
	raw, _ := json.MarshalIndent(out, "", "  ")
	return out, string(raw)
}

// previewRegion renders the three live view tabs (ADR-014 decision 3).
// The region is an aria-live region, so a screen reader hears every new
// preview (ADR-014 decision 4).
func (p *Pages) previewRegion(err *error, s state) template.HTML {
	values, _ := s.values()
	f := p.frag(err)
	f.raw(`<div id="preview" class="preview" aria-live="polite">`)
	f.raw(p.previewBody(err, s, values))
	f.raw(`</div>`)
	return f.html()
}

// previewBody renders the tabs, or the reason the preview cannot render.
func (p *Pages) previewBody(err *error, s state, values map[string]any) template.HTML {
	view, renderErr := p.opts.Builder.Render(s.Draft.PreviewSchema(), values, preview.Options{
		Format: s.Format, Locale: s.Locale,
	})
	if renderErr != nil {
		return p.frag(err).card(components.Card{
			ID: "preview-error", Title: "No preview",
			Text: "The schema is not complete yet. " + Message(renderErr),
		})
	}
	f := p.frag(err)
	f.raw(p.problemsCard(err, append(s.Draft.Problems(), view.Problems...)))
	f.raw(p.tabs(err, view))
	return f.html()
}

// problemsCard lists the problems of the draft and of the sample.
func (p *Pages) problemsCard(err *error, problems []string) template.HTML {
	if len(problems) == 0 {
		return p.frag(err).card(components.Card{
			ID: "problems", Title: "Checks", Text: "The sample credential matches the schema.",
		})
	}
	items := make([]string, 0, len(problems))
	for _, text := range problems {
		items = append(items, "<li>"+template.HTMLEscapeString(text)+"</li>")
	}
	f := p.frag(err)
	f.raw(template.HTML("<ul>" + strings.Join(items, "") + "</ul>")) //nolint:gosec // every item is escaped
	return f.card(components.Card{
		ID: "problems", Title: "Checks", Text: "Fix these points before you save.",
	})
}

// tab is one live view tab.
type tab struct {
	id    string
	title string
	body  template.HTML
}

// tabs renders the three tabs as disclosure regions. The first tab is
// open. Every tab button is keyboard operable and carries aria-expanded.
func (p *Pages) tabs(err *error, view preview.Preview) template.HTML {
	document := p.frag(err)
	document.add("json", components.JSON{
		ID: "sample-json", Summary: "The sample credential document",
		Data: json.RawMessage(view.CredentialJSON), Open: true,
	})
	list := []tab{
		{id: "tab-json", title: "Sample credential JSON", body: document.html()},
		{id: "tab-card", title: "Wallet card", body: p.cardTab(err, view)},
		{id: "tab-pdf", title: "PDF preview", body: pdfTab(view)},
	}
	f := p.frag(err)
	f.raw(`<div class="tabs">`)
	for i, t := range list {
		f.add("button", components.Button{
			Text: t.title, Controls: t.id, Expanded: i == 0, Variant: "ghost",
		})
	}
	f.raw(`</div>`)
	for i, t := range list {
		open := ""
		if i > 0 {
			open = " hidden"
		}
		f.raw(template.HTML(`<div id="` + t.id + `" class="tab-panel"` + open + `>`)) //nolint:gosec // the id is a literal
		f.raw(t.body)
		f.raw(`</div>`)
	}
	return f.html()
}

// cardTab renders the wallet card tab from the OID4VCI display metadata.
func (p *Pages) cardTab(err *error, view preview.Preview) template.HTML {
	rows := make([]components.Row, 0, len(view.Card.Rows))
	for _, row := range view.Card.Rows {
		rows = append(rows, components.Row{
			{Text: row.Label}, {Text: row.Value}, {Text: yesNo(row.SelectivelyDisclosable)},
		})
	}
	f := p.frag(err)
	f.add("table", components.Table{
		ID: "card-rows", Caption: "The claims the wallet shows",
		Columns: []string{"Label", "Value", "Selectively disclosable"},
		Rows:    rows, Empty: "The schema declares no claim yet.",
	})
	return f.card(components.Card{
		ID: "wallet-card", Title: view.Card.Title, Text: view.Card.Description,
		Footer: "The wallet uses the format " + view.Format + ".",
	})
}

// pdfTab renders the PDF preview tab (ADR-016). The link opens the
// document the preview cache holds.
func pdfTab(view preview.Preview) template.HTML {
	ref := template.HTMLEscapeString(view.PDFRef)
	href := template.HTMLEscapeString(pdfcache.URL(view.PDFRef))
	return template.HTML(`<p>The PDF preview reference is <code>` + ref + //nolint:gosec // every part is escaped
		`</code>.</p><p><a href="` + href + `">Open the PDF preview document</a></p>`)
}

func yesNo(v bool) string {
	if v {
		return "Yes"
	}
	return "No"
}

// render writes the whole builder page.
func (p *Pages) render(w http.ResponseWriter, r *http.Request, s state) error {
	_, sample := s.values()
	s.Sample = sample
	var err error
	f := p.frag(&err)
	f.raw(p.editor(&err, s))
	f.raw(p.previewRegion(&err, s))
	if err != nil {
		return err
	}
	title := "Schema builder"
	if s.Draft.Title != "" {
		title = "Schema builder: " + s.Draft.Title
	}
	return p.opts.Kit.RenderPage(w, r, components.Page{
		Title:       title,
		Heading:     "Schema builder",
		Description: "Build a credential schema and see what a citizen will see.",
		Nav:         p.nav("builder"),
		Content:     f.html(),
		Toasts:      s.Toasts,
	})
}

// editor renders the builder form. The form posts to the preview
// endpoint on every edit, with a 250 millisecond debounce
// (ADR-014 decision 1).
func (p *Pages) editor(err *error, s state) template.HTML {
	prefix := template.HTMLEscapeString(p.opts.Prefix)
	f := p.frag(err)
	f.raw(template.HTML(`<form id="builder-form" method="post" action="` + prefix + `/save"` + //nolint:gosec // the prefix is escaped
		` hx-post="` + prefix + `/preview"` +
		` hx-trigger="` + Debounce + `" hx-target="#preview" hx-swap="outerHTML">`))
	f.raw(template.HTML(`<input type="hidden" name="id" value="` + template.HTMLEscapeString(s.Draft.ID) + `">`)) //nolint:gosec // the id is escaped
	f.raw(p.identityCard(err, s))
	f.raw(p.fieldCards(err, s.Draft))
	f.raw(p.sampleCard(err, s))
	f.raw(p.actions(err))
	f.raw(`</form>`)
	return f.html()
}

// yesNoOptions returns the options of a yes or no select.
func yesNoOptions(on bool) []components.Option {
	return []components.Option{
		{Value: "no", Text: "No", Selected: !on},
		{Value: "yes", Text: "Yes", Selected: on},
	}
}

// identityCard renders the credential identity and the wallet card style.
func (p *Pages) identityCard(err *error, s state) template.HTML {
	wireOptions := make([]components.Option, 0, len(draft.Formats))
	for _, format := range draft.Formats {
		wireOptions = append(wireOptions, components.Option{
			Value: format, Text: format, Selected: len(s.Draft.Wire) > 0 && s.Draft.Wire[0] == format,
		})
	}
	f := p.frag(err)
	f.add("field", components.Field{ID: "type", Label: "Credential type", Value: s.Draft.Type, Required: true,
		Hint: "The SD-JWT VC vct, or the VCDM type name.", Attrs: map[string]string{"autocomplete": "off"}})
	f.add("field", components.Field{ID: "title", Label: "Display name", Value: s.Draft.Title,
		Hint: "The name a wallet shows on the card."})
	f.add("field", components.Field{ID: "description", Label: "Description", Type: "textarea", Value: s.Draft.Description,
		Hint: "One sentence under the name.", Attrs: map[string]string{"rows": "2"}})
	f.add("field", components.Field{ID: "locale", Label: "Language tag", Value: s.Draft.Locale,
		Hint: "A BCP 47 tag, for example en or fr."})
	f.add("field", components.Field{ID: "logo_uri", Label: "Logo URL", Type: "url", Value: s.Draft.LogoURI})
	f.add("field", components.Field{ID: "background_color", Label: "Card background colour", Value: s.Draft.BackgroundColor,
		Hint: "A CSS hex value, for example #123456."})
	f.add("field", components.Field{ID: "text_color", Label: "Card text colour", Value: s.Draft.TextColor,
		Hint: "A CSS hex value."})
	f.add("field", components.Field{ID: "wire", Label: "Wire format", Type: "select", Options: wireOptions})
	f.add("field", components.Field{ID: "expires", Label: "The credential expires", Type: "select",
		Options: yesNoOptions(s.Draft.Expires)})
	return f.card(components.Card{
		ID: "identity", Title: "Credential", Text: "These values go to the OID4VCI display metadata.",
	})
}

// fieldCards renders one card per field, then the add button.
func (p *Pages) fieldCards(err *error, d draft.Draft) template.HTML {
	f := p.frag(err)
	for i, field := range d.Fields {
		f.raw(p.fieldCard(err, i, field))
	}
	f.add("button", components.Button{
		Text: "Add a field", Type: "submit", Variant: "secondary", Name: "add", Value: "1",
		Attrs: map[string]string{"formaction": p.opts.Prefix + "/fields"},
	})
	return f.html()
}

// fieldCard renders the controls of one field. Every flag is a select, so
// the control works with the keyboard and keeps its value on every post.
func (p *Pages) fieldCard(err *error, i int, field draft.Field) template.HTML {
	name := "field." + strconv.Itoa(i) + "."
	id := func(suffix string) string { return "field-" + strconv.Itoa(i) + "-" + suffix }
	types := make([]components.Option, 0, len(draft.FieldTypes))
	for _, t := range draft.FieldTypes {
		types = append(types, components.Option{Value: t, Text: t, Selected: t == field.Type})
	}
	formats := make([]components.Option, 0, len(draft.FieldFormats))
	for _, t := range draft.FieldFormats {
		text := t
		if t == "" {
			text = "No format"
		}
		formats = append(formats, components.Option{Value: t, Text: text, Selected: t == field.Format})
	}
	f := p.frag(err)
	f.add("field", components.Field{ID: id("name"), Name: name + "name", Label: "Property name", Value: field.Name, Required: true,
		Hint: "Letters, digits, and underscores. It starts with a letter.", Attrs: map[string]string{"autocomplete": "off"}})
	f.add("field", components.Field{ID: id("label"), Name: name + "label", Label: "Label", Value: field.Label})
	f.add("field", components.Field{ID: id("description"), Name: name + "description", Label: "Help text", Value: field.Description})
	f.add("field", components.Field{ID: id("type"), Name: name + "type", Label: "Type", Type: "select", Options: types})
	f.add("field", components.Field{ID: id("format"), Name: name + "format", Label: "Format", Type: "select", Options: formats,
		Hint: "A format applies to a string only."})
	f.add("field", components.Field{ID: id("enum"), Name: name + "enum", Label: "Allowed values", Value: draft.EnumText(field.Enum),
		Hint: "A comma separated list. An empty list allows any value."})
	f.add("field", components.Field{ID: id("required"), Name: name + "required", Label: "Required", Type: "select",
		Options: yesNoOptions(field.Required)})
	f.add("field", components.Field{ID: id("sd"), Name: name + "sd", Label: "Selectively disclosable", Type: "select",
		Options: yesNoOptions(field.SelectivelyDisclosable), Hint: "The holder can hide this claim in a presentation."})
	f.add("button", components.Button{
		Text: "Remove this field", Type: "submit", Variant: "danger", Name: "remove", Value: strconv.Itoa(i),
		AriaLabel: "Remove the field " + field.Name,
		Attrs:     map[string]string{"formaction": p.opts.Prefix + "/fields"},
	})
	return f.card(components.Card{ID: "field-" + strconv.Itoa(i), Title: "Field " + strconv.Itoa(i+1)})
}

// sampleCard renders the sample values box and the fill button.
func (p *Pages) sampleCard(err *error, s state) template.HTML {
	f := p.frag(err)
	f.add("field", components.Field{
		ID: "sample", Label: "Sample values", Type: "textarea", Value: s.Sample,
		Hint:  "A JSON object. The preview uses these values.",
		Attrs: map[string]string{"rows": "8", "spellcheck": "false"},
	})
	f.add("button", components.Button{
		Text: "Fill the sample from the schema", Type: "submit",
		Attrs: map[string]string{"formaction": p.opts.Prefix + "/sample"},
	})
	return f.card(components.Card{ID: "sample-card", Title: "Sample values"})
}

// actions renders the save button.
func (p *Pages) actions(err *error) template.HTML {
	f := p.frag(err)
	f.add("button", components.Button{Text: "Save the draft", Type: "submit", Variant: "primary"})
	return f.card(components.Card{
		ID: "actions", Title: "Save",
		Text: "Save stores a draft version in the schema registry. No DPG changes until you publish it.",
	})
}

// importPage renders the import page (ADR-014 decision 6).
func (p *Pages) importPage(w http.ResponseWriter, r *http.Request) error {
	return p.renderImport(w, r, nil)
}

// renderImport writes the import page with the toasts.
func (p *Pages) renderImport(w http.ResponseWriter, r *http.Request, toasts []components.Toast) error {
	var err error
	f := p.frag(&err)
	f.raw(p.documentCard(&err))
	f.raw(p.catalogCard(&err, r))
	if err != nil {
		return err
	}
	return p.opts.Kit.RenderPage(w, r, components.Page{
		Title:       "Import a schema",
		Heading:     "Import a schema",
		Description: "Import a JSON Schema document, or a credential type of the DPG.",
		Nav:         p.nav("import"),
		Content:     f.html(),
		Toasts:      toasts,
	})
}

// documentCard renders the JSON Schema import form.
func (p *Pages) documentCard(err *error) template.HTML {
	f := p.frag(err)
	f.raw(template.HTML(`<form method="post" action="` + template.HTMLEscapeString(p.opts.Prefix) + `/import">`)) //nolint:gosec // the prefix is escaped
	f.add("field", components.Field{ID: "import-type", Name: "type", Label: "Credential type",
		Hint: "Empty takes the title of the document.", Attrs: map[string]string{"autocomplete": "off"}})
	f.add("field", components.Field{ID: "json_schema", Label: "JSON Schema 2020-12 document", Type: "textarea", Required: true,
		Hint: "Paste the document here.", Attrs: map[string]string{"rows": "12", "spellcheck": "false"}})
	f.add("button", components.Button{Text: "Import the document", Type: "submit", Variant: "primary"})
	f.raw(`</form>`)
	return f.card(components.Card{
		ID: "import-document", Title: "From a JSON Schema document",
		Text: "The builder keeps the type, the title, the required flags, the formats, and the enums.",
	})
}

// catalogCard renders the DPG catalogue import form, or says why the
// deployment has no catalogue.
func (p *Pages) catalogCard(err *error, r *http.Request) template.HTML {
	if !p.opts.Catalog {
		return p.frag(err).card(components.Card{
			ID: "import-catalog", Title: "From the DPG catalogue",
			Text: "This deployment has no DPG catalogue. Import a document instead.",
		})
	}
	entries, catalogErr := p.opts.Builder.Catalog(r.Context())
	if catalogErr != nil {
		return p.frag(err).card(components.Card{
			ID: "import-catalog", Title: "From the DPG catalogue",
			Text: "The DPG catalogue did not answer. Try again later.",
		})
	}
	options := make([]components.Option, 0, len(entries))
	for _, e := range entries {
		text := e.GetId()
		if e.GetType() != "" {
			text = e.GetType() + " (" + e.GetId() + ")"
		}
		options = append(options, components.Option{Value: e.GetId(), Text: text})
	}
	if len(options) == 0 {
		return p.frag(err).card(components.Card{
			ID: "import-catalog", Title: "From the DPG catalogue",
			Text: "The DPG catalogue has no credential type.",
		})
	}
	f := p.frag(err)
	f.raw(template.HTML(`<form method="post" action="` + template.HTMLEscapeString(p.opts.Prefix) + `/import">`)) //nolint:gosec // the prefix is escaped
	f.add("field", components.Field{ID: "catalog_entry_id", Label: "Credential type of the DPG", Type: "select", Options: options})
	f.add("button", components.Button{Text: "Import the credential type", Type: "submit", Variant: "primary"})
	f.raw(`</form>`)
	return f.card(components.Card{
		ID: "import-catalog", Title: "From the DPG catalogue",
		Text: "The builder reads the credential types the DPG adapter knows.",
	})
}

// runImport reads the source and opens the draft in the builder. The
// author checks it, then saves it (ADR-014 decisions 5 and 6).
func (p *Pages) runImport(w http.ResponseWriter, r *http.Request) error {
	values, err := form(r)
	if err != nil {
		return err
	}
	req := &schemabuilderv1.ImportRequest{Type: values.Get("type")}
	switch {
	case strings.TrimSpace(values.Get("json_schema")) != "":
		req.Source = &schemabuilderv1.ImportRequest_JsonSchema{JsonSchema: values.Get("json_schema")}
	case strings.TrimSpace(values.Get("catalog_entry_id")) != "":
		req.Source = &schemabuilderv1.ImportRequest_CatalogEntryId{CatalogEntryId: values.Get("catalog_entry_id")}
	}
	d, warnings, err := p.opts.Builder.Read(r.Context(), req)
	if err != nil {
		return p.renderImport(w, r, []components.Toast{{Level: "bad", Text: Message(err)}})
	}
	return p.render(w, r, state{Draft: d, Toasts: append(notice("imported"), warn(warnings)...)})
}

// String returns the page prefix, so a log line can name it.
func (p *Pages) String() string { return fmt.Sprintf("pages(%s)", p.opts.Prefix) }
