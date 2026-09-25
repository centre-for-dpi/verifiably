// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/dcql"
	"github.com/centre-for-dpi/vc-adapters/core/pex"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	tmpl "github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/template"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// The DIF Presentation Exchange pages (ADR-042 decision 4). The list
// names the live verifier stacks that read PE and not DCQL, lists the
// saved PE queries, and shows the PE form of each DCQL query with what
// that form loses. The editor authors or imports a definition,
// validates it against PE 2.0, converts it to DCQL with the loss report
// shown, and saves it as a PE query or its DCQL form as a DCQL query.
// Every action is a plain form post, so the pages work without
// JavaScript.
//
//	GET  /pe/                the list
//	GET  /pe/new             the editor; ?from=<id> loads the PE form of a DCQL query
//	POST /pe/new             action=import, validate, convert, save, or save_dcql
//	GET  /pe/edit/{id}       the editor of a saved PE query
//	POST /pe/edit/{id}       the same actions; save stores a new version

// The actions of the editor.
const (
	peImport   = "import"
	peValidate = "validate"
	peConvert  = "convert"
	peSave     = "save"
	peSaveDCQL = "save_dcql"
)

// peState is what one post of the editor holds.
type peState struct {
	id, version         string
	name, purpose, text string
	action              string
}

// pePath is the path of the list.
func (p *Portal) pePath() string { return p.opts.Prefix + "/pe/" }

// needsPE returns the names of the live verifier stacks whose adapter
// reads PE and not DCQL. ok is false without a verifier frame.
func (p *Portal) needsPE(r *http.Request) ([]string, bool) {
	if p.opts.Shell == nil {
		return nil, false
	}
	f := p.opts.Shell.Frame(r.Context())
	var out []string
	for _, st := range f.Live(commonv1.Role_ROLE_VERIFIER) {
		protocols := st.Capabilities.GetProtocols()
		if hasProtocol(protocols, backendv1.Protocol_PROTOCOL_OID4VP_PEX) && !hasProtocol(protocols, backendv1.Protocol_PROTOCOL_OID4VP_DCQL) {
			out = append(out, f.Snapshot().StackName(st.Peer.Dpg))
		}
	}
	return out, true
}

// hasProtocol reports whether a protocol list holds one protocol.
func hasProtocol(list []backendv1.Protocol, want backendv1.Protocol) bool {
	for _, got := range list {
		if got == want {
			return true
		}
	}
	return false
}

// exchangeList renders the list page.
func (p *Portal) exchangeList(w http.ResponseWriter, r *http.Request) error {
	resp, err := p.opts.Client.ListTemplates(r.Context(), connect.NewRequest(&discoveryv1.ListTemplatesRequest{}))
	if err != nil {
		return err
	}
	b := p.blocks()
	parts := []template.HTML{p.peTabs(b), template.HTML(`<div class="form-actions">`) +
		b.add("button", components.Button{Text: msg.T("verifier.pe.new.label"), Href: p.pePath() + "new", Variant: "primary"}) +
		template.HTML(`</div>`)}
	if names, ok := p.needsPE(r); ok {
		text := msg.T("verifier.pe.stacks.none")
		if len(names) > 0 {
			text = msg.T("verifier.pe.stacks.some", strings.Join(names, ", "))
		}
		parts = append(parts, b.add("card", components.Card{ID: "pe-stacks", Title: msg.T("verifier.pe.stacks.label"), Text: text}))
	}
	var rows []components.Row
	var generated []template.HTML
	for i, t := range resp.Msg.GetTemplates() {
		rec := tmpl.FromProto(t)
		if rec.Kind == tmpl.KindPE {
			rows = append(rows, components.Row{
				{HTML: link(p.pePath()+"edit/"+url.PathEscape(t.GetId()), t.GetDisplayName())},
				{Text: strconv.Itoa(int(t.GetVersion()))},
				{Text: queryText(t)},
				{HTML: b.add("badge", dcqlBadge(rec))},
			})
			continue
		}
		generated = append(generated, p.generatedBlock(b, i, t))
	}
	if len(rows) > 0 {
		parts = append(parts, b.add("table", components.Table{
			ID: "pe-queries", Caption: msg.T("verifier.pe.saved.label"),
			Columns: []string{
				msg.T("verifier.pe.column.name.label"), msg.T("verifier.pe.column.version.label"),
				msg.T("verifier.pe.column.asks.label"), msg.T("verifier.pe.column.dcql.label"),
			},
			Rows: rows,
		}))
	}
	parts = append(parts, generated...)
	if len(resp.Msg.GetTemplates()) == 0 {
		parts = append(parts, b.add("empty", components.Empty{
			Title: msg.T("verifier.pe.empty.title"), Text: msg.T("verifier.pe.empty.text"),
			Action: components.Button{Text: msg.T("verifier.pe.new.label"), Href: p.pePath() + "new", Variant: "primary"},
		}))
	}
	if b.err != nil {
		return b.err
	}
	return p.render(w, r, "templates", components.Page{
		Title: msg.T("verifier.nav.pe.label"), Lead: msg.T("verifier.pe.lead"), Description: msg.T("verifier.pe.lead"),
		Content: components.Join(parts...), Toasts: notice(r.URL.Query().Get("notice")),
	})
}

// dcqlBadge says whether a PE query has a DCQL form without a loss.
func dcqlBadge(rec tmpl.Template) components.Badge {
	switch {
	case rec.DCQL != "":
		return components.Badge{Status: "ok", Text: msg.T("verifier.pe.dcql.lossless.label")}
	case len(rec.Queries) > 0:
		return components.Badge{Status: "warn", Text: msg.T("verifier.pe.dcql.lossy.label")}
	}
	return components.Badge{Status: "info", Text: msg.T("verifier.pe.dcql.none.label")}
}

// generatedBlock renders the PE form of one DCQL query with its loss
// report.
func (p *Portal) generatedBlock(b *blocks, i int, t *discoveryv1.PresentationTemplate) template.HTML {
	id := strconv.Itoa(i + 1)
	var body template.HTML
	q, err := dcql.Parse([]byte(t.GetDcql()))
	var def pex.Definition
	var report pex.Report
	if err == nil {
		def, report, err = pex.FromDCQL(q, t.GetId(), t.GetDisplayName(), t.GetPurpose())
	}
	if err != nil {
		body = paragraph(msg.T("verifier.pe.lossy"))
	} else {
		body = b.add("json", components.JSON{ID: "pe-" + id, Summary: msg.T("verifier.pe.definition.label"), Data: rawJSON(string(pex.Marshal(def)))}) +
			lossTable(b, "pe-loss-"+id, report)
	}
	body += template.HTML(`<div class="form-actions">`) +
		b.add("button", components.Button{Text: msg.T("verifier.pe.open.label"), Href: p.opts.Prefix + "/templates/" + url.PathEscape(t.GetId())}) +
		b.add("button", components.Button{Text: msg.T("verifier.pe.edit_as.label"), Href: p.pePath() + "new?from=" + url.QueryEscape(t.GetId())}) +
		template.HTML(`</div>`)
	return b.add("block", components.Block{
		ID: "query-" + id, Title: t.GetDisplayName(), Lead: queryText(t),
		Meta: msg.T("verifier.pe.version.label", strconv.Itoa(int(t.GetVersion()))), Body: body,
	})
}

// lossTable renders a loss report: the part and what the conversion
// loses there. A lossless report is one sentence.
func lossTable(b *blocks, id string, report pex.Report) template.HTML {
	if report.Lossless() {
		return paragraph(msg.T("verifier.pe.loss.none"))
	}
	rows := make([]components.Row, 0, len(report.Losses))
	for _, l := range report.Losses {
		rows = append(rows, components.Row{{HTML: breakable(l.Where)}, {Text: msg.T("verifier.pe.loss."+l.Code, l.Detail)}})
	}
	return b.add("table", components.Table{
		ID: id, Caption: msg.T("verifier.pe.loss.caption.label"),
		Columns: []string{msg.T("verifier.pe.loss.column.part.label"), msg.T("verifier.pe.loss.column.text.label")},
		Rows:    rows,
	})
}

// breakable renders a JSON Pointer or an id with a break chance after
// each slash and underscore, so a narrow column can wrap it.
func breakable(text string) template.HTML {
	var b strings.Builder
	for _, r := range text {
		b.WriteString(template.HTMLEscapeString(string(r)))
		if r == '/' || r == '_' {
			b.WriteString("<wbr>")
		}
	}
	return template.HTML(b.String()) //nolint:gosec // every character is escaped
}

// paragraph renders one escaped sentence.
func paragraph(text string) template.HTML {
	return template.HTML(`<p>` + template.HTMLEscapeString(text) + `</p>`) //nolint:gosec // the text is escaped
}

// peTabs renders the tabs between the two query languages.
func (p *Portal) peTabs(b *blocks) template.HTML {
	return b.add("tabs", components.Tabs{Label: msg.T("verifier.dcql.tabs.label"), Links: []components.Link{
		{Href: p.dcqlPath(), Text: msg.T("verifier.dcql.tab.dcql.label")},
		{Href: p.pePath(), Text: msg.T("verifier.dcql.tab.pe.label"), Current: true},
	}})
}

// peNew renders the editor of a new definition. ?from=<id> loads the PE
// form of a saved DCQL query.
func (p *Portal) peNew(w http.ResponseWriter, r *http.Request) error {
	st := peState{}
	if from := strings.TrimSpace(r.URL.Query().Get("from")); from != "" {
		resp, err := p.opts.Client.GetTemplate(r.Context(), connect.NewRequest(&discoveryv1.GetTemplateRequest{Id: from}))
		if err != nil {
			return err
		}
		t := tmpl.FromProto(resp.Msg.GetTemplate())
		data, err := t.PresentationExchange()
		if err != nil {
			return connect.NewError(connect.CodeFailedPrecondition, err)
		}
		st.name, st.purpose, st.text = t.DisplayName+" (PE)", t.Purpose, pretty(data)
	}
	return p.peEditor(w, r, st, nil)
}

// peEdit renders the editor of a saved PE query.
func (p *Portal) peEdit(w http.ResponseWriter, r *http.Request) error {
	resp, err := p.opts.Client.GetTemplate(r.Context(), connect.NewRequest(&discoveryv1.GetTemplateRequest{Id: r.PathValue("id")}))
	if err != nil {
		return err
	}
	t := resp.Msg.GetTemplate()
	if t.GetKind() != discoveryv1.TemplateKind_TEMPLATE_KIND_PE {
		return connect.NewError(connect.CodeNotFound, errors.New("portal: the query is not a PE query"))
	}
	st := peState{
		id: t.GetId(), version: strconv.Itoa(int(t.GetVersion())),
		name: t.GetDisplayName(), purpose: t.GetPurpose(), text: pretty([]byte(t.GetPresentationDefinition())),
	}
	return p.peEditor(w, r, st, nil)
}

// peOutcome is what an action of the editor shows beside the form.
type peOutcome struct {
	problems []string
	valid    bool
	dcqlText string
	report   *pex.Report
	failed   string
}

// pePost runs one action of the editor.
func (p *Portal) pePost(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, MaxFormBytes)
	if err := r.ParseMultipartForm(MaxFormBytes); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	f := r.PostForm
	st := peState{
		id: r.PathValue("id"), name: strings.TrimSpace(f.Get("display_name")), purpose: strings.TrimSpace(f.Get("purpose")),
		text: f.Get("definition"), action: f.Get("action"), version: f.Get("version"),
	}
	out := &peOutcome{}
	if st.action == peImport {
		text, err := uploaded(r)
		if err != nil {
			out.problems = append(out.problems, msg.T("verifier.pe.problem.file"))
			return p.peEditor(w, r, st, out)
		}
		st.text = text
	}
	d, problems := pex.Validate([]byte(st.text))
	for _, pr := range problems {
		out.problems = append(out.problems, pr.Error())
	}
	if len(problems) > 0 {
		return p.peEditor(w, r, st, out)
	}
	out.valid = true
	if st.action == peImport {
		st.name, st.purpose = firstText(st.name, d.Name, d.ID), firstText(st.purpose, d.Purpose)
		st.text = pretty([]byte(st.text))
	}
	converted, report, convErr := pex.ToDCQL(d)
	switch st.action {
	case peConvert:
		if convErr != nil {
			out.failed = convErr.Error()
		} else {
			out.dcqlText, out.report = pretty(anyval.Must(dcql.Marshal(converted.Query))), &report
		}
	case peSave:
		return p.peSave(w, r, st, d, out)
	case peSaveDCQL:
		if convErr != nil {
			out.failed = convErr.Error()
			return p.peEditor(w, r, st, out)
		}
		return p.peSaveDCQL(w, r, st, converted, out)
	}
	return p.peEditor(w, r, st, out)
}

// peSave stores the definition as a PE query: a new query from the new
// editor, a new version from the editor of a saved query.
func (p *Portal) peSave(w http.ResponseWriter, r *http.Request, st peState, d pex.Definition, out *peOutcome) error {
	st.name = firstText(st.name, d.Name)
	if st.name == "" {
		out.problems = append(out.problems, msg.T("verifier.pe.problem.name"))
		return p.peEditor(w, r, st, out)
	}
	t := &discoveryv1.PresentationTemplate{
		Id: st.id, DisplayName: st.name, Purpose: st.purpose,
		Kind: discoveryv1.TemplateKind_TEMPLATE_KIND_PE, PresentationDefinition: st.text,
	}
	var id string
	var err error
	if st.id == "" {
		var resp *connect.Response[discoveryv1.CreateTemplateResponse]
		if resp, err = p.opts.Client.CreateTemplate(r.Context(), connect.NewRequest(&discoveryv1.CreateTemplateRequest{Template: t})); err == nil {
			id = resp.Msg.GetTemplate().GetId()
		}
	} else {
		var resp *connect.Response[discoveryv1.VersionTemplateResponse]
		if resp, err = p.opts.Client.VersionTemplate(r.Context(), connect.NewRequest(&discoveryv1.VersionTemplateRequest{Template: t})); err == nil {
			id = resp.Msg.GetTemplate().GetId()
		}
	}
	if err != nil {
		out.failed = msg.T("verifier.dcql.problem.save") + " " + connectReason(err)
		return p.peEditor(w, r, st, out)
	}
	http.Redirect(w, r, p.pePath()+"edit/"+url.PathEscape(id)+"?notice=saved", http.StatusSeeOther)
	return nil
}

// peSaveDCQL stores the DCQL form of the definition as a DCQL query.
func (p *Portal) peSaveDCQL(w http.ResponseWriter, r *http.Request, st peState, c pex.Converted, out *peOutcome) error {
	name := firstText(st.name, c.Name)
	t := &discoveryv1.PresentationTemplate{
		DisplayName: name, Purpose: firstText(st.purpose, c.Purpose),
		Kind: discoveryv1.TemplateKind_TEMPLATE_KIND_DCQL, Dcql: string(anyval.Must(dcql.Marshal(c.Query))),
	}
	resp, err := p.opts.Client.CreateTemplate(r.Context(), connect.NewRequest(&discoveryv1.CreateTemplateRequest{Template: t}))
	if err != nil {
		out.failed = msg.T("verifier.dcql.problem.save") + " " + connectReason(err)
		return p.peEditor(w, r, st, out)
	}
	http.Redirect(w, r, p.opts.Prefix+"/templates/"+url.PathEscape(resp.Msg.GetTemplate().GetId())+"?notice=saved", http.StatusSeeOther)
	return nil
}

// uploaded reads the imported file, up to the size of a definition.
func uploaded(r *http.Request) (string, error) {
	file, _, err := r.FormFile("file")
	if err != nil {
		return "", err
	}
	defer anyval.Close(file)
	data, err := io.ReadAll(io.LimitReader(file, pex.MaxDefinitionBytes+1))
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", errors.New("portal: the file is empty")
	}
	return string(data), nil
}

// firstText returns the first value that is not empty.
func firstText(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// peEditor renders the editor with the outcome of an action.
func (p *Portal) peEditor(w http.ResponseWriter, r *http.Request, st peState, out *peOutcome) error {
	b := p.blocks()
	action := p.pePath() + "new"
	title := msg.T("verifier.pe.new.label")
	if st.id != "" {
		action = p.pePath() + "edit/" + url.PathEscape(st.id)
		title = st.name
	}
	fields := components.Join(
		b.add("field", components.Field{ID: "display_name", Label: msg.T("verifier.dcql.name.label"), Value: st.name, Hint: msg.T("verifier.pe.name.hint")}),
		b.add("field", components.Field{ID: "purpose", Label: msg.T("verifier.dcql.purpose.label"), Value: st.purpose, Hint: msg.T("verifier.dcql.purpose.hint")}),
		b.add("field", components.Field{ID: "definition", Label: msg.T("verifier.pe.definition.label"), Type: "textarea", Value: st.text,
			Hint: msg.T("verifier.pe.definition.hint"), Attrs: map[string]string{"rows": "18", "spellcheck": "false"}}),
		b.add("field", components.Field{ID: "file", Label: msg.T("verifier.pe.file.label"), Type: "file",
			Hint: msg.T("verifier.pe.file.hint"), Attrs: map[string]string{"accept": "application/json,.json"}}),
	)
	actions := template.HTML(`<div class="form-actions">`) +
		b.add("button", components.Button{Text: msg.T("verifier.pe.import.label"), Type: "submit", Name: "action", Value: peImport}) +
		b.add("button", components.Button{Text: msg.T("verifier.pe.validate.label"), Type: "submit", Name: "action", Value: peValidate}) +
		b.add("button", components.Button{Text: msg.T("verifier.pe.convert.label"), Type: "submit", Name: "action", Value: peConvert}) +
		b.add("button", components.Button{Text: msg.T("verifier.pe.save_dcql.label"), Type: "submit", Name: "action", Value: peSaveDCQL}) +
		b.add("button", components.Button{Text: msg.T("verifier.pe.save.label"), Type: "submit", Name: "action", Value: peSave, Variant: "primary"}) +
		template.HTML(`</div>`)
	meta := ""
	if st.version != "" {
		meta = msg.T("verifier.pe.version.label", st.version)
	}
	card := b.add("card", components.Card{ID: "pe-editor", Title: msg.T("verifier.pe.editor.label"), Text: meta, Body: fields + actions})
	result := p.peResult(b, out)
	if b.err != nil {
		return b.err
	}
	esc := template.HTMLEscapeString
	form := template.HTML(`<form method="post" enctype="multipart/form-data" action="`+esc(action)+`">`) + //nolint:gosec // the action is escaped
		staffsession.HiddenField(r.Context()) + hidden("version", st.version) +
		template.HTML(`<div class="split"><div>`) + card + template.HTML(`</div>`) + result + template.HTML(`</div></form>`)
	if out != nil && (len(out.problems) > 0 || out.failed != "") {
		w.WriteHeader(http.StatusBadRequest)
	}
	return p.render(w, r, "templates", components.Page{
		Title: title, Lead: msg.T("verifier.pe.editor.lead"), Description: msg.T("verifier.pe.editor.lead"),
		Content: components.Join(p.peTabs(b), form), Toasts: notice(r.URL.Query().Get("notice")),
	})
}

// peResult renders the outcome of the last action: the problems, the
// DCQL form, and what the conversion loses.
func (p *Portal) peResult(b *blocks, out *peOutcome) template.HTML {
	var body template.HTML
	switch {
	case out == nil:
		body = paragraph(msg.T("verifier.pe.result.idle"))
	case len(out.problems) > 0:
		body = paragraph(msg.T("verifier.pe.result.invalid"))
		items := make([]string, 0, len(out.problems))
		for _, pr := range out.problems {
			items = append(items, `<li>`+template.HTMLEscapeString(pr)+`</li>`)
		}
		body += template.HTML(`<ul class="error">` + strings.Join(items, "") + `</ul>`) //nolint:gosec // every item is escaped
	case out.valid:
		body = paragraph(msg.T("verifier.pe.result.valid"))
	}
	if out != nil && out.failed != "" {
		body += template.HTML(`<p class="error">` + template.HTMLEscapeString(out.failed) + `</p>`) //nolint:gosec // the text is escaped
	}
	if out != nil && out.report != nil {
		body += b.add("code", components.Code{ID: "pe-dcql", Label: "dcql_query", Text: out.dcqlText}) + lossTable(b, "pe-loss", *out.report)
	}
	return b.add("block", components.Block{ID: "pe-result", Title: msg.T("verifier.pe.result.label"), Lead: msg.T("verifier.pe.result.lead"), Body: body})
}
