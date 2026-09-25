// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"bytes"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/dcql"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/catalog"
	tmpl "github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/template"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// The DCQL builder of board Verifier-DCQL (ADR-042 decisions 2 and 3).
// Staff pick a credential type of the catalogue, tick the claims, set
// accepted values and a date rule, choose the trust rules, and save the
// result as a query. The page draws the dcql_query the wallet receives
// on every form post, so it works without JavaScript. With htmx, a
// change of the form swaps the preview in place, and a change of the
// credential type swaps the claims too.
//
//	GET  /dcql/          the builder, with a type from the query string
//	POST /dcql/          action=preview draws the page again, action=save stores the query
//	POST /dcql/preview   the preview fragment for htmx

// builderState is what one post of the builder holds.
type builderState struct {
	name, purpose  string
	pick, shown    string
	issuer, kind   string
	format         string
	claims         map[string]bool
	values         map[string]string
	ops, rules     map[string]string
	trusted, alive bool
}

// dateOps are the operators of a date rule, in the order of the select.
var dateOps = []string{tmpl.OpAtLeastYears, tmpl.OpAtMostYears, tmpl.OpBefore, tmpl.OpAfter}

// pickOf encodes a credential type of the catalogue as one form value.
func pickOf(issuer, typeName, format string) string {
	if typeName == "" {
		return ""
	}
	return url.Values{"credential_issuer": {issuer}, "type": {typeName}, "format": {format}}.Encode()
}

// readState reads the builder form. A GET reads the type from the query
// string and turns both trust rules on.
func readState(r *http.Request) builderState {
	st := builderState{claims: map[string]bool{}, values: map[string]string{}, ops: map[string]string{}, rules: map[string]string{}}
	if r.Method == http.MethodGet {
		q := r.URL.Query()
		st.issuer, st.kind, st.format = strings.TrimSpace(q.Get("credential_issuer")), strings.TrimSpace(q.Get("type")), strings.TrimSpace(q.Get("format"))
		st.pick = pickOf(st.issuer, st.kind, st.format)
		st.trusted, st.alive = true, true
		return st
	}
	f := r.PostForm
	st.name, st.purpose = strings.TrimSpace(f.Get("display_name")), strings.TrimSpace(f.Get("purpose"))
	st.pick, st.shown = f.Get("pick"), f.Get("shown")
	if values, err := url.ParseQuery(st.pick); err == nil {
		st.issuer, st.kind, st.format = values.Get("credential_issuer"), values.Get("type"), values.Get("format")
	}
	for _, c := range f["claim"] {
		st.claims[c] = true
	}
	for key, v := range f {
		switch {
		case strings.HasPrefix(key, "values:"):
			st.values[strings.TrimPrefix(key, "values:")] = strings.TrimSpace(v[0])
		case strings.HasPrefix(key, "op:"):
			st.ops[strings.TrimPrefix(key, "op:")] = strings.TrimSpace(v[0])
		case strings.HasPrefix(key, "rule:"):
			st.rules[strings.TrimPrefix(key, "rule:")] = strings.TrimSpace(v[0])
		}
	}
	for _, t := range f["trust"] {
		st.trusted = st.trusted || t == "issuer"
		st.alive = st.alive || t == "status"
	}
	return st
}

// queryID is the credential query id of the chosen type.
func (st builderState) queryID() string {
	id := dcql.CleanID(st.kind)
	if i := strings.LastIndexAny(st.kind, "/#:"); i >= 0 && i < len(st.kind)-1 {
		id = dcql.CleanID(st.kind[i+1:])
	}
	if id == "" {
		return "credential"
	}
	return id
}

// isDate reports whether a field holds a date, so its constraint is a
// date rule rather than a list of values.
func isDate(f *discoveryv1.Field) bool {
	return f.GetFormat() == "date" || f.GetFormat() == "date-time" || strings.Contains(strings.ToLower(f.GetPath()), "date")
}

// typed turns one accepted value into the JSON type of its field.
func typed(f *discoveryv1.Field, text string) any {
	switch f.GetType() {
	case "integer", "number":
		if n, err := strconv.ParseFloat(text, 64); err == nil {
			return n
		}
	case "boolean":
		if b, err := strconv.ParseBool(text); err == nil {
			return b
		}
	}
	return text
}

// draft builds the template of the state from the fields of the type.
// It returns the template, the DCQL text to show, and a problem sentence
// when the query is not complete.
func (st builderState) draft(fields []*discoveryv1.Field) (tmpl.Template, string, string) {
	t := tmpl.Template{
		DisplayName: st.name, Purpose: st.purpose, Kind: tmpl.KindDCQL,
		RequireTrustedIssuer: st.trusted, RequireStatus: st.alive,
	}
	if st.kind == "" {
		return t, "", msg.T("verifier.dcql.problem.type")
	}
	format := st.format
	if format == "" {
		format = dcql.FormatSDJWT
	}
	sel := dcql.Selection{ID: st.queryID(), Format: format, Type: st.kind}
	for _, f := range fields {
		path := f.GetPath()
		if !st.claims[path] {
			continue
		}
		sel.Claims = append(sel.Claims, path)
		if isDate(f) {
			if op := st.ops[path]; op != "" {
				t.Predicates = append(t.Predicates, tmpl.Predicate{QueryID: sel.ID, Path: path, Op: op, Value: st.rules[path]})
			}
			continue
		}
		for _, v := range strings.Split(st.values[path], ",") {
			if v = strings.TrimSpace(v); v != "" {
				if sel.Values == nil {
					sel.Values = map[string][]any{}
				}
				sel.Values[path] = append(sel.Values[path], typed(f, v))
			}
		}
	}
	q, err := dcql.BuildRequest(dcql.Request{Selections: []dcql.Selection{sel}, Purpose: st.purpose,
		Sets: []dcql.Set{{Options: [][]string{{sel.ID}}, Required: true}}})
	if err != nil {
		return t, "", msg.T("verifier.dcql.problem.query") + " " + err.Error()
	}
	data, err := dcql.Marshal(q)
	if err != nil {
		return t, "", msg.T("verifier.dcql.problem.query") + " " + err.Error()
	}
	t.DCQL = string(data)
	if t.DisplayName == "" {
		t.DisplayName = "draft"
	}
	if _, err := tmpl.Build(t); err != nil {
		return t, pretty(data), msg.T("verifier.dcql.problem.query") + " " + err.Error()
	}
	t.DisplayName = st.name
	return t, pretty(data), ""
}

// pretty indents a JSON document for the preview.
func pretty(data []byte) string {
	var b bytes.Buffer
	if json.Indent(&b, data, "", "  ") != nil {
		return string(data)
	}
	return b.String()
}

// dcqlPath is the path of the builder.
func (p *Portal) dcqlPath() string { return p.opts.Prefix + "/dcql/" }

// fieldsOf reads the claims of the chosen type, or none without a type.
func (p *Portal) fieldsOf(r *http.Request, st builderState) ([]*discoveryv1.Field, error) {
	if st.kind == "" {
		return nil, nil
	}
	resp, err := p.opts.Client.GetFields(r.Context(), connect.NewRequest(&discoveryv1.GetFieldsRequest{
		CredentialIssuer: st.issuer, Type: st.kind,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg.GetFields(), nil
}

// dcqlPage renders the builder for a GET and for a post without htmx.
func (p *Portal) dcqlPage(w http.ResponseWriter, r *http.Request) error {
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, MaxFormBytes)
		if err := r.ParseForm(); err != nil {
			return connect.NewError(connect.CodeInvalidArgument, err)
		}
	}
	st := readState(r)
	fields, err := p.fieldsOf(r, st)
	if err != nil {
		return err
	}
	t, text, problem := st.draft(fields)
	if r.Method == http.MethodPost && r.PostForm.Get("action") == "save" {
		switch {
		case st.name == "":
			problem = msg.T("verifier.dcql.problem.name")
		case problem == "":
			saved, serr := p.opts.Client.CreateTemplate(r.Context(), connect.NewRequest(&discoveryv1.CreateTemplateRequest{Template: t.ToProto()}))
			if serr == nil {
				http.Redirect(w, r, p.opts.Prefix+"/templates/"+url.PathEscape(saved.Msg.GetTemplate().GetId())+"?notice=saved", http.StatusSeeOther)
				return nil
			}
			problem = msg.T("verifier.dcql.problem.save") + " " + connectReason(serr)
		}
	}
	types, err := p.opts.Client.ListCredentialTypes(r.Context(), connect.NewRequest(&discoveryv1.ListCredentialTypesRequest{}))
	if err != nil {
		return err
	}
	b := p.blocks()
	st.shown = st.pick
	tabs := b.add("tabs", components.Tabs{Label: msg.T("verifier.dcql.tabs.label"), Links: []components.Link{
		{Href: p.dcqlPath(), Text: msg.T("verifier.dcql.tab.dcql.label"), Current: true},
		{Href: p.opts.Prefix + "/pe/", Text: msg.T("verifier.dcql.tab.pe.label")},
	}})
	query := p.queryCard(b, st, types.Msg.GetTypes())
	claims := template.HTML(`<div id="dcql-claims">`) + p.claimsCard(b, st, fields) + template.HTML(`</div>`)
	trust := p.trustCard(b, st)
	preview := p.previewBlock(b, t, text, problem)
	actions := template.HTML(`<div class="form-actions">`) +
		b.add("button", components.Button{Text: msg.T("verifier.dcql.update.label"), Type: "submit", Name: "action", Value: "preview"}) +
		b.add("button", components.Button{Text: msg.T("verifier.dcql.save.label"), Type: "submit", Name: "action", Value: "save", Variant: "primary"}) +
		template.HTML(`</div>`)
	if b.err != nil {
		return b.err
	}
	esc := template.HTMLEscapeString
	form := template.HTML(`<form method="post" action="`+esc(p.dcqlPath())+`" hx-post="`+esc(p.dcqlPath()+"preview")+ //nolint:gosec // the paths are escaped
		`" hx-trigger="change" hx-target="#dcql-preview" hx-swap="outerHTML">`) +
		staffsession.HiddenField(r.Context()) + hidden("shown", st.shown) +
		template.HTML(`<div class="split"><div>`) + query + claims + trust + actions + template.HTML(`</div>`) + preview + template.HTML(`</div></form>`)
	if problem != "" && r.Method == http.MethodPost && r.PostForm.Get("action") == "save" {
		w.WriteHeader(http.StatusBadRequest)
	}
	return p.render(w, r, "dcql", components.Page{
		Title: msg.T("verifier.nav.dcql.label"), Lead: msg.T("verifier.dcql.lead"), Description: msg.T("verifier.dcql.lead"),
		Content: components.Join(tabs, form),
	})
}

// dcqlPreview answers the htmx post of the builder with the preview, and
// with the claims of the new type out of band when the type changed.
func (p *Portal) dcqlPreview(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, MaxFormBytes)
	if err := r.ParseForm(); err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	st := readState(r)
	fields, err := p.fieldsOf(r, st)
	if err != nil {
		return err
	}
	t, text, problem := st.draft(fields)
	b := p.blocks()
	out := p.previewBlock(b, t, text, problem)
	if st.pick != st.shown {
		st.shown = st.pick
		out += template.HTML(`<div id="dcql-claims" hx-swap-oob="true">`) + p.claimsCard(b, st, fields) + template.HTML(`</div>`) +
			template.HTML(`<input type="hidden" id="shown" name="shown" value="`+template.HTMLEscapeString(st.shown)+`" hx-swap-oob="true">`) //nolint:gosec // the value is escaped
	}
	if b.err != nil {
		return b.err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err = w.Write([]byte(out))
	return err
}

// hidden renders one hidden input with an id, so htmx can replace it.
func hidden(name, value string) template.HTML {
	esc := template.HTMLEscapeString
	return template.HTML(`<input type="hidden" id="` + esc(name) + `" name="` + esc(name) + `" value="` + esc(value) + `">`) //nolint:gosec // both parts are escaped
}

// queryCard renders the name, the purpose, and the credential type.
func (p *Portal) queryCard(b *blocks, st builderState, types []*discoveryv1.CredentialType) template.HTML {
	options := []components.Option{{Value: "", Text: msg.T("verifier.dcql.type.none.label"), Selected: st.pick == ""}}
	for _, t := range types {
		value := pickOf(t.GetCredentialIssuer(), t.GetType(), catalog.FormatName(t.GetFormat()))
		options = append(options, components.Option{
			Value: value, Selected: value == st.pick,
			Text: msg.T("verifier.dcql.type.option.label", displayName(t), catalog.FormatName(t.GetFormat()), t.GetCredentialIssuer()),
		})
	}
	return b.add("card", components.Card{ID: "dcql-query", Title: msg.T("verifier.dcql.query.label"), Body: components.Join(
		b.add("field", components.Field{ID: "display_name", Label: msg.T("verifier.dcql.name.label"), Value: st.name,
			Hint: msg.T("verifier.dcql.name.hint"), Attrs: map[string]string{"placeholder": msg.T("verifier.dcql.name.placeholder.label")}}),
		b.add("field", components.Field{ID: "purpose", Label: msg.T("verifier.dcql.purpose.label"), Value: st.purpose, Hint: msg.T("verifier.dcql.purpose.hint")}),
		b.add("field", components.Field{ID: "pick", Label: msg.T("verifier.dcql.type.label"), Type: "select", Options: options, Hint: msg.T("verifier.dcql.type.hint")}),
	)})
}

// claimsCard renders the claims of the type as tick cards, then one
// constraint input for each claim: accepted values, or a date rule.
func (p *Portal) claimsCard(b *blocks, st builderState, fields []*discoveryv1.Field) template.HTML {
	if len(fields) == 0 {
		text := msg.T("verifier.dcql.claims.pick")
		if st.kind != "" {
			text = msg.T("verifier.dcql.claims.none")
		}
		return b.add("card", components.Card{ID: "dcql-claim-card", Title: msg.T("verifier.dcql.claims.label"), Text: text})
	}
	options := make([]components.ChoiceOption, 0, len(fields))
	var rules []template.HTML
	for i, f := range fields {
		path := f.GetPath()
		options = append(options, components.ChoiceOption{Value: path, Title: path, Text: claimNote(f, st), Checked: st.claims[path]})
		id := strconv.Itoa(i + 1)
		if isDate(f) {
			ops := []components.Option{{Value: "", Text: msg.T("verifier.dcql.op.none.label"), Selected: st.ops[path] == ""}}
			for _, op := range dateOps {
				ops = append(ops, components.Option{Value: op, Text: msg.T("verifier.dcql.op." + op + ".label"), Selected: st.ops[path] == op})
			}
			rules = append(rules,
				b.add("field", components.Field{ID: "op-" + id, Name: "op:" + path, Label: msg.T("verifier.dcql.rule.label", path), Type: "select", Options: ops}),
				b.add("field", components.Field{ID: "rule-" + id, Name: "rule:" + path, Label: msg.T("verifier.dcql.rule.value.label", path), Value: st.rules[path],
					Hint: msg.T("verifier.dcql.rule.hint")}))
			continue
		}
		rules = append(rules, b.add("field", components.Field{ID: "values-" + id, Name: "values:" + path, Label: msg.T("verifier.dcql.values.label", path),
			Value: st.values[path], Hint: msg.T("verifier.dcql.values.hint")}))
	}
	choice := b.add("choice", components.Choice{ID: "claim", Legend: msg.T("verifier.dcql.claims.legend.label"), Hint: msg.T("verifier.dcql.claims.hint"),
		Multiple: true, Options: options})
	constraints := b.add("fieldset", components.Fieldset{ID: "constraints", Legend: msg.T("verifier.dcql.constraints.label"),
		Hint: msg.T("verifier.dcql.constraints.hint"), Body: components.Join(rules...)})
	return b.add("card", components.Card{ID: "dcql-claim-card", Title: msg.T("verifier.dcql.claims.label"), Body: components.Join(choice, constraints)})
}

// claimNote says what a claim holds and the constraint it has now.
func claimNote(f *discoveryv1.Field, st builderState) string {
	note := f.GetType()
	if f.GetTitle() != "" {
		note = f.GetTitle() + ", " + note
	}
	path := f.GetPath()
	switch {
	case isDate(f) && st.ops[path] != "" && st.rules[path] != "":
		note = msg.T("verifier.dcql.claim.rule", note, msg.T("verifier.dcql.op."+st.ops[path]+".label"), st.rules[path])
	case st.values[path] != "":
		note = msg.T("verifier.dcql.claim.values", note, st.values[path])
	}
	return note
}

// trustCard renders the two trust rules.
func (p *Portal) trustCard(b *blocks, st builderState) template.HTML {
	return b.add("card", components.Card{ID: "dcql-trust", Title: msg.T("verifier.dcql.trust.label"), Body: b.add("choice", components.Choice{
		ID: "trust", Legend: msg.T("verifier.dcql.trust.legend.label"), Hint: msg.T("verifier.dcql.trust.hint"), Multiple: true,
		Options: []components.ChoiceOption{
			{Value: "issuer", Title: msg.T("verifier.dcql.trust.issuer.label"), Text: msg.T("verifier.dcql.trust.issuer.text"), Checked: st.trusted},
			{Value: "status", Title: msg.T("verifier.dcql.trust.status.label"), Text: msg.T("verifier.dcql.trust.status.text"), Checked: st.alive},
		},
	})})
}

// previewBlock renders the dcql_query the wallet receives and the rules
// the policy service checks beside it.
func (p *Portal) previewBlock(b *blocks, t tmpl.Template, text, problem string) template.HTML {
	var body template.HTML
	if problem != "" {
		body += template.HTML(`<p class="error">` + template.HTMLEscapeString(problem) + `</p>`) //nolint:gosec // the text is escaped
	}
	if text != "" {
		body += b.add("code", components.Code{ID: "dcql-query-text", Label: "dcql_query", Text: text})
	}
	var rules []string
	if t.RequireTrustedIssuer {
		rules = append(rules, msg.T("verifier.dcql.trust.issuer.label"))
	}
	if t.RequireStatus {
		rules = append(rules, msg.T("verifier.dcql.trust.status.label"))
	}
	for _, pr := range t.Predicates {
		rules = append(rules, msg.T("verifier.dcql.rule.summary", pr.Path, msg.T("verifier.dcql.op."+pr.Op+".label"), pr.Value))
	}
	if len(rules) > 0 {
		rows := make([]components.Row, 0, len(rules))
		for _, r := range rules {
			rows = append(rows, components.Row{{Text: r}})
		}
		body += b.add("table", components.Table{ID: "dcql-rules", Caption: msg.T("verifier.dcql.rules.policy.label"),
			Columns: []string{msg.T("verifier.dcql.rules.column.rule.label")}, Rows: rows})
	}
	return b.add("block", components.Block{ID: "dcql-preview", Title: msg.T("verifier.dcql.preview.label"), Lead: msg.T("verifier.dcql.preview.lead"),
		Meta: formatMeta(t), Body: body})
}

// formatMeta names the format of the draft, or nothing.
func formatMeta(t tmpl.Template) string {
	q, err := dcql.Parse([]byte(t.DCQL))
	if err != nil || len(q.Credentials) == 0 {
		return ""
	}
	return q.Credentials[0].Format
}

// connectReason returns the message of a Connect error.
func connectReason(err error) string {
	var cerr *connect.Error
	if errors.As(err, &cerr) {
		return cerr.Message()
	}
	return err.Error()
}

// rulesTable lists the rules the policy service checks for a saved
// query, with the policy set that holds them.
func rulesTable(b *blocks, t *discoveryv1.PresentationTemplate) template.HTML {
	rec := tmpl.FromProto(t)
	var rows []components.Row
	if rec.RequireTrustedIssuer {
		rows = append(rows, components.Row{{Text: msg.T("verifier.dcql.trust.issuer.label")}, {Text: msg.T("verifier.dcql.trust.issuer.text")}})
	}
	if rec.RequireStatus {
		rows = append(rows, components.Row{{Text: msg.T("verifier.dcql.trust.status.label")}, {Text: msg.T("verifier.dcql.trust.status.text")}})
	}
	for _, pr := range rec.Predicates {
		rows = append(rows, components.Row{{Text: pr.Path}, {Text: msg.T("verifier.dcql.rule.summary", pr.Path, msg.T("verifier.dcql.op."+pr.Op+".label"), pr.Value)}})
	}
	caption := msg.T("verifier.dcql.rules.caption.label")
	if rec.PolicySetID != "" {
		caption = msg.T("verifier.dcql.rules.set.label", rec.PolicySetID)
	}
	return b.add("table", components.Table{
		ID: "rules", Caption: caption,
		Columns: []string{msg.T("verifier.dcql.rules.column.rule.label"), msg.T("verifier.dcql.rules.column.text.label")},
		Rows:    rows, Empty: msg.T("verifier.dcql.rules.none"),
	})
}
