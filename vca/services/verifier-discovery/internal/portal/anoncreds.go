// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"context"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/anoncreds"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	tmpl "github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/template"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// The AnonCreds proof request builder (P6-C6, ADR-061 decision 4).
// Staff pick an AnonCreds schema of a live verifier stack, tick the
// attributes the holder reveals, set the predicates the holder proves
// without the value, and save the result as a native query. The page
// draws the proof request the wallet receives on every form post, so it
// works without JavaScript. With htmx a change of the form swaps the
// preview, and a change of the schema swaps the attributes too. The
// builder shows only when a live verifier stack lists
// FEATURE_ANONCREDS_PROOF.
//
//	GET  /anoncreds/          the builder, ?schema=<id> picks a schema, ?from=<id> opens a saved query
//	POST /anoncreds/          action=preview draws the page again, action=save stores the query
//	POST /anoncreds/preview   the preview fragment for htmx

// StackSchemas is what one live verifier stack answers to
// ListProofSchemas: the name of the stack and its AnonCreds schemas.
type StackSchemas struct {
	// Stack is the name of the stack, as its adapter reports it.
	Stack string
	// Schemas are the AnonCreds schemas the stack knows.
	Schemas []*backendv1.ProofSchema
}

// anonState is what one post of the builder holds.
type anonState struct {
	id, name, purpose string
	schema, shown     string
	credDef           string
	reveal            map[string]bool
	ops, values       map[string]string
	trusted           bool
}

// anonPath is the path of the builder.
func (p *Portal) anonPath() string { return p.opts.Prefix + "/anoncreds/" }

// proofSchemas returns the stacks with AnonCreds proofs, or none.
func (p *Portal) proofSchemas(ctx context.Context) []StackSchemas {
	if p.opts.ProofSchemas == nil {
		return nil
	}
	return p.opts.ProofSchemas(ctx)
}

// anonCredsLive reports whether a live verifier stack asks for
// AnonCreds proofs.
func (p *Portal) anonCredsLive(ctx context.Context) bool { return len(p.proofSchemas(ctx)) > 0 }

// queryTabs renders the tabs between the query languages. The AnonCreds
// tab shows only when a live stack asks for AnonCreds proofs.
func (p *Portal) queryTabs(ctx context.Context, b *blocks, current string) template.HTML {
	links := []components.Link{
		{Href: p.dcqlPath(), Text: msg.T("verifier.dcql.tab.dcql.label"), Current: current == "dcql"},
		{Href: p.pePath(), Text: msg.T("verifier.dcql.tab.pe.label"), Current: current == "pe"},
	}
	if p.anonCredsLive(ctx) {
		links = append(links, components.Link{Href: p.anonPath(), Text: msg.T("verifier.dcql.tab.anoncreds.label"), Current: current == "anoncreds"})
	}
	return b.add("tabs", components.Tabs{Label: msg.T("verifier.dcql.tabs.label"), Links: links})
}

// schemaChoice is one schema of the select, with the stack that knows it.
type schemaChoice struct {
	stack  string
	schema *backendv1.ProofSchema
}

// schemaChoices lists the schemas of every stack, each schema once.
func schemaChoices(stacks []StackSchemas) []schemaChoice {
	var out []schemaChoice
	seen := map[string]bool{}
	for _, st := range stacks {
		for _, s := range st.Schemas {
			if !seen[s.GetId()] {
				seen[s.GetId()] = true
				out = append(out, schemaChoice{stack: st.Stack, schema: s})
			}
		}
	}
	return out
}

// find returns the choice of a schema id.
func find(choices []schemaChoice, id string) (schemaChoice, bool) {
	for _, c := range choices {
		if c.schema.GetId() == id {
			return c, true
		}
	}
	return schemaChoice{}, false
}

// readAnonState reads the builder form, or the query string of a GET.
func readAnonState(r *http.Request) anonState {
	st := anonState{reveal: map[string]bool{}, ops: map[string]string{}, values: map[string]string{}}
	if r.Method == http.MethodGet {
		st.schema, st.trusted = strings.TrimSpace(r.URL.Query().Get("schema")), true
		return st
	}
	f := r.PostForm
	st.id, st.name, st.purpose = strings.TrimSpace(f.Get("id")), strings.TrimSpace(f.Get("display_name")), strings.TrimSpace(f.Get("purpose"))
	st.schema, st.shown, st.credDef = strings.TrimSpace(f.Get("schema")), f.Get("shown"), strings.TrimSpace(f.Get("creddef"))
	for _, a := range f["reveal"] {
		st.reveal[a] = true
	}
	for key, v := range f {
		switch {
		case strings.HasPrefix(key, "op:"):
			st.ops[strings.TrimPrefix(key, "op:")] = strings.TrimSpace(v[0])
		case strings.HasPrefix(key, "value:"):
			st.values[strings.TrimPrefix(key, "value:")] = strings.TrimSpace(v[0])
		}
	}
	st.trusted = slices.Contains(f["trust"], "issuer")
	return st
}

// fromTemplate fills the state from a saved AnonCreds query.
func fromTemplate(t *discoveryv1.PresentationTemplate) anonState {
	st := anonState{
		id: t.GetId(), name: t.GetDisplayName(), purpose: t.GetPurpose(), trusted: t.GetRequireTrustedIssuer(),
		reveal: map[string]bool{}, ops: map[string]string{}, values: map[string]string{},
	}
	req := anoncreds.FromProto(t.GetAnoncreds())
	take := func(r anoncreds.Restriction) {
		if st.schema == "" {
			st.schema, st.credDef = r.SchemaID, r.CredDefID
		}
	}
	for _, a := range req.Attributes {
		take(a.Restriction)
		for _, n := range a.Names {
			st.reveal[n] = true
		}
	}
	for _, pr := range req.Predicates {
		take(pr.Restriction)
		st.ops[pr.Name], st.values[pr.Name] = pr.Op, strconv.FormatInt(pr.Value, 10)
	}
	return st
}

// draft builds the query of the state against its schema. It returns
// the template and the problem that stops a save.
func (st anonState) draft(choice schemaChoice, ok bool) (tmpl.Template, string) {
	t := tmpl.Template{ID: st.id, DisplayName: st.name, Purpose: st.purpose, Kind: tmpl.KindNative, RequireTrustedIssuer: st.trusted}
	if !ok {
		return t, msg.T("verifier.anoncreds.problem.schema")
	}
	restriction := anoncreds.Restriction{SchemaID: choice.schema.GetId()}
	if slices.Contains(choice.schema.GetCredentialDefinitions(), st.credDef) {
		restriction.CredDefID = st.credDef
	}
	req := anoncreds.Request{Name: st.name}
	var revealed []string
	for _, a := range choice.schema.GetAttributes() {
		if st.reveal[a] {
			revealed = append(revealed, a)
		}
		op := st.ops[a]
		if op == "" {
			continue
		}
		n, err := strconv.ParseInt(st.values[a], 10, 64)
		if err != nil {
			return t, msg.T("verifier.anoncreds.problem.number", a)
		}
		req.Predicates = append(req.Predicates, anoncreds.Predicate{Name: a, Op: op, Value: n, Restriction: restriction})
	}
	if len(revealed) > 0 {
		req.Attributes = []anoncreds.Attribute{{Names: revealed, Restriction: restriction}}
	}
	t.AnonCreds = &req
	draft := t
	if draft.DisplayName == "" {
		draft.DisplayName = "draft"
	}
	built, err := tmpl.Build(draft)
	if err != nil {
		return t, msg.T("verifier.anoncreds.problem.request") + " " + strings.TrimPrefix(strings.TrimPrefix(err.Error(), "template: "), "anoncreds: ")
	}
	t.AnonCreds = built.AnonCreds
	return t, ""
}

// anonPage renders the builder for a GET and for a post without htmx.
func (p *Portal) anonPage(w http.ResponseWriter, r *http.Request) error {
	stacks := p.proofSchemas(r.Context())
	if len(stacks) == 0 {
		http.NotFound(w, r)
		return nil
	}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, MaxFormBytes)
		if err := r.ParseForm(); err != nil {
			return connect.NewError(connect.CodeInvalidArgument, err)
		}
	}
	st := readAnonState(r)
	if from := strings.TrimSpace(r.URL.Query().Get("from")); from != "" && r.Method == http.MethodGet {
		resp, err := p.opts.Client.GetTemplate(r.Context(), connect.NewRequest(&discoveryv1.GetTemplateRequest{Id: from}))
		if err != nil {
			return err
		}
		st = fromTemplate(resp.Msg.GetTemplate())
	}
	choices := schemaChoices(stacks)
	choice, ok := find(choices, st.schema)
	t, problem := st.draft(choice, ok)
	saving := r.Method == http.MethodPost && r.PostForm.Get("action") == "save"
	if saving {
		switch {
		case st.name == "":
			problem = msg.T("verifier.dcql.problem.name")
		case problem == "":
			id, err := p.saveAnon(r.Context(), t)
			if err == nil {
				http.Redirect(w, r, p.opts.Prefix+"/templates/"+url.PathEscape(id)+"?notice=saved", http.StatusSeeOther)
				return nil
			}
			problem = msg.T("verifier.dcql.problem.save") + " " + connectReason(err)
		}
	}
	b := p.blocks()
	st.shown = st.schema
	query := p.anonQueryCard(b, st, choices)
	attributes := template.HTML(`<div id="anoncreds-attributes">`) + p.anonAttributesCard(b, st, choice, ok) + template.HTML(`</div>`)
	trust := b.add("card", components.Card{ID: "anoncreds-trust", Title: msg.T("verifier.dcql.trust.label"), Body: b.add("choice", components.Choice{
		ID: "trust", Legend: msg.T("verifier.dcql.trust.legend.label"), Hint: msg.T("verifier.anoncreds.trust.hint"), Multiple: true,
		Options: []components.ChoiceOption{{Value: "issuer", Title: msg.T("verifier.dcql.trust.issuer.label"),
			Text: msg.T("verifier.dcql.trust.issuer.text"), Checked: st.trusted}},
	})})
	preview := p.anonPreview(b, t, choice, problem)
	actions := template.HTML(`<div class="form-actions">`) +
		b.add("button", components.Button{Text: msg.T("verifier.dcql.update.label"), Type: "submit", Name: "action", Value: "preview"}) +
		b.add("button", components.Button{Text: msg.T("verifier.dcql.save.label"), Type: "submit", Name: "action", Value: "save", Variant: "primary"}) +
		template.HTML(`</div>`)
	tabs := p.queryTabs(r.Context(), b, "anoncreds")
	if b.err != nil {
		return b.err
	}
	esc := template.HTMLEscapeString
	form := template.HTML(`<form method="post" action="`+esc(p.anonPath())+`" hx-post="`+esc(p.anonPath()+"preview")+ //nolint:gosec // the paths are escaped
		`" hx-trigger="change" hx-target="#anoncreds-preview" hx-swap="outerHTML">`) +
		staffsession.HiddenField(r.Context()) + hidden("shown", st.shown) + hidden("id", st.id) +
		template.HTML(`<div class="split"><div>`) + query + attributes + trust + actions + template.HTML(`</div>`) + preview + template.HTML(`</div></form>`)
	if problem != "" && saving {
		w.WriteHeader(http.StatusBadRequest)
	}
	return p.render(w, r, "dcql", components.Page{
		Title: msg.T("verifier.anoncreds.title.label"), Lead: msg.T("verifier.anoncreds.lead"), Description: msg.T("verifier.anoncreds.lead"),
		Content: components.Join(tabs, form),
	})
}

// saveAnon stores the query: a new query, or the next version of the
// query the builder opened.
func (p *Portal) saveAnon(ctx context.Context, t tmpl.Template) (string, error) {
	if t.ID == "" {
		resp, err := p.opts.Client.CreateTemplate(ctx, connect.NewRequest(&discoveryv1.CreateTemplateRequest{Template: t.ToProto()}))
		if err != nil {
			return "", err
		}
		return resp.Msg.GetTemplate().GetId(), nil
	}
	resp, err := p.opts.Client.VersionTemplate(ctx, connect.NewRequest(&discoveryv1.VersionTemplateRequest{Template: t.ToProto()}))
	if err != nil {
		return "", err
	}
	return resp.Msg.GetTemplate().GetId(), nil
}

// anonPreview answers the htmx post of the builder with the preview, and
// with the attributes of the new schema out of band when it changed.
func (p *Portal) anonPreview(b *blocks, t tmpl.Template, choice schemaChoice, problem string) template.HTML {
	var body template.HTML
	if problem != "" {
		body += template.HTML(`<p class="error">` + template.HTMLEscapeString(problem) + `</p>`) //nolint:gosec // the text is escaped
	}
	if t.AnonCreds != nil && problem == "" {
		body += b.add("code", components.Code{ID: "anoncreds-request-text", Label: "proof_request", Text: pretty(t.AnonCreds.JSON())})
	}
	return b.add("block", components.Block{ID: "anoncreds-preview", Title: msg.T("verifier.anoncreds.preview.label"),
		Lead: msg.T("verifier.anoncreds.preview.lead"), Meta: choice.stack, Body: body})
}

// anonPreviewPost answers the htmx post of the builder.
func (p *Portal) anonPreviewPost(w http.ResponseWriter, r *http.Request) error {
	stacks := p.proofSchemas(r.Context())
	if len(stacks) == 0 {
		http.NotFound(w, r)
		return nil
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxFormBytes)
	if err := r.ParseForm(); err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	st := readAnonState(r)
	choice, ok := find(schemaChoices(stacks), st.schema)
	t, problem := st.draft(choice, ok)
	b := p.blocks()
	out := p.anonPreview(b, t, choice, problem)
	if st.schema != st.shown {
		st.shown = st.schema
		out += template.HTML(`<div id="anoncreds-attributes" hx-swap-oob="true">`) + p.anonAttributesCard(b, st, choice, ok) + template.HTML(`</div>`) +
			template.HTML(`<input type="hidden" id="shown" name="shown" value="`+template.HTMLEscapeString(st.shown)+`" hx-swap-oob="true">`) //nolint:gosec // the value is escaped
	}
	if b.err != nil {
		return b.err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err := w.Write([]byte(out))
	return err
}

// anonQueryCard renders the name, the purpose, and the schema select.
func (p *Portal) anonQueryCard(b *blocks, st anonState, choices []schemaChoice) template.HTML {
	options := []components.Option{{Value: "", Text: msg.T("verifier.anoncreds.schema.none.label"), Selected: st.schema == ""}}
	for _, c := range choices {
		options = append(options, components.Option{
			Value: c.schema.GetId(), Selected: c.schema.GetId() == st.schema,
			Text: msg.T("verifier.anoncreds.schema.option.label", c.schema.GetName()+" "+c.schema.GetVersion(), c.stack),
		})
	}
	return b.add("card", components.Card{ID: "anoncreds-query", Title: msg.T("verifier.dcql.query.label"), Body: components.Join(
		b.add("field", components.Field{ID: "display_name", Label: msg.T("verifier.dcql.name.label"), Value: st.name,
			Hint: msg.T("verifier.anoncreds.name.hint"), Attrs: map[string]string{"placeholder": msg.T("verifier.dcql.name.placeholder.label")}}),
		b.add("field", components.Field{ID: "purpose", Label: msg.T("verifier.dcql.purpose.label"), Value: st.purpose, Hint: msg.T("verifier.dcql.purpose.hint")}),
		b.add("field", components.Field{ID: "schema", Label: msg.T("verifier.anoncreds.schema.label"), Type: "select", Options: options,
			Hint: msg.T("verifier.anoncreds.schema.hint")}),
	)})
}

// anonAttributesCard renders the attributes of the schema as tick
// cards, one predicate select and number for each attribute, and the
// credential definition select.
func (p *Portal) anonAttributesCard(b *blocks, st anonState, choice schemaChoice, ok bool) template.HTML {
	if !ok {
		return b.add("card", components.Card{ID: "anoncreds-attribute-card", Title: msg.T("verifier.anoncreds.attributes.label"),
			Text: msg.T("verifier.anoncreds.attributes.pick")})
	}
	s := choice.schema
	options := make([]components.ChoiceOption, 0, len(s.GetAttributes()))
	var predicates []template.HTML
	for i, a := range s.GetAttributes() {
		options = append(options, components.ChoiceOption{Value: a, Title: a, Text: msg.T("verifier.anoncreds.attribute.text"), Checked: st.reveal[a]})
		id := strconv.Itoa(i + 1)
		ops := []components.Option{{Value: "", Text: msg.T("verifier.anoncreds.op.none.label"), Selected: st.ops[a] == ""}}
		for _, op := range anoncreds.Ops {
			ops = append(ops, components.Option{Value: op, Text: op, Selected: st.ops[a] == op})
		}
		predicates = append(predicates,
			b.add("field", components.Field{ID: "op-" + id, Name: "op:" + a, Label: msg.T("verifier.anoncreds.op.label", a), Type: "select", Options: ops}),
			b.add("field", components.Field{ID: "value-" + id, Name: "value:" + a, Label: msg.T("verifier.anoncreds.value.label", a),
				Value: st.values[a], Hint: msg.T("verifier.anoncreds.value.hint"), Attrs: map[string]string{"inputmode": "numeric"}}))
	}
	defs := []components.Option{{Value: "", Text: msg.T("verifier.anoncreds.creddef.any.label"), Selected: st.credDef == ""}}
	for _, d := range s.GetCredentialDefinitions() {
		defs = append(defs, components.Option{Value: d, Text: d, Selected: d == st.credDef})
	}
	about := msg.T("verifier.anoncreds.schema.about", s.GetId(), s.GetOrganisation(), s.GetIssuerDid())
	return b.add("card", components.Card{ID: "anoncreds-attribute-card", Title: msg.T("verifier.anoncreds.attributes.label"), Text: about,
		Body: components.Join(
			b.add("choice", components.Choice{ID: "reveal", Legend: msg.T("verifier.anoncreds.reveal.label"), Hint: msg.T("verifier.anoncreds.reveal.hint"),
				Multiple: true, Options: options}),
			b.add("fieldset", components.Fieldset{ID: "predicates", Legend: msg.T("verifier.anoncreds.predicates.label"),
				Hint: msg.T("verifier.anoncreds.predicates.hint"), Body: components.Join(predicates...)}),
			b.add("field", components.Field{ID: "creddef", Label: msg.T("verifier.anoncreds.creddef.label"), Type: "select", Options: defs,
				Hint: msg.T("verifier.anoncreds.creddef.hint")}),
		)})
}

// anonCredsBlock renders the stored AnonCreds request of a native query
// on its detail page, with a link that opens it in the builder.
func (p *Portal) anonCredsBlock(ctx context.Context, b *blocks, t *discoveryv1.PresentationTemplate) template.HTML {
	req := anoncreds.FromProto(t.GetAnoncreds())
	out := b.add("json", components.JSON{ID: "anoncreds", Summary: msg.T("verifier.anoncreds.detail.label"), Open: true, Data: rawJSON(string(req.JSON()))})
	if p.anonCredsLive(ctx) {
		out += template.HTML(`<div class="form-actions">`) +
			b.add("button", components.Button{Text: msg.T("verifier.anoncreds.edit.label"), Href: p.anonPath() + "?from=" + url.QueryEscape(t.GetId())}) +
			template.HTML(`</div>`)
	}
	return out
}
