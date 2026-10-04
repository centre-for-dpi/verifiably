// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	combinedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/combined/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/internal/rolenav"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// The combined query pages (ADR-026, ADR-079 decision 4). A combined
// query joins saved queries into one request, with rules that span two
// credentials. The combined service of the pair stores it. The pages
// show only when the own pair lists that service in the peer list.
//
//	GET  /combined/                the combined queries
//	GET  /combined/new             the form of a new combined query
//	POST /combined/new             store it
//	GET  /combined/edit/{id}       the form of a stored combined query
//	POST /combined/edit/{id}       store it again under its id
//	POST /combined/delete/{id}     remove it

// CombinedTemplates manages the combined templates of the combined
// service. The combined client is one.
type CombinedTemplates interface {
	List(context.Context, *connect.Request[combinedv1.ListRequest]) (*connect.Response[combinedv1.ListResponse], error)
	Get(context.Context, *connect.Request[combinedv1.GetRequest]) (*connect.Response[combinedv1.GetResponse], error)
	Create(context.Context, *connect.Request[combinedv1.CreateRequest]) (*connect.Response[combinedv1.CreateResponse], error)
	Update(context.Context, *connect.Request[combinedv1.UpdateRequest]) (*connect.Response[combinedv1.UpdateResponse], error)
	Delete(context.Context, *connect.Request[combinedv1.DeleteRequest]) (*connect.Response[combinedv1.DeleteResponse], error)
}

// The rule kinds of the form, in the order of the select.
const (
	ruleNone           = ""
	ruleSameSubject    = "same_subject"
	ruleDelegationLink = "delegation_link"
	ruleDateOrder      = "date_order"
)

// The values of the requirement of a rule.
const (
	ruleRequired = "required"
	ruleOptional = "optional"
)

// ruleKinds maps a form value onto its cross rule.
var ruleKinds = map[string]combinedv1.CrossRule{
	ruleSameSubject:    combinedv1.CrossRule_CROSS_RULE_SAME_SUBJECT,
	ruleDelegationLink: combinedv1.CrossRule_CROSS_RULE_DELEGATION_LINK,
	ruleDateOrder:      combinedv1.CrossRule_CROSS_RULE_DATE_ORDER,
}

// The parameter names of the cross rules, as the combined service reads
// them.
const (
	paramLeft        = "left"
	paramRight       = "right"
	paramClaim       = "claim"
	paramSubject     = "subject"
	paramDelegation  = "delegation"
	paramBeforeQuery = "before_query"
	paramBeforeClaim = "before_claim"
	paramAfterQuery  = "after_query"
	paramAfterClaim  = "after_claim"
)

// ruleRow is one rule of the form. first and second name the credential
// queries; the claims name a path in each.
type ruleRow struct {
	kind, name                             string
	first, second, firstClaim, secondClaim string
	// optional marks a rule that may skip. The zero value is required,
	// so a new rule starts required (ADR-080).
	optional bool
}

// combinedForm is what the form holds.
type combinedForm struct {
	id, name, policySet string
	members             map[string]bool
	groups              map[string]string
	rules               []ruleRow
	problem             string
}

// combinedPath is the path of the list.
func (p *Portal) combinedPath() string { return p.opts.Prefix + "/combined/" }

// combinedLive reports whether the combined pages show: the portal has a
// combined client, and the own pair lists the combined service, when
// the pages sit in a verifier frame.
func (p *Portal) combinedLive(ctx context.Context) bool {
	if p.opts.Combined == nil {
		return false
	}
	return p.opts.Shell == nil || p.opts.Shell.Frame(ctx).Runs(rolenav.CombinedService)
}

// registerCombined adds the combined pages to mux.
func (p *Portal) registerCombined(mux *http.ServeMux) {
	base := p.combinedPath()
	mux.HandleFunc("GET "+base+"{$}", p.handle(p.combinedOnly(p.combinedList)))
	mux.HandleFunc("GET "+base+"new", p.handle(p.combinedOnly(p.combinedNew)))
	mux.HandleFunc("POST "+base+"new", p.handle(p.combinedOnly(p.combinedSave)))
	mux.HandleFunc("GET "+base+"edit/{id}", p.handle(p.combinedOnly(p.combinedEdit)))
	mux.HandleFunc("POST "+base+"edit/{id}", p.handle(p.combinedOnly(p.combinedSave)))
	mux.HandleFunc("POST "+base+"delete/{id}", p.handle(p.combinedOnly(p.combinedDelete)))
}

// combinedOnly answers 404 while the combined pages are hidden.
func (p *Portal) combinedOnly(fn func(http.ResponseWriter, *http.Request) error) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		if !p.combinedLive(r.Context()) {
			http.NotFound(w, r)
			return nil
		}
		return fn(w, r)
	}
}

// savedQueries reads the saved queries a combined query can join: every
// query with a DCQL form. An AnonCreds query has none.
func (p *Portal) savedQueries(ctx context.Context) ([]*discoveryv1.PresentationTemplate, error) {
	resp, err := p.opts.Client.ListTemplates(ctx, connect.NewRequest(&discoveryv1.ListTemplatesRequest{}))
	if err != nil {
		return nil, err
	}
	var out []*discoveryv1.PresentationTemplate
	for _, t := range resp.Msg.GetTemplates() {
		if t.GetKind() != discoveryv1.TemplateKind_TEMPLATE_KIND_NATIVE {
			out = append(out, t)
		}
	}
	return out, nil
}

// credentialIDs returns the DCQL credential query ids of a saved query,
// as the combined service merges them: the id of each structured query,
// or the template id and the position.
func credentialIDs(t *discoveryv1.PresentationTemplate) []string {
	out := make([]string, 0, len(t.GetQueries()))
	for i, q := range t.GetQueries() {
		id := q.GetQueryId()
		if id == "" {
			id = t.GetId() + "-" + strconv.Itoa(i)
		}
		out = append(out, id)
	}
	return out
}

// combinedList renders the combined queries.
func (p *Portal) combinedList(w http.ResponseWriter, r *http.Request) error {
	resp, err := p.opts.Combined.List(r.Context(), connect.NewRequest(&combinedv1.ListRequest{}))
	if err != nil {
		return err
	}
	saved, err := p.savedQueries(r.Context())
	if err != nil {
		return err
	}
	names := map[string]string{}
	for _, t := range saved {
		names[t.GetId()] = t.GetDisplayName()
	}
	b := p.blocks()
	parts := []template.HTML{
		p.queryTabs(r.Context(), b, "combined"),
		template.HTML(`<div class="form-actions">`) +
			b.add("button", components.Button{Text: msg.T("verifier.combined.new.label"), Href: p.combinedPath() + "new", Variant: "primary"}) +
			template.HTML(`</div>`),
	}
	rows := make([]components.Row, 0, len(resp.Msg.GetTemplates()))
	for _, c := range resp.Msg.GetTemplates() {
		members := make([]string, 0, len(c.GetMembers()))
		for _, m := range c.GetMembers() {
			name := names[m.GetTemplateId()]
			if name == "" {
				name = m.GetTemplateId()
			}
			members = append(members, name)
		}
		rules := make([]string, 0, len(c.GetRules()))
		for _, rule := range c.GetRules() {
			rules = append(rules, ruleLabel(rule))
		}
		remove := formWith(r.Context(), "filters", p.combinedPath()+"delete/"+url.PathEscape(c.GetId()), "post",
			b.add("button", components.Button{Text: msg.T("verifier.combined.delete.label"), Type: "submit", Variant: "danger"}))
		rows = append(rows, components.Row{
			{HTML: link(p.combinedPath()+"edit/"+url.PathEscape(c.GetId()), c.GetDisplayName())},
			{Text: strings.Join(members, ", ")},
			{Text: firstText(strings.Join(rules, ", "), msg.T("verifier.combined.rules.none.label"))},
			{Text: firstText(c.GetPolicySetId(), msg.T("verifier.combined.policy.default.label"))},
			{HTML: remove},
		})
	}
	if len(rows) == 0 {
		parts = append(parts, b.add("empty", components.Empty{
			Title: msg.T("verifier.combined.empty.title"), Text: msg.T("verifier.combined.empty.text"),
			Action: components.Button{Text: msg.T("verifier.combined.new.label"), Href: p.combinedPath() + "new", Variant: "primary"},
		}))
	} else {
		parts = append(parts, b.add("table", components.Table{
			ID: "combined-queries", Caption: msg.T("verifier.combined.caption.label"),
			Columns: []string{
				msg.T("verifier.combined.column.name.label"), msg.T("verifier.combined.column.members.label"),
				msg.T("verifier.combined.column.rules.label"), msg.T("verifier.combined.column.policy.label"),
				msg.T("verifier.combined.column.action.label"),
			},
			Rows: rows,
		}))
	}
	if b.err != nil {
		return b.err
	}
	return p.render(w, r, "combined", components.Page{
		Title: msg.T("verifier.nav.combined.label"), Lead: msg.T("verifier.combined.lead"), Description: msg.T("verifier.combined.lead"),
		Content: components.Join(parts...), Toasts: notice(r.URL.Query().Get("notice")),
	})
}

// ruleLabel names a rule: its display name, or the name of its kind.
func ruleLabel(rule *combinedv1.CombinedTemplate_Rule) string {
	if rule.GetDisplayName() != "" {
		return rule.GetDisplayName()
	}
	for value, kind := range ruleKinds {
		if kind == rule.GetKind() {
			return msg.T("verifier.combined.rule." + value + ".label")
		}
	}
	return rule.GetKind().String()
}

// combinedNew renders the form of a new combined query.
func (p *Portal) combinedNew(w http.ResponseWriter, r *http.Request) error {
	return p.combinedEditor(w, r, combinedForm{})
}

// combinedEdit renders the form of a stored combined query.
func (p *Portal) combinedEdit(w http.ResponseWriter, r *http.Request) error {
	resp, err := p.opts.Combined.Get(r.Context(), connect.NewRequest(&combinedv1.GetRequest{Id: r.PathValue("id")}))
	if err != nil {
		return err
	}
	c := resp.Msg.GetTemplate()
	f := combinedForm{id: c.GetId(), name: c.GetDisplayName(), policySet: c.GetPolicySetId(),
		members: map[string]bool{}, groups: map[string]string{}}
	for _, m := range c.GetMembers() {
		f.members[m.GetTemplateId()] = true
		f.groups[m.GetTemplateId()] = m.GetAlternativeGroup()
	}
	for _, rule := range c.GetRules() {
		f.rules = append(f.rules, rowOf(rule))
	}
	return p.combinedEditor(w, r, f)
}

// rowOf reads one stored rule into a row of the form.
func rowOf(rule *combinedv1.CombinedTemplate_Rule) ruleRow {
	params := rule.GetParams()
	row := ruleRow{name: rule.GetDisplayName(), optional: !rule.GetRequired()}
	switch rule.GetKind() {
	case combinedv1.CrossRule_CROSS_RULE_SAME_SUBJECT:
		row.kind, row.first, row.second, row.firstClaim = ruleSameSubject, params[paramLeft], params[paramRight], params[paramClaim]
	case combinedv1.CrossRule_CROSS_RULE_DELEGATION_LINK:
		row.kind, row.first, row.second = ruleDelegationLink, params[paramSubject], params[paramDelegation]
	case combinedv1.CrossRule_CROSS_RULE_DATE_ORDER:
		row.kind, row.first, row.firstClaim = ruleDateOrder, params[paramBeforeQuery], params[paramBeforeClaim]
		row.second, row.secondClaim = params[paramAfterQuery], params[paramAfterClaim]
	case combinedv1.CrossRule_CROSS_RULE_UNSPECIFIED:
	}
	return row
}

// ruleOf turns a row of the form into a rule. ok is false for a row
// without a kind.
func ruleOf(row ruleRow) (*combinedv1.CombinedTemplate_Rule, bool) {
	kind, ok := ruleKinds[row.kind]
	if !ok {
		return nil, false
	}
	params := map[string]string{}
	set := func(key, value string) {
		if value != "" {
			params[key] = value
		}
	}
	switch kind {
	case combinedv1.CrossRule_CROSS_RULE_SAME_SUBJECT:
		set(paramLeft, row.first)
		set(paramRight, row.second)
		set(paramClaim, row.firstClaim)
	case combinedv1.CrossRule_CROSS_RULE_DELEGATION_LINK:
		set(paramSubject, row.first)
		set(paramDelegation, row.second)
	case combinedv1.CrossRule_CROSS_RULE_DATE_ORDER:
		set(paramBeforeQuery, row.first)
		set(paramBeforeClaim, row.firstClaim)
		set(paramAfterQuery, row.second)
		set(paramAfterClaim, row.secondClaim)
	case combinedv1.CrossRule_CROSS_RULE_UNSPECIFIED:
	}
	return &combinedv1.CombinedTemplate_Rule{Kind: kind, DisplayName: row.name, Params: params, Required: !row.optional}, true
}

// combinedSave stores the posted form: a new combined query, or the
// stored one again under its id. A refusal keeps the form and names the
// problem.
func (p *Portal) combinedSave(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, MaxFormBytes)
	if err := r.ParseForm(); err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	form := r.PostForm
	f := combinedForm{id: r.PathValue("id"), name: strings.TrimSpace(form.Get("display_name")),
		policySet: strings.TrimSpace(form.Get("policy_set")), members: map[string]bool{}, groups: map[string]string{}}
	saved, err := p.savedQueries(r.Context())
	if err != nil {
		return err
	}
	out := &combinedv1.CombinedTemplate{Id: f.id, DisplayName: f.name, PolicySetId: f.policySet}
	for _, id := range form["member"] {
		f.members[id] = true
	}
	for _, t := range saved {
		id := t.GetId()
		f.groups[id] = strings.TrimSpace(form.Get("group." + id))
		if f.members[id] {
			out.Members = append(out.Members, &combinedv1.CombinedTemplate_Member{TemplateId: id, AlternativeGroup: f.groups[id]})
		}
	}
	for i := 1; form.Has("rule_kind." + strconv.Itoa(i)); i++ {
		n := strconv.Itoa(i)
		row := ruleRow{
			kind: form.Get("rule_kind." + n), name: strings.TrimSpace(form.Get("rule_name." + n)),
			first: form.Get("rule_first." + n), second: form.Get("rule_second." + n),
			firstClaim: strings.TrimSpace(form.Get("rule_first_claim." + n)), secondClaim: strings.TrimSpace(form.Get("rule_second_claim." + n)),
			optional: form.Get("rule_need."+n) == ruleOptional,
		}
		f.rules = append(f.rules, row)
		if rule, ok := ruleOf(row); ok {
			out.Rules = append(out.Rules, rule)
		}
	}
	if f.name == "" {
		f.problem = msg.T("verifier.combined.problem.name")
		return p.combinedEditor(w, r, f)
	}
	if f.id == "" {
		_, err = p.opts.Combined.Create(r.Context(), connect.NewRequest(&combinedv1.CreateRequest{Template: out}))
	} else {
		_, err = p.opts.Combined.Update(r.Context(), connect.NewRequest(&combinedv1.UpdateRequest{Template: out}))
	}
	switch connect.CodeOf(err) {
	case connect.CodeInvalidArgument, connect.CodeFailedPrecondition:
		f.problem = msg.T("verifier.combined.problem.refused") + " " + reasonOf(err)
		return p.combinedEditor(w, r, f)
	}
	if err != nil {
		return err
	}
	http.Redirect(w, r, p.combinedPath()+"?notice=combined-saved", http.StatusSeeOther)
	return nil
}

// reasonOf returns the message of a Connect error without its code.
func reasonOf(err error) string {
	var cerr *connect.Error
	if errors.As(err, &cerr) {
		return cerr.Message()
	}
	return err.Error()
}

// combinedDelete removes one combined query.
func (p *Portal) combinedDelete(w http.ResponseWriter, r *http.Request) error {
	if _, err := p.opts.Combined.Delete(r.Context(), connect.NewRequest(&combinedv1.DeleteRequest{Id: r.PathValue("id")})); err != nil {
		return err
	}
	http.Redirect(w, r, p.combinedPath()+"?notice=combined-deleted", http.StatusSeeOther)
	return nil
}

// combinedEditor renders the form, with a problem after a refused post.
// The form offers one more rule row than it holds, and two at least.
func (p *Portal) combinedEditor(w http.ResponseWriter, r *http.Request, f combinedForm) error {
	saved, err := p.savedQueries(r.Context())
	if err != nil {
		return err
	}
	b := p.blocks()
	var problem template.HTML
	if f.problem != "" {
		problem = template.HTML(`<p class="error" role="alert">` + template.HTMLEscapeString(f.problem) + `</p>`) //nolint:gosec // the text is escaped
	}
	var body template.HTML
	if len(saved) == 0 {
		body = b.add("empty", components.Empty{
			Title: msg.T("verifier.pe.empty.title"), Text: msg.T("verifier.combined.queries.none"),
			Action: components.Button{Text: msg.T("verifier.nav.dcql.label"), Href: p.dcqlPath(), Variant: "primary"},
		})
	} else {
		body = p.combinedFields(r.Context(), b, f, saved)
	}
	title := msg.T("verifier.combined.new.label")
	action := p.combinedPath() + "new"
	if f.id != "" {
		title = msg.T("verifier.combined.edit.label", f.name)
		action = p.combinedPath() + "edit/" + url.PathEscape(f.id)
	}
	card := b.add("card", components.Card{ID: "combined-form", Title: title, Body: problem + formWith(r.Context(), "", action, "post", body)})
	if b.err != nil {
		return b.err
	}
	if f.problem != "" {
		w.WriteHeader(http.StatusBadRequest)
	}
	return p.render(w, r, "combined", components.Page{
		Title: msg.T("verifier.nav.combined.label"), Lead: msg.T("verifier.combined.form.lead"), Description: msg.T("verifier.combined.form.lead"),
		Content: components.Join(p.queryTabs(r.Context(), b, "combined"), card),
	})
}

// combinedFields renders the fields of the form: the name, the member
// queries with their alternative groups, the policy set, and the rules.
func (p *Portal) combinedFields(_ context.Context, b *blocks, f combinedForm, saved []*discoveryv1.PresentationTemplate) template.HTML {
	members := make([]components.ChoiceOption, 0, len(saved))
	groups := make([]template.HTML, 0, len(saved))
	queries := []components.Option{{Value: "", Text: msg.T("verifier.combined.rule.query.none.label")}}
	for i, t := range saved {
		members = append(members, components.ChoiceOption{Value: t.GetId(), Title: t.GetDisplayName(),
			Text: msg.T("verifier.combined.member.text", queryText(t)), Checked: f.members[t.GetId()]})
		groups = append(groups, b.add("field", components.Field{ID: "group-" + strconv.Itoa(i+1), Name: "group." + t.GetId(),
			Label: msg.T("verifier.combined.group.label", t.GetDisplayName()), Value: f.groups[t.GetId()]}))
		for _, id := range credentialIDs(t) {
			queries = append(queries, components.Option{Value: id, Text: t.GetDisplayName() + ": " + id})
		}
	}
	parts := []template.HTML{
		b.add("field", components.Field{ID: "display-name", Name: "display_name", Label: msg.T("verifier.combined.name.label"),
			Value: f.name, Required: true}),
		b.add("choice", components.Choice{ID: "member", Legend: msg.T("verifier.combined.members.label"),
			Hint: msg.T("verifier.combined.members.hint"), Options: members, Multiple: true}),
		b.add("block", components.Block{ID: "groups", Title: msg.T("verifier.combined.groups.label"),
			Lead: msg.T("verifier.combined.groups.hint"), Body: components.Join(groups...)}),
		b.add("field", components.Field{ID: "policy-set", Name: "policy_set", Label: msg.T("verifier.combined.policy.label"),
			Value: f.policySet, Hint: msg.T("verifier.combined.policy.hint")}),
	}
	rows := append([]ruleRow(nil), f.rules...)
	rows = append(rows, ruleRow{})
	if len(rows) < 2 {
		rows = append(rows, ruleRow{})
	}
	for i, row := range rows {
		parts = append(parts, p.ruleBlock(b, i+1, row, queries))
	}
	parts = append(parts, template.HTML(`<div class="form-actions">`)+
		b.add("button", components.Button{Text: msg.T("verifier.combined.save.label"), Type: "submit", Variant: "primary"})+
		template.HTML(`</div>`))
	return components.Join(parts...)
}

// ruleBlock renders the fields of one rule row.
func (p *Portal) ruleBlock(b *blocks, n int, row ruleRow, queries []components.Option) template.HTML {
	num := strconv.Itoa(n)
	kinds := []components.Option{{Value: ruleNone, Text: msg.T("verifier.combined.rule.none.label"), Selected: row.kind == ruleNone}}
	for _, value := range []string{ruleSameSubject, ruleDelegationLink, ruleDateOrder} {
		kinds = append(kinds, components.Option{Value: value, Text: msg.T("verifier.combined.rule." + value + ".label"), Selected: row.kind == value})
	}
	pick := func(chosen string) []components.Option {
		out := make([]components.Option, len(queries))
		copy(out, queries)
		for i := range out {
			out[i].Selected = out[i].Value == chosen
		}
		return out
	}
	body := components.Join(
		b.add("field", components.Field{ID: "rule-kind-" + num, Name: "rule_kind." + num, Label: msg.T("verifier.combined.rule.kind.label"),
			Type: "select", Options: kinds, Hint: msg.T("verifier.combined.rule.kind.hint")}),
		b.add("field", components.Field{ID: "rule-name-" + num, Name: "rule_name." + num, Label: msg.T("verifier.combined.rule.name.label"), Value: row.name}),
		b.add("field", components.Field{ID: "rule-first-" + num, Name: "rule_first." + num, Label: msg.T("verifier.combined.rule.first.label"),
			Type: "select", Options: pick(row.first), Hint: msg.T("verifier.combined.rule.first.hint")}),
		b.add("field", components.Field{ID: "rule-first-claim-" + num, Name: "rule_first_claim." + num,
			Label: msg.T("verifier.combined.rule.first_claim.label"), Value: row.firstClaim, Hint: msg.T("verifier.combined.rule.claim.hint")}),
		b.add("field", components.Field{ID: "rule-second-" + num, Name: "rule_second." + num, Label: msg.T("verifier.combined.rule.second.label"),
			Type: "select", Options: pick(row.second), Hint: msg.T("verifier.combined.rule.second.hint")}),
		b.add("field", components.Field{ID: "rule-second-claim-" + num, Name: "rule_second_claim." + num,
			Label: msg.T("verifier.combined.rule.second_claim.label"), Value: row.secondClaim}),
		b.add("choice", components.Choice{ID: "rule-need-" + num, Name: "rule_need." + num,
			Legend: msg.T("verifier.combined.rule.need.label"), Hint: msg.T("verifier.combined.rule.need.hint"),
			Options: []components.ChoiceOption{
				{Value: ruleRequired, Title: msg.T("verifier.combined.rule.required.label"), Text: msg.T("verifier.combined.rule.required.text"), Checked: !row.optional},
				{Value: ruleOptional, Title: msg.T("verifier.combined.rule.optional.label"), Text: msg.T("verifier.combined.rule.optional.text"), Checked: row.optional},
			}}),
	)
	return b.add("block", components.Block{ID: "rule-" + num, Title: msg.T("verifier.combined.rule.label", num), Body: body})
}
