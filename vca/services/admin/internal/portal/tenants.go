// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/stacks"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// errStack reports a stack value that names no stack.
var errStack = errors.New("portal: the stack value names no stack")

// agentTypes are the agent choices of the tenant forms, in form order.
// The empty value leaves the choice to the stack.
var agentTypes = []struct {
	value string
	key   string
	proto backendv1.DpgTenant_AgentType
}{
	{"", "admin.tenants.agent.default", backendv1.DpgTenant_AGENT_TYPE_UNSPECIFIED},
	{"shared", "admin.tenants.agent.shared", backendv1.DpgTenant_AGENT_TYPE_SHARED},
	{"dedicated", "admin.tenants.agent.dedicated", backendv1.DpgTenant_AGENT_TYPE_DEDICATED},
}

// registerTenants adds the tenant pages (owner spec AD5, ADR-037).
func (p *Portal) registerTenants(mux *http.ServeMux) {
	at := p.opts.Prefix
	mux.HandleFunc("GET "+at+"/tenants", p.guarded(p.tenants))
	mux.HandleFunc("POST "+at+"/tenants", p.posted(p.createTenant))
	mux.HandleFunc("GET "+at+"/tenants/{id}", p.guarded(p.tenant))
	mux.HandleFunc("POST "+at+"/tenants/{id}/delete", p.posted(p.deleteTenant))
	mux.HandleFunc("POST "+at+"/tenants/{id}/bind", p.posted(p.bindTenant))
	mux.HandleFunc("POST "+at+"/tenants/{id}/unbind", p.posted(p.unbindTenant))
}

// tenancyStacks returns the live stacks whose adapter lists multi
// tenancy. The pages offer tenancy on these stacks only (ADR-037
// decision 3).
func (f frame) tenancyStacks() []stacks.Stack {
	return stacks.With(f.snap, backendv1.Feature_FEATURE_MULTI_TENANCY)
}

// tenants renders the tenant list with the create form.
func (p *Portal) tenants(w http.ResponseWriter, r *http.Request, s session) error {
	res, err := p.opts.Client.ListTenants(r.Context(), call(s, &adminv1.ListTenantsRequest{
		Page: &commonv1.Pagination{PageToken: r.URL.Query().Get("page_token")},
	}))
	if err != nil {
		return err
	}
	f := p.frame(r.Context())
	offered := f.tenancyStacks()
	// The stack column shows when a stack offers tenancy or a tenant
	// holds a binding from earlier. Otherwise tenancy stays out of sight.
	showStacks := len(offered) > 0
	for _, t := range res.Msg.GetTenants() {
		showStacks = showStacks || len(t.GetBindings()) > 0
	}
	b := p.blocks()
	at := p.opts.Prefix
	rows := make([]components.Row, 0, len(res.Msg.GetTenants()))
	for _, t := range res.Msg.GetTenants() {
		row := components.Row{{HTML: components.Join(
			template.HTML(`<a href="`+template.HTMLEscapeString(at+"/tenants/"+t.GetId())+`"><strong>`+ //nolint:gosec // both values are escaped
				template.HTMLEscapeString(t.GetDisplayName())+`</strong></a><br>`),
			code(t.GetId()),
		)}}
		if showStacks {
			row = append(row, components.Cell{HTML: bindingBadges(b, t.GetBindings())})
		}
		row = append(row,
			components.Cell{HTML: tenantState(b, t)},
			components.Cell{Text: t.GetCreatedAt().AsTime().UTC().Format(TimeFormat)},
			components.Cell{HTML: form(at+"/tenants/"+t.GetId()+"/delete", s.CSRF,
				b.add("button", components.Button{Text: msg.T("common.delete.label"), Type: "submit", Variant: "danger"}))},
		)
		rows = append(rows, row)
	}
	columns := []string{msg.T("admin.tenants.column.name.label")}
	if showStacks {
		columns = append(columns, msg.T("admin.tenants.column.stacks.label"))
	}
	columns = append(columns, msg.T("admin.tenants.column.state.label"), msg.T("admin.tenants.column.created.label"),
		msg.T("admin.tenants.column.actions.label"))
	table := b.add("table", components.Table{
		ID: "tenants", Caption: msg.T("admin.tenants.caption.label", strconv.Itoa(int(res.Msg.GetPage().GetTotalSize()))),
		Columns: columns, Rows: rows, Empty: msg.T("admin.tenants.empty"),
	})
	fields := []template.HTML{
		b.add("field", components.Field{ID: "display_name", Label: msg.T("admin.tenants.display_name.label"), Required: true}),
	}
	if len(offered) > 0 {
		options := make([]components.ChoiceOption, 0, len(offered))
		for _, st := range offered {
			options = append(options, components.ChoiceOption{
				Value: st.Dpg.String(), Title: st.Name, Text: msg.T("admin.tenants.stack.text"), Meta: versionMeta(st),
			})
		}
		fields = append(fields,
			b.add("choice", components.Choice{ID: "stacks", Legend: msg.T("admin.tenants.stacks.label"), Hint: msg.T("admin.tenants.stacks.hint"),
				Options: options, Multiple: true}),
			p.agentChoice(b),
		)
	}
	fields = append(fields, b.add("button", components.Button{Text: msg.T("admin.tenants.create.label"), Type: "submit", Variant: "primary"}))
	text := msg.T("admin.tenants.new.text")
	if len(offered) > 0 {
		text = msg.T("admin.tenants.new.stacks.text")
	}
	create := b.add("card", components.Card{
		ID: "create-tenant", Title: msg.T("admin.tenants.new.label"), Text: text,
		Body: form(at+"/tenants", s.CSRF, fields...),
	})
	actions := b.add("button", components.Button{Text: msg.T("admin.tenants.new.label"), Href: "#create-tenant", Variant: "primary"})
	if b.err != nil {
		return b.err
	}
	return p.renderWith(w, r, s, f, components.Page{
		Title:       msg.T("admin.nav.tenants.label"),
		Lead:        msg.T("admin.tenants.lead"),
		Actions:     actions,
		Description: msg.T("admin.tenants.lead"),
		Content:     components.Join(table, create),
		Toasts:      notice(r.URL.Query().Get("notice")),
	})
}

// agentChoice is the agent type choice of the tenant forms.
func (p *Portal) agentChoice(b *blocks) template.HTML {
	options := make([]components.ChoiceOption, 0, len(agentTypes))
	for i, a := range agentTypes {
		value := a.value
		if value == "" {
			value = "default"
		}
		options = append(options, components.ChoiceOption{Value: value, Title: msg.T(a.key + ".label"), Text: msg.T(a.key + ".text"), Checked: i == 0})
	}
	return b.add("choice", components.Choice{ID: "agent_type", Legend: msg.T("admin.tenants.agent.label"), Options: options})
}

// bindingBadges shows one badge per stack a tenant is bound on, or a
// short text for a tenant that lives in VCA only.
func bindingBadges(b *blocks, bindings []*adminv1.TenantBinding) template.HTML {
	if len(bindings) == 0 {
		return template.HTML(`<span class="hint">` + template.HTMLEscapeString(msg.T("admin.tenants.vca_only.label")) + `</span>`) //nolint:gosec // the text is escaped
	}
	parts := make([]template.HTML, 0, len(bindings))
	for _, bd := range bindings {
		parts = append(parts, b.add("badge", components.Badge{Status: "info", Text: bd.GetStackName()}))
	}
	return components.Join(parts...)
}

// tenantState is the badge of the state of a tenant.
func tenantState(b *blocks, t *adminv1.Tenant) template.HTML {
	if t.GetState() == adminv1.Tenant_STATE_ACTIVE {
		return b.add("badge", components.Badge{Status: "ok", Text: msg.T("admin.tenants.state.active.label")})
	}
	return b.add("badge", components.Badge{Status: "warn", Text: msg.T("admin.tenants.state.suspended.label")})
}

// tenant renders one tenant with its stack tenants and the bind form.
func (p *Portal) tenant(w http.ResponseWriter, r *http.Request, s session) error {
	res, err := p.opts.Client.GetTenant(r.Context(), call(s, &adminv1.GetTenantRequest{Id: r.PathValue("id")}))
	if err != nil {
		return err
	}
	t := res.Msg.GetTenant()
	f := p.frame(r.Context())
	b := p.blocks()
	at := p.opts.Prefix
	base := at + "/tenants/" + t.GetId()
	facts := b.add("table", components.Table{
		ID: "tenant-facts", Caption: msg.T("admin.tenants.details.label"),
		Columns: []string{
			msg.T("admin.tenants.id.label"), msg.T("admin.tenants.column.state.label"),
			msg.T("admin.tenants.column.created.label"), msg.T("admin.tenants.column.actions.label"),
		},
		Rows: []components.Row{{
			{HTML: code(t.GetId())},
			{HTML: tenantState(b, t)},
			{Text: t.GetCreatedAt().AsTime().UTC().Format(TimeFormat)},
			{HTML: form(base+"/delete", s.CSRF, b.add("button", components.Button{Text: msg.T("admin.tenants.delete.label"), Type: "submit", Variant: "danger"}))},
		}},
	})
	offered := f.tenancyStacks()
	var unbound []stacks.Stack
	for _, st := range offered {
		if !boundOn(t, st.Dpg) {
			unbound = append(unbound, st)
		}
	}
	var onStacks, bind template.HTML
	if len(offered) > 0 || len(t.GetBindings()) > 0 {
		onStacks = p.bindingsBlock(b, t, s.CSRF)
	}
	if len(unbound) > 0 {
		options := make([]components.ChoiceOption, 0, len(unbound))
		for i, st := range unbound {
			options = append(options, components.ChoiceOption{
				Value: st.Dpg.String(), Title: st.Name, Text: msg.T("admin.tenants.stack.text"),
				Meta: versionMeta(st), Checked: i == 0,
			})
		}
		bind = b.add("card", components.Card{
			ID: "bind-stack", Title: msg.T("admin.tenants.bind.label"), Text: msg.T("admin.tenants.bind.text"),
			Body: form(base+"/bind", s.CSRF,
				b.add("choice", components.Choice{ID: "stack", Legend: msg.T("admin.tenants.stack.label"), Options: options}),
				p.agentChoice(b),
				b.add("button", components.Button{Text: msg.T("admin.tenants.bind.label"), Type: "submit", Variant: "primary"}),
			),
		})
	}
	actions := b.add("button", components.Button{Text: msg.T("admin.tenants.back.label"), Href: at + "/tenants", Variant: "secondary"})
	if b.err != nil {
		return b.err
	}
	return p.renderWith(w, r, s, f, components.Page{
		Title:       t.GetDisplayName(),
		Label:       msg.T("admin.tenants.tenant.label"),
		Lead:        msg.T("admin.tenants.detail.lead"),
		Actions:     actions,
		Description: msg.T("admin.tenants.detail.lead"),
		Content:     components.Join(facts, onStacks, bind),
		Toasts:      notice(r.URL.Query().Get("notice")),
	})
}

// bindingsBlock is the section of the stack tenants of one tenant.
func (p *Portal) bindingsBlock(b *blocks, t *adminv1.Tenant, csrf string) template.HTML {
	base := p.opts.Prefix + "/tenants/" + t.GetId()
	if len(t.GetBindings()) == 0 {
		// The bind card follows the block, so the lead says what to do.
		return b.add("block", components.Block{
			ID: "on-stacks", Title: msg.T("admin.tenants.on_stacks.label"), Lead: msg.T("admin.tenants.no_bindings.text"),
		})
	}
	rows := make([]components.Row, 0, len(t.GetBindings()))
	for _, bd := range t.GetBindings() {
		dids := make([]template.HTML, 0, len(bd.GetTenant().GetDids()))
		for _, d := range bd.GetTenant().GetDids() {
			dids = append(dids, shortCode(d), template.HTML(`<br>`))
		}
		if len(dids) == 0 {
			dids = append(dids, template.HTML(template.HTMLEscapeString(msg.T("admin.tenants.no_dids.label")))) //nolint:gosec // the text is escaped
		}
		rows = append(rows, components.Row{
			{HTML: components.Join(
				template.HTML(`<strong>`+template.HTMLEscapeString(bd.GetStackName())+`</strong><br>`), //nolint:gosec // the name is escaped
				bindingState(b, bd),
				hint(msg.T("admin.tenants.bound_at.label", bd.GetBoundAt().AsTime().UTC().Format(TimeFormat))),
			)},
			{HTML: components.Join(
				template.HTML(template.HTMLEscapeString(bd.GetTenant().GetName())+`<br>`), //nolint:gosec // the name is escaped
				code(bd.GetTenant().GetId()),
				hint(agentLabel(bd.GetTenant().GetAgentType())),
			)},
			{HTML: components.Join(dids...)},
			{HTML: form(base+"/unbind", csrf,
				template.HTML(`<input type="hidden" name="stack" value="`+template.HTMLEscapeString(bd.GetStack().String())+`">`), //nolint:gosec // the value is escaped
				b.add("button", components.Button{Text: msg.T("admin.tenants.unbind.label"), Type: "submit", Variant: "danger"}))},
		})
	}
	table := b.add("table", components.Table{
		ID: "bindings", Caption: msg.T("admin.tenants.bindings.caption.label", strconv.Itoa(len(rows))),
		Columns: []string{
			msg.T("admin.tenants.column.stack.label"), msg.T("admin.tenants.column.stack_tenant.label"),
			msg.T("admin.tenants.column.dids.label"), msg.T("admin.tenants.column.actions.label"),
		},
		Rows: rows,
	})
	return b.add("block", components.Block{
		ID: "on-stacks", Title: msg.T("admin.tenants.on_stacks.label"), Lead: msg.T("admin.tenants.on_stacks.lead"), Body: table,
	})
}

// bindingState is the badge of one binding: read now, or the reason
// the stack did not answer.
func bindingState(b *blocks, bd *adminv1.TenantBinding) template.HTML {
	if bd.GetError() == "" {
		return b.add("badge", components.Badge{Status: "ok", Text: msg.T("admin.tenants.binding.ok.label")})
	}
	return components.Join(
		b.add("badge", components.Badge{Status: "warn", Text: msg.T("admin.tenants.binding.error.label")}),
		hint(bd.GetError()),
	)
}

// hint is an escaped line of small text.
func hint(text string) template.HTML {
	return template.HTML(`<p class="hint">` + template.HTMLEscapeString(text) + `</p>`) //nolint:gosec // the text is escaped
}

// shortCode shows a long identifier in the monospace face with its
// middle cut, and the full value in its title.
func shortCode(v string) template.HTML {
	shown := v
	if r := []rune(v); len(r) > 34 {
		shown = string(r[:22]) + "…" + string(r[len(r)-8:])
	}
	e := template.HTMLEscapeString(v)
	return template.HTML(`<code title="` + e + `">` + template.HTMLEscapeString(shown) + `</code>`) //nolint:gosec // both values are escaped
}

// versionMeta is the release line of a stack on a choice card.
func versionMeta(st stacks.Stack) string {
	if v := st.Capabilities.GetDpgInfo().GetVersion(); v != "" {
		return msg.T("admin.tenants.stack.version.label", v)
	}
	return ""
}

// agentLabel names an agent type for a table cell.
func agentLabel(a backendv1.DpgTenant_AgentType) string {
	for _, at := range agentTypes {
		if at.proto == a {
			return msg.T(at.key + ".label")
		}
	}
	return msg.T("admin.tenants.agent.default.label")
}

// boundOn reports whether a tenant holds a binding on a stack.
func boundOn(t *adminv1.Tenant, d configv1.Dpg) bool {
	for _, bd := range t.GetBindings() {
		if bd.GetStack() == d {
			return true
		}
	}
	return false
}

// stackValue reads one stack value of a form.
func stackValue(v string) (configv1.Dpg, error) {
	n, ok := configv1.Dpg_value[strings.TrimSpace(v)]
	if !ok || n == 0 {
		return configv1.Dpg_DPG_UNSPECIFIED, connect.NewError(connect.CodeInvalidArgument, errStack)
	}
	return configv1.Dpg(n), nil
}

// agentValue reads the agent choice of a form.
func agentValue(v string) backendv1.DpgTenant_AgentType {
	for _, a := range agentTypes {
		if a.value != "" && a.value == v {
			return a.proto
		}
	}
	return backendv1.DpgTenant_AGENT_TYPE_UNSPECIFIED
}

// createTenant creates one tenant, on the chosen stacks too, and
// returns to the list.
func (p *Portal) createTenant(w http.ResponseWriter, r *http.Request, s session) error {
	req := &adminv1.CreateTenantRequest{
		DisplayName: r.PostFormValue("display_name"),
		AgentType:   agentValue(r.PostFormValue("agent_type")),
	}
	for _, v := range r.PostForm["stacks"] {
		d, err := stackValue(v)
		if err != nil {
			return err
		}
		req.Stacks = append(req.Stacks, d)
	}
	if _, err := p.opts.Client.CreateTenant(r.Context(), call(s, req)); err != nil {
		return err
	}
	p.redirect(w, r, "/tenants", "tenant-created")
	return nil
}

// deleteTenant removes one tenant and its stack tenants.
func (p *Portal) deleteTenant(w http.ResponseWriter, r *http.Request, s session) error {
	_, err := p.opts.Client.DeleteTenant(r.Context(), call(s, &adminv1.DeleteTenantRequest{Id: r.PathValue("id")}))
	if err != nil {
		return err
	}
	p.redirect(w, r, "/tenants", "tenant-deleted")
	return nil
}

// bindTenant creates the tenant on one more stack.
func (p *Portal) bindTenant(w http.ResponseWriter, r *http.Request, s session) error {
	d, err := stackValue(r.PostFormValue("stack"))
	if err != nil {
		return err
	}
	id := r.PathValue("id")
	if _, err := p.opts.Client.BindTenant(r.Context(), call(s, &adminv1.BindTenantRequest{
		Id: id, Stack: d, AgentType: agentValue(r.PostFormValue("agent_type")),
	})); err != nil {
		return err
	}
	p.redirect(w, r, "/tenants/"+id, "tenant-bound")
	return nil
}

// unbindTenant removes the tenant from one stack.
func (p *Portal) unbindTenant(w http.ResponseWriter, r *http.Request, s session) error {
	d, err := stackValue(r.PostFormValue("stack"))
	if err != nil {
		return err
	}
	id := r.PathValue("id")
	if _, err := p.opts.Client.UnbindTenant(r.Context(), call(s, &adminv1.UnbindTenantRequest{Id: id, Stack: d})); err != nil {
		return err
	}
	p.redirect(w, r, "/tenants/"+id, "tenant-unbound")
	return nil
}
