// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// The Ecosystems tab of the tenant pages (P6-C9, ADR-068). A stack that
// lists ecosystems groups its tenants: one tenant leads an ecosystem and
// the other tenants are members. The tab shows only where a live adapter
// lists the feature.

// ecosystemsFeature is the feature of the tab.
const ecosystemsFeature = backendv1.Feature_FEATURE_ECOSYSTEMS

// registerEcosystems adds the Ecosystems tab and its forms.
func (p *Portal) registerEcosystems(mux *http.ServeMux) {
	at := p.opts.Prefix
	mux.HandleFunc("GET "+at+"/tenants/ecosystems", p.guarded(p.ecosystems))
	mux.HandleFunc("POST "+at+"/tenants/ecosystems", p.posted(p.createEcosystem))
	mux.HandleFunc("POST "+at+"/tenants/ecosystems/switch", p.posted(p.switchEcosystems))
	mux.HandleFunc("POST "+at+"/tenants/ecosystems/members", p.posted(p.addEcosystemMember))
	mux.HandleFunc("POST "+at+"/tenants/ecosystems/members/remove", p.posted(p.removeEcosystemMember))
}

// tenantTabs are the tabs of the tenant pages. They show only where a
// live adapter lists ecosystems.
func (p *Portal) tenantTabs(b *blocks, f frame, current string) template.HTML {
	if !f.has(ecosystemsFeature) {
		return ""
	}
	at := p.opts.Prefix
	return b.add("tabs", components.Tabs{Label: msg.T("admin.tenants.tabs.label"), Links: []components.Link{
		{Href: at + "/tenants", Text: msg.T("admin.tenants.tab.list.label"), Current: current == "list"},
		{Href: at + "/tenants/ecosystems", Text: msg.T("admin.tenants.tab.ecosystems.label"), Current: current == "ecosystems"},
	}})
}

// ecosystemView is what the tab needs: the switches, the ecosystems, and
// the VCA tenants by id with their stack tenants.
type ecosystemView struct {
	res     *adminv1.ListStackEcosystemsResponse
	tenants map[string]*adminv1.Tenant
	order   []*adminv1.Tenant
}

// tenantName names a VCA tenant, or says the stack tenant is no VCA
// tenant.
func (v ecosystemView) tenantName(id, fallback string) string {
	if t, ok := v.tenants[id]; ok {
		return t.GetDisplayName()
	}
	if fallback != "" {
		return fallback + " (" + msg.T("admin.ecosystems.not_vca.label") + ")"
	}
	return msg.T("admin.ecosystems.not_vca.label")
}

// onStacks returns the stacks whose switch is on.
func (v ecosystemView) onStacks() map[configv1.Dpg]string {
	out := map[configv1.Dpg]string{}
	for _, st := range v.res.GetStacks() {
		if st.GetEnabled() {
			out[st.GetStack()] = st.GetStackName()
		}
	}
	return out
}

// ecosystems renders the Ecosystems tab.
func (p *Portal) ecosystems(w http.ResponseWriter, r *http.Request, s session) error {
	f := p.frame(r.Context())
	if !f.has(ecosystemsFeature) {
		http.NotFound(w, r)
		return nil
	}
	res, err := p.opts.Client.ListStackEcosystems(r.Context(), call(s, &adminv1.ListStackEcosystemsRequest{}))
	if err != nil {
		return err
	}
	tenants, err := p.opts.Client.ListTenants(r.Context(), call(s, &adminv1.ListTenantsRequest{}))
	if err != nil {
		return err
	}
	v := ecosystemView{res: res.Msg, tenants: map[string]*adminv1.Tenant{}, order: tenants.Msg.GetTenants()}
	for _, t := range v.order {
		v.tenants[t.GetId()] = t
	}
	b := p.blocks()
	content := []template.HTML{p.tenantTabs(b, f, "ecosystems"), p.switchBlock(b, s, v)}
	if len(v.onStacks()) == 0 {
		content = append(content, b.add("note", components.Note{
			Label: msg.T("admin.ecosystems.off.title.label"), Text: msg.T("admin.ecosystems.off.text"),
		}))
	} else {
		content = append(content, p.ecosystemBlock(b, s, v), p.memberBlock(b, s, v))
	}
	if errs := res.Msg.GetErrors(); len(errs) > 0 {
		content = append(content, b.add("note", components.Note{Label: msg.T("admin.ecosystems.errors.label"), Text: strings.Join(errs, " ")}))
	}
	if b.err != nil {
		return b.err
	}
	return p.renderWith(w, r, s, f, components.Page{
		Title:       msg.T("admin.tenants.tab.ecosystems.label"),
		Heading:     msg.T("admin.nav.tenants.label"),
		Lead:        msg.T("admin.ecosystems.lead"),
		Description: msg.T("admin.ecosystems.lead"),
		Content:     components.Join(content...),
		Toasts:      notice(r.URL.Query().Get("notice")),
	})
}

// switchBlock shows the switch of each stack with the action that turns
// it around.
func (p *Portal) switchBlock(b *blocks, s session, v ecosystemView) template.HTML {
	at := p.opts.Prefix
	rows := make([]components.Row, 0, len(v.res.GetStacks()))
	for _, st := range v.res.GetStacks() {
		var state, action template.HTML
		turn, label := "true", msg.T("admin.ecosystems.turn_on.label")
		switch {
		case st.GetError() != "":
			state = components.Join(b.add("badge", components.Badge{Status: "warn", Text: msg.T("admin.tenants.binding.error.label")}), hint(st.GetError()))
		case st.GetEnabled():
			state = b.add("badge", components.Badge{Status: "ok", Text: msg.T("admin.ecosystems.on.label")})
			turn, label = "false", msg.T("admin.ecosystems.turn_off.label")
		default:
			state = b.add("badge", components.Badge{Status: "info", Text: msg.T("admin.ecosystems.off.label")})
		}
		if st.GetError() == "" {
			variant := "primary"
			if turn == "false" {
				variant = "danger"
			}
			action = form(at+"/tenants/ecosystems/switch", s.CSRF,
				hidden("stack", st.GetStack().String()), hidden("enabled", turn),
				b.add("button", components.Button{Text: label, Type: "submit", Variant: variant}))
		}
		rows = append(rows, components.Row{{Text: st.GetStackName()}, {HTML: state}, {HTML: action}})
	}
	return b.add("block", components.Block{
		ID: "ecosystem-switch", Title: msg.T("admin.ecosystems.switch.label"), Lead: msg.T("admin.ecosystems.switch.lead"),
		Body: b.add("table", components.Table{
			ID: "ecosystem-stacks", Caption: msg.T("admin.ecosystems.switch.caption.label", strconv.Itoa(len(rows))),
			Columns: []string{
				msg.T("admin.ecosystems.column.stack.label"), msg.T("admin.ecosystems.column.state.label"),
				msg.T("admin.ecosystems.column.actions.label"),
			},
			Rows: rows,
		}),
	})
}

// ecosystemBlock lists the ecosystems with their lead, and the form that
// creates one.
func (p *Portal) ecosystemBlock(b *blocks, s session, v ecosystemView) template.HTML {
	at := p.opts.Prefix
	rows := make([]components.Row, 0, len(v.res.GetEcosystems()))
	for _, e := range v.res.GetEcosystems() {
		eco := e.GetEcosystem()
		rows = append(rows, components.Row{
			{HTML: components.Join(
				template.HTML(`<strong>`+template.HTMLEscapeString(eco.GetName())+`</strong>`), //nolint:gosec // the value is escaped
				hint(eco.GetDescription()),
			)},
			{Text: e.GetStackName()},
			{Text: v.tenantName(e.GetLeadTenantId(), eco.GetLeadTenantName())},
			{Text: strconv.Itoa(len(e.GetMembers()))},
		})
	}
	table := b.add("table", components.Table{
		ID: "ecosystems", Caption: msg.T("admin.ecosystems.caption.label", strconv.Itoa(len(rows))),
		Columns: []string{
			msg.T("admin.ecosystems.column.name.label"), msg.T("admin.ecosystems.column.stack.label"),
			msg.T("admin.ecosystems.column.lead.label"), msg.T("admin.ecosystems.column.members.label"),
		},
		Rows: rows, Empty: msg.T("admin.ecosystems.empty"),
	})
	create := b.add("card", components.Card{
		ID: "create-ecosystem", Title: msg.T("admin.ecosystems.new.label"), Text: msg.T("admin.ecosystems.new.text"),
		Body: stackedForm(at+"/tenants/ecosystems", s.CSRF, components.Join(
			b.add("field", components.Field{ID: "lead_target", Name: "target", Label: msg.T("admin.ecosystems.lead_target.label"),
				Type: "select", Options: v.targets()}),
			b.add("field", components.Field{ID: "ecosystem_name", Name: "name", Label: msg.T("admin.ecosystems.name.label"), Required: true}),
			b.add("field", components.Field{ID: "description", Label: msg.T("admin.ecosystems.description.label"), Type: "textarea", Required: true,
				Hint: msg.T("admin.ecosystems.description.hint")}),
			b.add("button", components.Button{Text: msg.T("admin.ecosystems.create.label"), Type: "submit", Variant: "primary"}),
		)),
	})
	return b.add("block", components.Block{
		ID: "stack-ecosystems", Title: msg.T("admin.ecosystems.list.label"), Lead: msg.T("admin.ecosystems.list.lead"),
		Body: components.Join(table, create),
	})
}

// targets offers each VCA tenant on each stack whose switch is on.
func (v ecosystemView) targets() []components.Option {
	on := v.onStacks()
	var out []components.Option
	for _, t := range v.order {
		for _, bd := range t.GetBindings() {
			if name, ok := on[bd.GetStack()]; ok {
				out = append(out, components.Option{
					Value: t.GetId() + "|" + bd.GetStack().String(), Text: msg.T("admin.keys.stack.target.value.label", t.GetDisplayName(), name),
				})
			}
		}
	}
	return out
}

// memberBlock lists the members of each ecosystem with a remove action,
// and the form that adds one.
func (p *Portal) memberBlock(b *blocks, s session, v ecosystemView) template.HTML {
	at := p.opts.Prefix
	var rows []components.Row
	var choices []components.Option
	for _, e := range v.res.GetEcosystems() {
		eco := e.GetEcosystem()
		value := eco.GetId() + "|" + e.GetStack().String()
		choices = append(choices, components.Option{Value: value, Text: msg.T("admin.keys.stack.target.value.label", eco.GetName(), e.GetStackName())})
		for _, m := range e.GetMembers() {
			var action template.HTML
			if m.GetTenantId() != "" {
				action = form(at+"/tenants/ecosystems/members/remove", s.CSRF,
					hidden("ecosystem", value), hidden("tenant", m.GetTenantId()),
					b.add("button", components.Button{Text: msg.T("admin.ecosystems.remove.label"), Type: "submit", Variant: "danger"}))
			}
			joined := ""
			if at := m.GetMember().GetJoinedAt(); at != nil {
				joined = at.AsTime().UTC().Format(TimeFormat)
			}
			rows = append(rows, components.Row{
				{Text: eco.GetName()}, {Text: v.tenantName(m.GetTenantId(), m.GetMember().GetTenantName())},
				{Text: m.GetMember().GetStatus()}, {Text: joined}, {HTML: action},
			})
		}
	}
	table := b.add("table", components.Table{
		ID: "ecosystem-members", Caption: msg.T("admin.ecosystems.members.caption.label", strconv.Itoa(len(rows))),
		Columns: []string{
			msg.T("admin.ecosystems.column.name.label"), msg.T("admin.ecosystems.column.tenant.label"),
			msg.T("admin.ecosystems.column.state.label"), msg.T("admin.ecosystems.column.joined.label"),
			msg.T("admin.ecosystems.column.actions.label"),
		},
		Rows: rows, Empty: msg.T("admin.ecosystems.members.empty"),
	})
	body := table
	if len(choices) > 0 {
		var tenants []components.Option
		for _, t := range v.order {
			tenants = append(tenants, components.Option{Value: t.GetId(), Text: t.GetDisplayName()})
		}
		body = components.Join(table, b.add("card", components.Card{
			ID: "add-member", Title: msg.T("admin.ecosystems.add.label"), Text: msg.T("admin.ecosystems.add.text"),
			Body: stackedForm(at+"/tenants/ecosystems/members", s.CSRF, components.Join(
				b.add("field", components.Field{ID: "member_ecosystem", Name: "ecosystem", Label: msg.T("admin.ecosystems.ecosystem.label"),
					Type: "select", Options: choices}),
				b.add("field", components.Field{ID: "member_tenant", Name: "tenant", Label: msg.T("admin.ecosystems.member_target.label"),
					Type: "select", Options: tenants}),
				b.add("button", components.Button{Text: msg.T("admin.ecosystems.add.submit.label"), Type: "submit", Variant: "primary"}),
			)),
		}))
	}
	return b.add("block", components.Block{ID: "members", Title: msg.T("admin.ecosystems.members.label"), Body: body})
}

// hidden is one hidden form field.
func hidden(name, value string) template.HTML {
	return template.HTML(`<input type="hidden" name="` + template.HTMLEscapeString(name) + `" value="` + template.HTMLEscapeString(value) + `">`) //nolint:gosec // both values are escaped
}

// switchEcosystems turns the ecosystems of one stack on or off.
func (p *Portal) switchEcosystems(w http.ResponseWriter, r *http.Request, s session) error {
	d, err := stackValue(r.PostFormValue("stack"))
	if err != nil {
		return err
	}
	on := r.PostFormValue("enabled") == "true"
	if _, err := p.opts.Client.SetStackEcosystems(r.Context(), call(s, &adminv1.SetStackEcosystemsRequest{Stack: d, Enabled: on})); err != nil {
		return err
	}
	code := "ecosystems-off"
	if on {
		code = "ecosystems-on"
	}
	p.redirect(w, r, "/tenants/ecosystems", code)
	return nil
}

// createEcosystem creates one ecosystem that a tenant leads.
func (p *Portal) createEcosystem(w http.ResponseWriter, r *http.Request, s session) error {
	tenantID, stack, ok := strings.Cut(r.PostFormValue("target"), "|")
	if !ok || tenantID == "" {
		return connect.NewError(connect.CodeInvalidArgument, errTarget)
	}
	d, err := stackValue(stack)
	if err != nil {
		return err
	}
	if _, err := p.opts.Client.CreateStackEcosystem(r.Context(), call(s, &adminv1.CreateStackEcosystemRequest{
		Stack: d, LeadTenantId: tenantID, Name: r.PostFormValue("name"), Description: r.PostFormValue("description"),
	})); err != nil {
		return err
	}
	p.redirect(w, r, "/tenants/ecosystems", "ecosystem-created")
	return nil
}

// ecosystemTarget reads the ecosystem and the stack of a member form.
func ecosystemTarget(r *http.Request) (string, configv1.Dpg, error) {
	id, stack, ok := strings.Cut(r.PostFormValue("ecosystem"), "|")
	if !ok || id == "" {
		return "", 0, connect.NewError(connect.CodeInvalidArgument, errTarget)
	}
	d, err := stackValue(stack)
	return id, d, err
}

// addEcosystemMember adds one tenant to an ecosystem.
func (p *Portal) addEcosystemMember(w http.ResponseWriter, r *http.Request, s session) error {
	id, d, err := ecosystemTarget(r)
	if err != nil {
		return err
	}
	res, err := p.opts.Client.AddStackEcosystemMember(r.Context(), call(s, &adminv1.AddStackEcosystemMemberRequest{
		Stack: d, EcosystemId: id, TenantId: r.PostFormValue("tenant"),
	}))
	if err != nil {
		return err
	}
	code := "ecosystem-member-added"
	if res.Msg.GetInvited() {
		code = "ecosystem-member-invited"
	}
	p.redirect(w, r, "/tenants/ecosystems", code)
	return nil
}

// removeEcosystemMember removes one member tenant from an ecosystem.
func (p *Portal) removeEcosystemMember(w http.ResponseWriter, r *http.Request, s session) error {
	id, d, err := ecosystemTarget(r)
	if err != nil {
		return err
	}
	if _, err := p.opts.Client.RemoveStackEcosystemMember(r.Context(), call(s, &adminv1.RemoveStackEcosystemMemberRequest{
		Stack: d, EcosystemId: id, TenantId: r.PostFormValue("tenant"),
	})); err != nil {
		return err
	}
	p.redirect(w, r, "/tenants/ecosystems", "ecosystem-member-removed")
	return nil
}
