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
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// deliveryChannels are the VCA delivery channels the page lists. VCA
// builds none of them in this release (ADR-040 decision 1).
var deliveryChannels = []string{"email", "sms", "webhook"}

// registerNotifications adds the notifications page (owner spec AD9,
// ADR-040).
func (p *Portal) registerNotifications(mux *http.ServeMux) {
	at := p.opts.Prefix
	mux.HandleFunc("GET "+at+"/notifications", p.guarded(p.notifications))
	mux.HandleFunc("POST "+at+"/notifications/webhook", p.posted(p.setWebhook))
}

// notifications renders the VCA delivery channels and, where a live
// adapter lists webhooks, the webhook of each stack tenant.
func (p *Portal) notifications(w http.ResponseWriter, r *http.Request, s session) error {
	f := p.frame(r.Context())
	b := p.blocks()
	rows := make([]components.Row, 0, len(deliveryChannels))
	for _, c := range deliveryChannels {
		key := "admin.notifications.channel." + c
		rows = append(rows, components.Row{
			{HTML: template.HTML(`<strong>` + template.HTMLEscapeString(msg.T(key+".label")) + `</strong>`)}, //nolint:gosec // the text is escaped
			{Text: msg.T(key + ".text")},
			{HTML: b.add("badge", components.Badge{Status: "warn", Text: notBuilt()})},
		})
	}
	delivery := b.add("block", components.Block{
		ID: "vca-delivery", Title: msg.T("admin.notifications.delivery.label"), Lead: msg.T("admin.notifications.delivery.lead"),
		Body: b.add("table", components.Table{
			ID: "channels", Caption: msg.T("admin.notifications.channels.caption.label"),
			Columns: []string{
				msg.T("admin.notifications.column.channel.label"), msg.T("admin.notifications.column.carries.label"),
				msg.T("admin.notifications.column.state.label"),
			},
			Rows: rows,
		}),
	})
	var hooks template.HTML
	if f.has(backendv1.Feature_FEATURE_WEBHOOKS) {
		res, err := p.opts.Client.ListStackWebhooks(r.Context(), call(s, &adminv1.ListStackWebhooksRequest{}))
		if err != nil {
			return err
		}
		hooks = p.webhookBlock(b, s, res.Msg.GetWebhooks())
	}
	if b.err != nil {
		return b.err
	}
	return p.renderWith(w, r, s, f, components.Page{
		Title:       msg.T("common.notifications.label"),
		Lead:        msg.T("admin.notifications.lead"),
		Description: msg.T("admin.notifications.lead"),
		Content:     components.Join(delivery, hooks),
		Toasts:      notice(r.URL.Query().Get("notice")),
	})
}

// webhookBlock is the section of the stack webhooks: one row per stack
// tenant with a clear action, and the form that sets one.
func (p *Portal) webhookBlock(b *blocks, s session, hooks []*adminv1.StackWebhook) template.HTML {
	at := p.opts.Prefix
	block := components.Block{ID: "stack-webhooks", Title: msg.T("admin.notifications.webhooks.label"), Lead: msg.T("admin.notifications.webhooks.lead")}
	if len(hooks) == 0 {
		block.Body = b.add("empty", components.Empty{
			Title: msg.T("admin.notifications.webhooks.empty.title"), Text: msg.T("admin.notifications.webhooks.empty.text"),
			Action: components.Button{Text: msg.T("admin.keys.stack.tenants.label"), Href: at + "/tenants"},
		})
		return b.add("block", block)
	}
	rows := make([]components.Row, 0, len(hooks))
	targets := make([]components.Option, 0, len(hooks))
	for _, h := range hooks {
		target := h.GetTenantId() + "|" + h.GetStack().String()
		targets = append(targets, components.Option{
			Value: target, Text: msg.T("admin.keys.stack.target.value.label", h.GetTenantName(), h.GetStackName()),
		})
		var address, state, action template.HTML
		switch {
		case h.GetError() != "":
			address = hint(msg.T("admin.notifications.webhook.unknown.label"))
			state = components.Join(
				b.add("badge", components.Badge{Status: "warn", Text: msg.T("admin.tenants.binding.error.label")}),
				hint(h.GetError()),
			)
		case h.GetWebhook().GetUrl() == "":
			address = hint(msg.T("admin.notifications.webhook.none.label"))
			state = b.add("badge", components.Badge{Status: "info", Text: msg.T("admin.notifications.webhook.off.label")})
		default:
			address = code(h.GetWebhook().GetUrl())
			state = b.add("badge", components.Badge{Status: "ok", Text: msg.T("admin.notifications.webhook.on.label")})
			action = form(at+"/notifications/webhook", s.CSRF,
				template.HTML(`<input type="hidden" name="target" value="`+template.HTMLEscapeString(target)+`">`), //nolint:gosec // the value is escaped
				b.add("button", components.Button{Text: msg.T("admin.notifications.webhook.clear.label"), Type: "submit", Variant: "danger"}))
		}
		rows = append(rows, components.Row{
			{Text: h.GetTenantName()}, {Text: h.GetStackName()}, {HTML: address}, {HTML: state}, {HTML: action},
		})
	}
	table := b.add("table", components.Table{
		ID: "webhooks", Caption: msg.T("admin.notifications.webhooks.caption.label", strconv.Itoa(len(rows))),
		Columns: []string{
			msg.T("admin.keys.column.tenant.label"), msg.T("admin.keys.stack.column.stack.label"),
			msg.T("admin.notifications.column.webhook.label"), msg.T("admin.notifications.column.state.label"),
			msg.T("admin.keys.column.actions.label"),
		},
		Rows: rows,
	})
	set := b.add("card", components.Card{
		ID: "set-webhook", Title: msg.T("admin.notifications.webhook.set.label"), Text: msg.T("admin.notifications.webhook.set.text"),
		Body: form(at+"/notifications/webhook", s.CSRF,
			b.add("field", components.Field{ID: "webhook_target", Name: "target", Label: msg.T("admin.keys.stack.target.label"), Type: "select", Options: targets}),
			b.add("field", components.Field{ID: "url", Label: msg.T("admin.notifications.webhook.url.label"), Type: "url", Required: true,
				Hint: msg.T("admin.notifications.webhook.url.hint")}),
			b.add("button", components.Button{Text: msg.T("admin.notifications.webhook.save.label"), Type: "submit", Variant: "primary"}),
		),
	})
	block.Body = components.Join(table, set)
	return b.add("block", block)
}

// setWebhook sets or clears the webhook of one stack tenant.
func (p *Portal) setWebhook(w http.ResponseWriter, r *http.Request, s session) error {
	tenantID, stack, ok := strings.Cut(r.PostFormValue("target"), "|")
	if !ok || tenantID == "" {
		return connect.NewError(connect.CodeInvalidArgument, errTarget)
	}
	d, err := stackValue(stack)
	if err != nil {
		return err
	}
	hook := strings.TrimSpace(r.PostFormValue("url"))
	if _, err := p.opts.Client.SetStackWebhook(r.Context(), call(s, &adminv1.SetStackWebhookRequest{
		TenantId: tenantID, Stack: d, Url: hook,
	})); err != nil {
		return err
	}
	code := "webhook-saved"
	if hook == "" {
		code = "webhook-cleared"
	}
	p.redirect(w, r, "/notifications", code)
	return nil
}

// notBuilt is the state of a VCA channel that this release does not
// build. The catalogue keeps a sentence; the badge drops its full stop.
func notBuilt() string {
	return strings.TrimSuffix(msg.T("admin.notifications.not_built"), ".")
}
