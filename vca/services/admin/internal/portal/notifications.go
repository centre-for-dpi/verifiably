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
	mux.HandleFunc("POST "+at+"/notifications/holder", p.posted(p.setHolderEndpoint))
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
		if f.has(backendv1.Feature_FEATURE_HOLDER_NOTIFICATIONS) {
			hooks = components.Join(hooks, p.holderBlock(b, s, res.Msg.GetWebhooks()))
		}
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
			if h.GetWebhook().GetSigned() {
				state = components.Join(state, b.add("badge", components.Badge{Status: "info", Text: msg.T("admin.notifications.webhook.signed.label")}))
			}
			if h.GetWebhook().GetFixed() {
				// The stack keeps a webhook once set, so no clear shows.
				action = hint(msg.T("admin.notifications.webhook.fixed"))
				break
			}
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
		Body: stackedForm(at+"/notifications/webhook", s.CSRF, components.Join(
			b.add("field", components.Field{ID: "webhook_target", Name: "target", Label: msg.T("admin.keys.stack.target.label"), Type: "select", Options: targets}),
			b.add("field", components.Field{ID: "url", Label: msg.T("admin.notifications.webhook.url.label"), Type: "url", Required: true,
				Hint: msg.T("admin.notifications.webhook.url.hint")}),
			b.add("field", components.Field{ID: "signing_secret", Label: msg.T("admin.notifications.webhook.secret.label"), Type: "password",
				Autocomplete: "new-password", Hint: msg.T("admin.notifications.webhook.secret.hint")}),
			b.add("button", components.Button{Text: msg.T("admin.notifications.webhook.save.label"), Type: "submit", Variant: "primary"}),
		)),
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
		TenantId: tenantID, Stack: d, Url: hook, SigningSecret: r.PostFormValue("signing_secret"),
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

// holderBlock is the section of the holder notifications of a stack
// (ADR-067): one row per stack tenant with its address, and the form
// for a tenant with none. The stack takes one address per tenant.
func (p *Portal) holderBlock(b *blocks, s session, hooks []*adminv1.StackWebhook) template.HTML {
	at := p.opts.Prefix
	block := components.Block{ID: "holder-notifications", Title: msg.T("admin.notifications.holder.label"), Lead: msg.T("admin.notifications.holder.lead")}
	rows := make([]components.Row, 0, len(hooks))
	var targets []components.Option
	for _, h := range hooks {
		// Only a stack that lists the feature reads an address.
		if h.GetNotification() == nil && h.GetNotificationError() == "" {
			continue
		}
		var address, state template.HTML
		switch n := h.GetNotification(); {
		case h.GetNotificationError() != "":
			address = hint(msg.T("admin.notifications.webhook.unknown.label"))
			state = components.Join(b.add("badge", components.Badge{Status: "warn", Text: msg.T("admin.tenants.binding.error.label")}),
				hint(h.GetNotificationError()))
		case n.GetUrl() == "":
			address = hint(msg.T("admin.notifications.holder.none.label"))
			state = b.add("badge", components.Badge{Status: "info", Text: msg.T("admin.notifications.webhook.off.label")})
			targets = append(targets, components.Option{
				Value: h.GetTenantId() + "|" + h.GetStack().String(), Text: msg.T("admin.keys.stack.target.value.label", h.GetTenantName(), h.GetStackName()),
			})
		default:
			address = code(n.GetUrl())
			state = b.add("badge", components.Badge{Status: "ok", Text: msg.T("admin.notifications.webhook.on.label")})
			if n.GetKeptByAdapter() {
				state = components.Join(state, hint(msg.T("admin.notifications.holder.kept")))
			}
		}
		rows = append(rows, components.Row{{Text: h.GetTenantName()}, {Text: h.GetStackName()}, {HTML: address}, {HTML: state}})
	}
	table := b.add("table", components.Table{
		ID: "holder-endpoints", Caption: msg.T("admin.notifications.holder.caption.label", strconv.Itoa(len(rows))),
		Columns: []string{
			msg.T("admin.keys.column.tenant.label"), msg.T("admin.keys.stack.column.stack.label"),
			msg.T("admin.notifications.column.address.label"), msg.T("admin.notifications.column.state.label"),
		},
		Rows: rows,
	})
	if len(targets) == 0 {
		block.Body = table
		return b.add("block", block)
	}
	set := b.add("card", components.Card{
		ID: "set-holder-endpoint", Title: msg.T("admin.notifications.holder.set.label"), Text: msg.T("admin.notifications.holder.set.text"),
		Body: stackedForm(at+"/notifications/holder", s.CSRF, components.Join(
			b.add("field", components.Field{ID: "holder_target", Name: "target", Label: msg.T("admin.keys.stack.target.label"), Type: "select", Options: targets}),
			b.add("field", components.Field{ID: "notification_url", Label: msg.T("admin.notifications.holder.url.label"), Type: "url", Required: true,
				Hint: msg.T("admin.notifications.holder.url.hint")}),
			b.add("button", components.Button{Text: msg.T("admin.notifications.holder.save.label"), Type: "submit", Variant: "primary"}),
		)),
	})
	block.Body = components.Join(table, set)
	return b.add("block", block)
}

// setHolderEndpoint registers the holder notification address of one
// stack tenant.
func (p *Portal) setHolderEndpoint(w http.ResponseWriter, r *http.Request, s session) error {
	tenantID, stack, ok := strings.Cut(r.PostFormValue("target"), "|")
	if !ok || tenantID == "" {
		return connect.NewError(connect.CodeInvalidArgument, errTarget)
	}
	d, err := stackValue(stack)
	if err != nil {
		return err
	}
	if _, err := p.opts.Client.SetStackNotificationEndpoint(r.Context(), call(s, &adminv1.SetStackNotificationEndpointRequest{
		TenantId: tenantID, Stack: d, Url: strings.TrimSpace(r.PostFormValue("notification_url")),
	})); err != nil {
		return err
	}
	p.redirect(w, r, "/notifications", "notification-saved")
	return nil
}

// notBuilt is the state of a VCA channel that this release does not
// build. The catalogue keeps a sentence; the badge drops its full stop.
func notBuilt() string {
	return strings.TrimSuffix(msg.T("admin.notifications.not_built"), ".")
}
