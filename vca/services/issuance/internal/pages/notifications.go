// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"html/template"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// deliveryChannels are the VCA delivery channels. VCA builds none of
// them in this release (ADR-040 decision 1).
var deliveryChannels = []string{"email", "sms", "webhook"}

// notifications names the delivery channels of the issuer and their
// state, and the webhooks of the stack when its adapter lists them.
func (p *Pages) notifications(pg page) error {
	b := p.blocks()
	rows := make([]components.Row, 0, len(deliveryChannels))
	for _, c := range deliveryChannels {
		key := "admin.notifications.channel." + c
		rows = append(rows, components.Row{
			{HTML: template.HTML(`<strong>`) + escape(msg.T(key+".label")) + template.HTML(`</strong>`)}, //nolint:gosec // literal tags around escaped text
			{Text: msg.T(key + ".text")},
			{HTML: b.add("badge", components.Badge{Status: "warn", Text: msg.T("admin.notifications.not_built")})},
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
	if caps := p.caps(pg); has(caps, backendv1.Feature_FEATURE_WEBHOOKS) {
		hooks = b.add("card", components.Card{
			ID: "stack-webhooks", Title: msg.T("admin.notifications.webhooks.label"),
			Text: msg.T("issuer.notifications.webhooks.text", stackName(caps)),
		})
	}
	if b.err != nil {
		return b.err
	}
	return p.render(pg, components.Page{
		Title: msg.T("common.notifications.label"), Lead: msg.T("issuer.notifications.lead"),
		Description: msg.T("issuer.notifications.lead"), Content: components.Join(delivery, hooks),
	})
}
