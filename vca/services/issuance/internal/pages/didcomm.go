// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"context"
	"html/template"
	"net/mail"
	"slices"
	"strings"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuancev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// The DIDComm and email cards of the delivery step (P6-C3, ADR-059). A
// DIDComm invitation goes to a new wallet, or to a wallet that connected
// before. The email card of a stack that mails its own offers needs the
// address of the holder.

// Connections lists the DIDComm connections of the adapter of the pair.
type Connections interface {
	ListConnections(context.Context, *connect.Request[backendv1.ListConnectionsRequest]) (
		*connect.Response[backendv1.ListConnectionsResponse], error)
}

// maxConnections caps the connections the select lists.
const maxConnections = 100

// connectionComplete is the state of a connection that takes an offer.
const connectionComplete = "completed"

// connections lists the complete connections of the adapter. A failed
// call lists none, so the invitation still works.
func (p *Pages) connections(ctx context.Context) []*backendv1.DidcommConnection {
	if p.opts.Connections == nil {
		return nil
	}
	res, err := p.opts.Connections.ListConnections(ctx, connect.NewRequest(&backendv1.ListConnectionsRequest{
		Page: &commonv1.Pagination{PageSize: maxConnections},
	}))
	if err != nil {
		return nil
	}
	var out []*backendv1.DidcommConnection
	for _, c := range res.Msg.GetConnections() {
		if c.GetState() == connectionComplete {
			out = append(out, c)
		}
	}
	return out
}

// connectionName names a connection by the label of its wallet, else
// by its id.
func connectionName(c *backendv1.DidcommConnection) string {
	if l := strings.TrimSpace(c.GetLabel()); l != "" {
		return l
	}
	return c.GetId()
}

// didcommFields draws the fields of the DIDComm and the email cards
// that the step offers.
func (p *Pages) didcommFields(pg page, b *blocks, w wizard, list []backendv1.Channel) []template.HTML {
	var out []template.HTML
	if slices.Contains(list, backendv1.Channel_CHANNEL_DIDCOMM_OOB) {
		if conns := p.connections(pg.r.Context()); len(conns) > 0 {
			current := w.form.Get("connection")
			opts := []components.Option{{Value: "", Text: msg.T("issuer.issue.connection.new.label")}}
			for _, c := range conns {
				opts = append(opts, components.Option{Value: c.GetId(), Text: connectionName(c), Selected: c.GetId() == current})
			}
			out = append(out, b.add("field", components.Field{ID: "connection", Label: msg.T("issuer.issue.connection.label"),
				Type: "select", Hint: msg.T("issuer.issue.connection.hint"), Options: opts}))
		}
	}
	if slices.Contains(list, backendv1.Channel_CHANNEL_EMAIL) {
		value := w.form.Get("holder_email")
		if _, posted := w.form["holder_email"]; !posted {
			// The email claim of the credential fills the field.
			if v, ok := w.values.claims["email"].(string); ok {
				value = v
			}
		}
		out = append(out, b.add("field", components.Field{ID: "holder_email", Label: msg.T("issuer.issue.holder_email.label"),
			Type: "email", Value: value, Hint: msg.T("issuer.issue.holder_email.hint"), Autocomplete: "email"}))
	}
	return out
}

// deliveryProblem returns the catalogue key of what the delivery step
// lacks: the address of an email, or a format the channel carries.
func deliveryProblem(w wizard, channel backendv1.Channel) string {
	if channel == backendv1.Channel_CHANNEL_EMAIL {
		addr, err := mail.ParseAddress(strings.TrimSpace(w.form.Get("holder_email")))
		if err != nil || addr.Name != "" {
			return "issuer.issue.error.email"
		}
	}
	if !carriesFormat(w.caps, channel, pickFormat(w)) {
		return "issuer.issue.error.format"
	}
	return ""
}

// badDelivery sends a step back to the delivery step with the problem.
func (p *Pages) badDelivery(pg page, w wizard, key string) error {
	w.step = stepDelivery
	w.toasts = []components.Toast{{Level: "bad", Text: msg.T(key)}}
	return p.renderDelivery(pg, w)
}

// didcommRows names the connection or the address in the review.
func (p *Pages) didcommRows(pg page, w wizard, channel backendv1.Channel) []components.Row {
	switch channel {
	case backendv1.Channel_CHANNEL_DIDCOMM_OOB:
		name := msg.T("issuer.issue.connection.new.label")
		if id := w.form.Get("connection"); id != "" {
			name = id
			for _, c := range p.connections(pg.r.Context()) {
				if c.GetId() == id {
					name = connectionName(c)
				}
			}
		}
		return []components.Row{{{Text: msg.T("issuer.issue.review.connection.label")}, {Text: name}}}
	case backendv1.Channel_CHANNEL_EMAIL:
		return []components.Row{{{Text: msg.T("issuer.issue.review.email.label")}, {Text: strings.TrimSpace(w.form.Get("holder_email"))}}}
	}
	return nil
}

// deliveryOf is the delivery of the issue request: the channel, and the
// connection or the address it needs.
func deliveryOf(w wizard, channel backendv1.Channel) *issuancev1.Delivery {
	d := &issuancev1.Delivery{Channel: channel, Locale: "en"}
	switch channel {
	case backendv1.Channel_CHANNEL_DIDCOMM_OOB:
		d.ConnectionId = strings.TrimSpace(w.form.Get("connection"))
	case backendv1.Channel_CHANNEL_EMAIL:
		d.Email = strings.TrimSpace(w.form.Get("holder_email"))
	}
	return d
}
