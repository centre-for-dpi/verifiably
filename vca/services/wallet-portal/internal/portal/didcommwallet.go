// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"html/template"
	"net/http"
	"strconv"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// The DIDComm wallet of the stack (P6-C7, ADR-062). The pages exist
// only when the adapter of the own pair lists FEATURE_WALLET_DIDCOMM
// (ADR-034 decision 5).
//
//	POST /invitation   accept or decline a scanned invitation
//	GET  /connections  what waits over a connection, and the connections
//	POST /inbox        accept an offer or answer a request that waits

// The kinds of an inbox entry in a form.
const (
	kindOffer   = "offer"
	kindRequest = "request"
)

// didcommPage reports whether the own stack wallet speaks DIDComm. It
// answers 404 when it does not.
func (p *Portal) didcommPage(w http.ResponseWriter, r *http.Request) (*pen, bool) {
	b := p.pen(r)
	if !b.frame.Has(backendv1.Feature_FEATURE_WALLET_DIDCOMM) {
		http.NotFound(w, r)
		return nil, false
	}
	return b, true
}

// valueTable renders the values of an offer.
func (b *pen) valueTable(id string, values []*walletportalv1.NamedValue) template.HTML {
	rows := make([]components.Row, 0, len(values))
	for _, v := range values {
		rows = append(rows, components.Row{{Text: v.GetName()}, {Text: v.GetValue()}})
	}
	return b.part("table", components.Table{
		ID: id, Caption: msg.T("holder.didcomm.values.caption.label"),
		Columns: []string{msg.T("holder.didcomm.column.name.label"), msg.T("holder.didcomm.column.value.label")},
		Rows:    rows, Empty: msg.T("holder.didcomm.values.empty"),
	})
}

// askedList renders what a proof request asks for.
func (b *pen) askedList(asked []string) template.HTML {
	if len(asked) == 0 {
		return b.raw(`<p>` + template.HTMLEscapeString(msg.T("holder.didcomm.asked.empty")) + `</p>`)
	}
	out := `<p>` + template.HTMLEscapeString(msg.T("holder.didcomm.asked.label")) + `</p><ul>`
	for _, a := range asked {
		out += `<li>` + template.HTMLEscapeString(a) + `</li>`
	}
	return b.raw(out + `</ul>`)
}

// answerCard renders an invitation that the stack wallet opens: what it
// carries, and the accept and decline buttons.
func (p *Portal) answerCard(b *pen, inv *walletportalv1.DidcommInvitation) template.HTML {
	from := inv.GetLabel()
	if from == "" {
		from = msg.T("holder.didcomm.unnamed.label")
	}
	var body template.HTML
	var title, text, accept string
	switch {
	case inv.GetCarriesOffer():
		title, text, accept = msg.T("holder.didcomm.offer.label", from), msg.T("holder.didcomm.offer.text"), msg.T("holder.offer.accept.label")
		body = b.valueTable("invitation-values", inv.GetOffered())
	case inv.GetCarriesRequest():
		title, text, accept = msg.T("holder.didcomm.request.label", from), msg.T("holder.didcomm.request.text"), msg.T("holder.didcomm.share.label")
		body = b.askedList(inv.GetRequested())
	default:
		title, text, accept = msg.T("holder.didcomm.connection.label", from), msg.T("holder.didcomm.connection.text"), msg.T("holder.didcomm.connect.label")
	}
	if name := inv.GetName(); name != "" {
		body = b.raw(`<p><strong>`+template.HTMLEscapeString(name)+`</strong></p>`) + body
	}
	// Decline and accept share one form. The form has no text field, so
	// no key press submits it.
	decline := b.part("button", components.Button{Text: msg.T("holder.offer.decline.label"), Type: "submit", Variant: "secondary",
		Name: "action", Value: "decline"})
	actions := b.raw(`<div class="form-actions">`) +
		b.form(p.opts.Prefix+"/invitation", map[string]string{"invitation_id": inv.GetInvitationId()},
			components.Button{Text: accept, Type: "submit", Variant: "primary", Name: "action", Value: "accept"}, decline) +
		b.raw(`</div>`)
	return b.part("card", components.Card{ID: "didcomm-invitation", Title: title, Text: text, Body: body + actions})
}

// answerInvitation accepts or declines a scanned invitation.
func (p *Portal) answerInvitation(w http.ResponseWriter, r *http.Request) error {
	if _, ok := p.didcommPage(w, r); !ok {
		return nil
	}
	if _, ok := p.writer(w, r); !ok {
		return nil
	}
	resp, err := p.opts.Service.AnswerInvitation(r.Context(), connect.NewRequest(&walletportalv1.AnswerInvitationRequest{
		InvitationId: r.PostFormValue("invitation_id"), Decline: r.PostFormValue("action") == "decline",
	}))
	if err != nil {
		return p.problem(w, r, msg.T("holder.invitation.title.label"), msg.T("holder.didcomm.problem.title"), message(err))
	}
	switch {
	case resp.Msg.GetRecord() != nil:
		return p.outcome(w, r, answerOf(resp.Msg.GetRecord(), resp.Msg.GetMessage()))
	case resp.Msg.GetConnectionLabel() != "":
		http.Redirect(w, r, p.opts.Prefix+"/connections?notice=connected", http.StatusSeeOther)
	default:
		http.Redirect(w, r, p.opts.Prefix+"/", http.StatusSeeOther)
	}
	return nil
}

// answerOf turns the record of a DIDComm answer into the answer the
// outcome page shows.
func answerOf(rec *walletportalv1.PresentationRecord, text string) *walletportalv1.PresentConfirmResponse {
	return &walletportalv1.PresentConfirmResponse{
		Accepted: rec.GetResult() == walletportalv1.PresentationRecord_RESULT_ACCEPTED, Message: text, Record: rec,
	}
}

// connections renders the page of the DIDComm wallet: what waits over a
// connection, and the connections.
func (p *Portal) connections(w http.ResponseWriter, r *http.Request) error {
	b, ok := p.didcommPage(w, r)
	if !ok {
		return nil
	}
	var parts []template.HTML
	inbox, err := p.opts.Service.ListInbox(r.Context(), connect.NewRequest(&walletportalv1.ListInboxRequest{}))
	if err != nil {
		parts = append(parts, b.part("card", components.Card{ID: "inbox-problem", Title: msg.T("holder.didcomm.problem.title"), Text: message(err)}))
	} else {
		parts = append(parts, p.inboxBlock(b, inbox.Msg.GetEntries()))
	}
	conns, err := p.opts.Service.ListConnections(r.Context(), connect.NewRequest(&walletportalv1.ListConnectionsRequest{}))
	if err != nil {
		parts = append(parts, b.part("card", components.Card{ID: "connections-problem", Title: msg.T("holder.didcomm.problem.title"), Text: message(err)}))
	} else {
		parts = append(parts, p.connectionBlock(b, conns.Msg.GetConnections()))
	}
	page := components.Page{
		Title: msg.T("holder.nav.connections.label"), Lead: msg.T("holder.didcomm.lead"), Description: msg.T("holder.didcomm.lead"),
		Content: components.Join(parts...),
	}
	if r.URL.Query().Get("notice") == "connected" {
		page.Toasts = []components.Toast{{ID: "connected", Level: "ok", Text: msg.T("holder.didcomm.connected")}}
	}
	return p.render(w, r, b, page)
}

// inboxBlock renders one card per entry that waits, with its answer
// form.
func (p *Portal) inboxBlock(b *pen, entries []*walletportalv1.InboxEntry) template.HTML {
	if len(entries) == 0 {
		return b.part("block", components.Block{ID: "inbox", Title: msg.T("holder.didcomm.inbox.label"),
			Body: b.raw(`<p>` + template.HTMLEscapeString(msg.T("holder.didcomm.inbox.empty")) + `</p>`)})
	}
	var cards []template.HTML
	for i, e := range entries {
		from := e.GetFrom()
		if from == "" {
			from = msg.T("holder.didcomm.unnamed.label")
		}
		var body template.HTML
		var title, kind, accept string
		if e.GetKind() == walletportalv1.InboxEntry_KIND_OFFER {
			title, kind, accept = msg.T("holder.didcomm.offer.label", from), kindOffer, msg.T("holder.offer.accept.label")
			body = b.valueTable("inbox-values-"+strconv.Itoa(i), e.GetOffered())
		} else {
			title, kind, accept = msg.T("holder.didcomm.request.label", from), kindRequest, msg.T("holder.didcomm.share.label")
			body = b.askedList(e.GetRequested())
		}
		if name := e.GetName(); name != "" {
			body = b.raw(`<p><strong>`+template.HTMLEscapeString(name)+`</strong></p>`) + body
		}
		body += b.raw(`<div class="form-actions">`) + b.form(p.opts.Prefix+"/inbox", map[string]string{"id": e.GetId(), "kind": kind},
			components.Button{Text: accept, Type: "submit", Variant: "primary"}) + b.raw(`</div>`)
		text := msg.T("holder.didcomm.inbox.text")
		if at := e.GetReceivedAt(); at != nil {
			text = msg.T("holder.didcomm.inbox.when", shortDay(at.AsTime()))
		}
		cards = append(cards, b.part("card", components.Card{ID: "inbox-" + strconv.Itoa(i), Title: title, Text: text, Body: body}))
	}
	return b.part("block", components.Block{ID: "inbox", Title: msg.T("holder.didcomm.inbox.label"),
		Lead: msg.T("holder.didcomm.inbox.lead"), Body: components.Join(cards...)})
}

// connectionBlock renders the connections of the wallet.
func (p *Portal) connectionBlock(b *pen, list []*walletportalv1.Connection) template.HTML {
	rows := make([]components.Row, 0, len(list))
	for _, c := range list {
		since := ""
		if c.GetCreatedAt() != nil {
			since = shortDay(c.GetCreatedAt().AsTime())
		}
		rows = append(rows, components.Row{{Text: c.GetLabel()}, {Text: c.GetState()}, {Text: since}})
	}
	table := b.part("table", components.Table{
		ID: "wallet-connections", Caption: msg.T("holder.didcomm.connections.caption.label"),
		Columns: []string{msg.T("holder.didcomm.column.party.label"), msg.T("holder.didcomm.column.state.label"), msg.T("holder.didcomm.column.since.label")},
		Rows:    rows, Empty: msg.T("holder.didcomm.connections.empty"),
	})
	link := b.part("button", components.Button{Text: msg.T("holder.home.claim.label"), Href: p.opts.Prefix + "/claim", Variant: "secondary"})
	return b.part("block", components.Block{ID: "connections", Title: msg.T("holder.didcomm.connections.label"),
		Lead: msg.T("holder.didcomm.connections.lead"), Body: table + link})
}

// answerInbox accepts an offer or answers a request that waits.
func (p *Portal) answerInbox(w http.ResponseWriter, r *http.Request) error {
	if _, ok := p.didcommPage(w, r); !ok {
		return nil
	}
	if _, ok := p.writer(w, r); !ok {
		return nil
	}
	kind := walletportalv1.InboxEntry_KIND_UNSPECIFIED
	switch r.PostFormValue("kind") {
	case kindOffer:
		kind = walletportalv1.InboxEntry_KIND_OFFER
	case kindRequest:
		kind = walletportalv1.InboxEntry_KIND_PROOF_REQUEST
	}
	resp, err := p.opts.Service.AnswerInbox(r.Context(), connect.NewRequest(&walletportalv1.AnswerInboxRequest{
		Id: r.PostFormValue("id"), Kind: kind,
	}))
	if err != nil {
		return p.problem(w, r, msg.T("holder.nav.connections.label"), msg.T("holder.didcomm.problem.title"), message(err))
	}
	if rec := resp.Msg.GetRecord(); rec != nil {
		return p.outcome(w, r, answerOf(rec, resp.Msg.GetMessage()))
	}
	http.Redirect(w, r, p.opts.Prefix+"/", http.StatusSeeOther)
	return nil
}
