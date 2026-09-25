// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"fmt"
	"html/template"
	"net/http"
	"time"

	"connectrpc.com/connect"

	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/cards"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// mine renders the home page of board Holder-Portal: one card per
// credential with the issuer, the type, the status and the expiry, and a
// tile to discovery (ADR-021 decision 6).
func (p *Portal) mine(w http.ResponseWriter, r *http.Request) error {
	b := p.pen(r)
	resp, err := p.opts.Service.ListMine(r.Context(),
		connect.NewRequest(&walletportalv1.ListMineRequest{}))
	var parts []template.HTML
	if err != nil {
		parts = append(parts, b.part("card", components.Card{
			ID: "wallet-problem", Title: msg.T("holder.problem.title"), Text: msg.T("holder.problem.text"),
		}))
	} else {
		parts = append(parts, p.cardList(b, resp.Msg.GetCards()))
	}
	parts = append(parts, p.recent(b, r))
	if p.opts.Service.BrowserStorage() {
		parts = append(parts, p.browserCard(b))
	}
	lead := p.homeLead(b)
	return p.render(w, r, b, components.Page{
		Title:       msg.T("holder.nav.credentials.label"),
		Lead:        lead,
		Description: lead,
		Actions: components.Join(
			b.part("button", components.Button{Text: msg.T("holder.nav.present.label"), Href: p.opts.Prefix + "/present", Variant: "secondary"}),
			b.part("button", components.Button{Text: msg.T("holder.home.claim.label"), Href: p.opts.Prefix + "/claim", Variant: "primary"}),
		),
		Content: components.Join(parts...),
	})
}

// homeLead names the wallet of the own stack, or where the credentials
// sit when the browser keeps them.
func (p *Portal) homeLead(b *pen) string {
	if p.opts.Service.BrowserStorage() {
		return msg.T("holder.home.lead.browser")
	}
	if own, ok := b.frame.Own(); ok {
		if name := own.Capabilities.GetDpgInfo().GetDisplayName(); name != "" {
			return msg.T("holder.home.lead", name)
		}
	}
	return msg.T("holder.home.lead.plain")
}

// cardList renders the grid of credential cards, with the tile to
// discovery last.
func (p *Portal) cardList(b *pen, list []*walletportalv1.Card) template.HTML {
	add := components.Link{Href: p.opts.Prefix + "/discover", Text: msg.T("holder.home.add.label")}
	if len(list) == 0 {
		return components.Join(b.part("empty", components.Empty{
			Title: msg.T("holder.credentials.empty.title"), Text: msg.T("holder.credentials.empty.text"),
			Action: components.Button{Text: msg.T("holder.home.add.label"), Href: add.Href, Variant: "primary"},
		}))
	}
	items := make([]components.CredentialCard, 0, len(list))
	for i, card := range list {
		items = append(items, p.card(b, card, i))
	}
	return b.part("credentials", components.Credentials{Label: msg.T("holder.home.list.label"), Items: items, Add: add})
}

// card maps one credential onto a wallet card: the status word and tone,
// the expiry, and the detail with the trust, the claims, and the remove
// form.
func (p *Portal) card(b *pen, card *walletportalv1.Card, index int) components.CredentialCard {
	id := fmt.Sprintf("card-%d", index)
	status, word := cardStatus(card, p.opts.Now())
	trust := b.part("badge", components.Badge{
		Text: "Issuer: " + cards.TrustWord(card.GetTrust()), Status: cards.TrustStatus(card.GetTrust()),
	})
	state := b.part("badge", components.Badge{
		Text:   "Credential: " + cards.RevocationWord(card.GetRevocation()),
		Status: cards.RevocationStatus(card.GetRevocation()),
	})
	text := b.raw("<p>" + template.HTMLEscapeString(card.GetStatusText()) + "</p>")
	table := b.part("table", claimTable(id, card))
	remove := b.form(p.opts.Prefix+"/delete", map[string]string{"id": card.GetId()},
		components.Button{Text: "Remove from my wallet", Type: "submit", Variant: "danger"})
	title := card.GetTitle()
	if title == "" {
		title = msg.T("holder.card.untitled.label")
	}
	issuer := card.GetIssuerName()
	if issuer == "" {
		issuer = card.GetIssuer()
	}
	return components.CredentialCard{
		ID: id, Issuer: issuer, Title: title, Status: status, StatusText: word,
		Meta: cardMeta(card), Summary: msg.T("holder.card.more.label"),
		Body: components.Join(trust, state, text, b.raw(validity(card)), table, remove),
	}
}

// cardStatus returns the badge status and the word of a credential: a
// withdrawn or expired credential is bad, a stopped or early one warns,
// one the wallet could not check is info, and every other one is valid.
func cardStatus(card *walletportalv1.Card, now time.Time) (string, string) {
	window := card.GetValidity()
	switch {
	case card.GetRevocation() == walletportalv1.Card_REVOCATION_STATE_REVOKED:
		return "bad", msg.T("holder.card.revoked.label")
	case window.GetValidUntil() != nil && now.After(window.GetValidUntil().AsTime()):
		return "bad", msg.T("holder.card.expired.label")
	case card.GetRevocation() == walletportalv1.Card_REVOCATION_STATE_SUSPENDED:
		return "warn", msg.T("holder.card.suspended.label")
	case window.GetValidFrom() != nil && now.Before(window.GetValidFrom().AsTime()):
		return "warn", msg.T("holder.card.early.label")
	case card.GetRevocation() == walletportalv1.Card_REVOCATION_STATE_UNKNOWN:
		return "info", msg.T("holder.card.unknown.label")
	}
	return "ok", msg.T("holder.card.valid.label")
}

// cardMeta returns the meta line of a card: the expiry, the day the
// wallet got it, or a sentence that it names no end date.
func cardMeta(card *walletportalv1.Card) string {
	if until := card.GetValidity().GetValidUntil(); until != nil {
		return msg.T("holder.card.expires.label", shortDay(until.AsTime()))
	}
	if got := card.GetReceivedAt(); got != nil {
		return msg.T("holder.card.received.label", shortDay(got.AsTime()))
	}
	return msg.T("holder.card.open")
}

// shortDay formats a date for the meta line of a card, as the issuer
// pages do.
func shortDay(t time.Time) string { return t.UTC().Format("2 Jan 2006") }

// day formats a date for a card.
func day(t time.Time) string { return t.UTC().Format(time.DateOnly) }

// validity returns the validity window of a card in plain words.
func validity(card *walletportalv1.Card) string {
	window := card.GetValidity()
	from, until := window.GetValidFrom(), window.GetValidUntil()
	if from == nil && until == nil {
		return "<p>" + template.HTMLEscapeString(msg.T("holder.card.open")) + "</p>"
	}
	var parts string
	if from != nil {
		parts += "Valid from " + day(from.AsTime()) + ". "
	}
	if until != nil {
		parts += "Valid until " + day(until.AsTime()) + "."
	}
	return "<p>" + template.HTMLEscapeString(parts) + "</p>"
}
