// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"html/template"
	"net/http"
	"net/url"

	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// A DIDComm invitation (P6-C3). An issuer that issues over DIDComm shows
// an out of band invitation. This wallet claims OID4VCI offers, so the
// page names the invitation and points the holder at a DIDComm wallet.

// invitationPage renders the page of one DIDComm invitation.
func (p *Portal) invitationPage(w http.ResponseWriter, r *http.Request, inv *walletportalv1.DidcommInvitation) error {
	b := p.pen(r)
	card := p.invitationCard(b, inv)
	return p.render(w, r, b, components.Page{
		Title: msg.T("holder.invitation.title.label"), Lead: msg.T("holder.invitation.lead"),
		Description: msg.T("holder.invitation.lead"), Content: card,
	})
}

// invitationCard names the invitation, who sent it, and what it
// carries, with the text to copy and a link that a DIDComm wallet on
// the same device opens.
func (p *Portal) invitationCard(b *pen, inv *walletportalv1.DidcommInvitation) template.HTML {
	text := msg.T("holder.invitation.text")
	if inv.GetCarriesOffer() {
		text = msg.T("holder.invitation.offer.text")
	}
	title := msg.T("holder.invitation.title.label")
	if label := inv.GetLabel(); label != "" {
		title = msg.T("holder.invitation.from.label", label)
	}
	parts := []template.HTML{b.part("code", components.Code{ID: "invitation", Label: msg.T("holder.invitation.code.label"), Text: inv.GetUri()})}
	if openable(inv.GetUri()) {
		parts = append(parts, b.raw(`<div class="form-actions"><a class="btn btn-primary" href="`+
			template.HTMLEscapeString(inv.GetUri())+`">`+template.HTMLEscapeString(msg.T("holder.invitation.open.label"))+`</a></div>`))
	}
	return b.part("card", components.Card{ID: "didcomm-invitation", Title: title, Text: text, Body: components.Join(parts...)})
}

// openable reports whether an invitation is safe as a link: https or
// the didcomm scheme that a DIDComm wallet opens.
func openable(uri string) bool {
	u, err := url.Parse(uri)
	return err == nil && (u.Scheme == "https" || u.Scheme == "didcomm")
}
