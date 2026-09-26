// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"context"
	"html/template"
	"net/http"
	"strings"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// A stack wallet that lists FEATURE_WALLET_CLAIM_IN_STACK claims an
// offer in its own pages. The wallet then uses the stack for what the
// stack holds and keeps the browser store beside it for what the holder
// loads here. A stack wallet that lists FEATURE_WALLET_DOCUMENT gives a
// document of each credential.

// Has reports whether the adapter of the own pair lists a feature. The
// service asks it per request, so it follows the live probe.
func (p *Portal) Has(ctx context.Context, feature backendv1.Feature) bool {
	return p.shell.Frame(ctx).Has(feature)
}

// hybrid reports whether the stack wallet sits beside the browser store.
func (p *Portal) hybrid(b *pen) bool {
	return !p.opts.Service.BrowserStorage() && b.frame.Has(backendv1.Feature_FEATURE_WALLET_CLAIM_IN_STACK)
}

// stackPage returns the display name of the own stack and the address
// of its wallet page: the first component with a public address.
func stackPage(b *pen) (string, string) {
	own := b.ownCaps()
	name := own.GetDpgInfo().GetDisplayName()
	for _, c := range own.GetDpgInfo().GetComponents() {
		if u := c.GetUrl(); strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://") {
			return name, u
		}
	}
	return name, ""
}

// stackCard renders the card that sends the holder to the wallet page
// of the stack to claim.
func (p *Portal) stackCard(b *pen, text string) template.HTML {
	name, page := stackPage(b)
	var body template.HTML
	if page != "" {
		body = b.part("button", components.Button{
			Text: msg.T("holder.stack.open.label", name), Href: page, Variant: "primary",
		})
	}
	return b.part("card", components.Card{
		ID: "stack-claim", Title: msg.T("holder.stack.title", name), Text: text, Body: body,
	})
}

// documentLink renders the link to the document of a stack credential.
func (p *Portal) documentLink(b *pen, card *walletportalv1.Card) template.HTML {
	if card.GetInBrowser() || p.opts.Service.BrowserStorage() || !b.frame.Has(backendv1.Feature_FEATURE_WALLET_DOCUMENT) {
		return ""
	}
	return b.part("button", components.Button{
		Text: msg.T("holder.card.document.label"), Variant: "secondary",
		Href: p.opts.Prefix + "/document?id=" + template.URLQueryEscaper(card.GetId()),
	})
}

// document serves the document of one stack credential as a download.
func (p *Portal) document(w http.ResponseWriter, r *http.Request) error {
	if !p.pen(r).frame.Has(backendv1.Feature_FEATURE_WALLET_DOCUMENT) {
		http.NotFound(w, r)
		return nil
	}
	resp, err := p.opts.Service.Document(r.Context(), connect.NewRequest(&walletportalv1.DocumentRequest{
		Id: r.URL.Query().Get("id"),
	}))
	if err != nil {
		return p.problem(w, r, msg.T("holder.nav.credentials.label"), msg.T("holder.card.document.problem"), message(err))
	}
	media := resp.Msg.GetMediaType()
	if media == "" {
		media = "application/octet-stream"
	}
	name := "credential"
	if media == "application/pdf" {
		name += ".pdf"
	}
	w.Header().Set("Content-Type", media)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, err = w.Write(resp.Msg.GetContent())
	return err
}
