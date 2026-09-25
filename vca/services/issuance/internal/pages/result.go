// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"encoding/base64"
	"errors"
	"html/template"
	"net/url"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/qr"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuancev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/service"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// qrQuiet is the light margin of the QR symbol in modules. The standard
// asks for four at least.
const qrQuiet = 4

// result draws the result of one issuance: the QR code of the offer,
// the transaction code, the link, the document, and the wallets of the
// live holder pairs (board Issuer-Issue, spec IS5 and IS7).
func (p *Pages) result(pg page) error {
	if p.opts.Issuance == nil {
		return connect.NewError(connect.CodeNotFound, errNoOffer)
	}
	ctx := pg.r.Context()
	res, err := p.opts.Issuance.GetOffer(ctx, staffshell.AsActor(ctx, &issuancev1.GetOfferRequest{Id: pg.r.PathValue("id")}))
	if err != nil {
		return err
	}
	offer := res.Msg.GetOffer()
	caps := p.caps(pg)
	name := p.offerSchemaName(pg, offer)
	b := p.blocks()
	parts := []template.HTML{p.offerBlock(b, offer, name, p.issuerName(pg, caps))}
	parts = append(parts, p.handoff(b, pg.f))
	actions := b.add("button", components.Button{Text: msg.T("issuer.issue.again.label"), Href: IssuePath, Variant: "primary"})
	if b.err != nil {
		return b.err
	}
	return p.render(pg, components.Page{
		Title: msg.T("issuer.issue.result.title.label"), Label: msg.T("issuer.nav.issue.label"),
		Lead: msg.T("issuer.issue.result.lead", name), Description: msg.T("issuer.issue.lead"),
		Actions: actions, Content: components.Join(parts...),
	})
}

// errNoOffer reports a result page without an issuance service.
var errNoOffer = errors.New("no issuance service")

// offerSchemaName names the schema of an offer, or its id when the
// registry does not answer.
func (p *Pages) offerSchemaName(pg page, offer *issuancev1.Offer) string {
	if p.opts.Schemas == nil || offer.GetSchemaId() == "" {
		return offer.GetSchemaId()
	}
	ctx := pg.r.Context()
	res, err := p.opts.Schemas.Get(ctx, staffshell.AsActor(ctx, &schemav1.GetRequest{Id: offer.GetSchemaId(), Version: offer.GetSchemaVersion()}))
	if err != nil {
		return offer.GetSchemaId()
	}
	return schemaName(res.Msg.GetSchema())
}

// issuerName names the issuer: the display name of the identity of the
// stack, else its identifier, else the stack.
func (p *Pages) issuerName(pg page, caps *backendv1.GetCapabilitiesResponse) string {
	if p.opts.Identity != nil {
		res, err := p.opts.Identity.GetIssuerIdentity(pg.r.Context(), connect.NewRequest(&backendv1.GetIssuerIdentityRequest{}))
		if err == nil {
			if n := res.Msg.GetIdentity().GetMetadata().GetDisplayName(); n != "" {
				return n
			}
			if id := firstIdentifier(res.Msg.GetIdentity()); id != "" {
				return id
			}
		}
	}
	return stackName(caps)
}

// offerBlock is the offer: its state, the QR code, the transaction
// code, the link, and the document.
func (p *Pages) offerBlock(b *blocks, offer *issuancev1.Offer, schema, issuer string) template.HTML {
	var qrPart, body []template.HTML
	if src, ok := qrImage(offer.GetOfferUri()); ok {
		qrPart = append(qrPart, b.add("qr", components.QR{Src: src, Alt: msg.T("issuer.issue.result.qr.alt", schema, issuer), Size: 256}))
	}
	if pin := offer.GetPin(); pin != "" {
		body = append(body, b.add("code", components.Code{ID: "pin", Label: msg.T("issuer.issue.result.pin.label"), Text: pin}))
	}
	var row []template.HTML
	if uri := offer.GetOfferUri(); uri != "" && offer.GetChannel() == backendv1.Channel_CHANNEL_DC_API && walletLink(uri) {
		// The button stays hidden until /static/dcapi.js finds the API.
		// The QR code and the link stay for every other browser (ADR-043
		// decision 3).
		row = append(row, b.add("dcapi", components.DCAPI{
			Text: msg.T("issuer.issue.dc_api.button.label"), Offer: uri, OK: msg.T("issuer.issue.dc_api.ok"),
			Cancel: msg.T("issuer.issue.dc_api.cancel"), Fail: msg.T("issuer.issue.dc_api.fail"),
		}))
	}
	if uri := offer.GetOfferUri(); uri != "" {
		body = append(body, b.add("code", components.Code{ID: "offer-link", Label: msg.T("issuer.issue.result.link.label"), Text: uri}))
		if walletLink(uri) {
			row = append(row, offerAnchor(uri, msg.T("issuer.issue.result.open.label")))
		}
	}
	if ref := offer.GetPdfRef(); ref != "" {
		row = append(row, b.add("button", components.Button{Text: msg.T("issuer.issue.result.pdf.label"), Href: service.DocumentPath + url.PathEscape(ref), Variant: "secondary"}))
	}
	if len(row) > 0 {
		body = append(body, actionRow(row...))
	}
	var lead []string
	if key := channelKey(offer.GetChannel()); key != "" {
		lead = append(lead, msg.T("issuer.issue.result.channel", msg.T(key+".label")))
	}
	if offer.GetPin() != "" {
		lead = append(lead, msg.T("issuer.issue.result.pin.text"))
	}
	content := components.Join(body...)
	if len(qrPart) > 0 {
		// The QR code sits beside the codes and the links on a wide screen.
		content = template.HTML(`<div class="media-row"><div>`) + components.Join(qrPart...) +
			template.HTML(`</div><div>`) + content + template.HTML(`</div></div>`)
	}
	return b.add("block", components.Block{
		ID: "offer", Title: msg.T("issuer.issue.result.offer.label"), Meta: stateText(offer.GetState()), Lead: strings.Join(lead, " "),
		Body: content,
	})
}

// stateText names the state of an offer.
func stateText(s issuancev1.Offer_State) string {
	switch s {
	case issuancev1.Offer_STATE_DELIVERED:
		return msg.T("issuer.issue.state.delivered.label")
	case issuancev1.Offer_STATE_DEFERRED:
		return msg.T("issuer.issue.state.deferred.label")
	case issuancev1.Offer_STATE_EXPIRED:
		return msg.T("issuer.issue.state.expired.label")
	case issuancev1.Offer_STATE_FAILED:
		return msg.T("issuer.issue.state.failed.label")
	}
	return msg.T("issuer.issue.state.pending.label")
}

// walletLink reports whether an offer URI is safe as a link: the offer
// scheme of OID4VCI, or https.
func walletLink(uri string) bool {
	u, err := url.Parse(uri)
	return err == nil && (u.Scheme == "openid-credential-offer" || u.Scheme == "https")
}

// offerAnchor links the offer URI, so a wallet on the same device opens
// it. walletLink checked the scheme; the text and the address are
// escaped.
func offerAnchor(uri, text string) template.HTML {
	return template.HTML(`<a class="btn btn-secondary" href="` + template.HTMLEscapeString(uri) + `">` + template.HTMLEscapeString(text) + `</a>`) //nolint:gosec // the scheme is checked and both parts are escaped
}

// qrImage draws the QR code of a payload as an SVG data URI. ok is
// false when the payload is empty or too long for a QR code.
func qrImage(payload string) (template.URL, bool) {
	if payload == "" {
		return "", false
	}
	code, err := qr.Encode([]byte(payload))
	if err != nil {
		return "", false
	}
	n := code.Size + 2*qrQuiet
	var path strings.Builder
	for y := 0; y < code.Size; y++ {
		for x := 0; x < code.Size; x++ {
			if code.Module(x, y) {
				path.WriteString("M" + strconv.Itoa(x+qrQuiet) + " " + strconv.Itoa(y+qrQuiet) + "h1v1h-1z")
			}
		}
	}
	size := strconv.Itoa(n)
	svg := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ` + size + ` ` + size + `" shape-rendering="crispEdges">` +
		`<rect width="` + size + `" height="` + size + `" fill="#fff"/><path fill="#000" d="` + path.String() + `"/></svg>`
	return template.URL("data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(svg))), true //nolint:gosec // the page builds the SVG from the QR modules alone
}

// handoff points the staff member at the wallets of the live holder
// pairs of the deployment, by the names their adapters report.
func (p *Pages) handoff(b *blocks, f staffshell.Frame) template.HTML {
	live := f.Live(commonv1.Role_ROLE_HOLDER)
	block := components.Block{ID: "handoff", Title: msg.T("issuer.issue.handoff.label")}
	if len(live) == 0 {
		block.Lead = msg.T("issuer.issue.handoff.none")
		return b.add("block", block)
	}
	block.Lead = msg.T("issuer.issue.handoff.text")
	buttons := make([]components.Button, 0, len(live))
	for _, st := range live {
		buttons = append(buttons, components.Button{
			Text: msg.T("issuer.issue.handoff.wallet.label", holderName(st)), Variant: "secondary",
			Href: strings.TrimRight(st.Peer.PublicURL, "/") + topology.HomePath(commonv1.Role_ROLE_HOLDER),
		})
	}
	block.Body = p.actions(b, buttons...)
	return b.add("block", block)
}

// holderName is the name of the stack of a holder pair as its adapter
// reports it, else the pair name.
func holderName(st topology.Status) string {
	if n := st.Capabilities.GetDpgInfo().GetDisplayName(); n != "" {
		return n
	}
	return st.Peer.Pair
}
