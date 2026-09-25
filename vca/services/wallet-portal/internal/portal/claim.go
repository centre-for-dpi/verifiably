// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/qrscan"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/session"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// maxScanBytes caps the body of one post of the camera scanner.
const maxScanBytes = 1 << 20

// moved sends a browser from an old page to its new place.
func (p *Portal) moved(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, p.opts.Prefix+path, http.StatusMovedPermanently)
	}
}

// claimPage renders the claim page of spec HO3: the card "I have a code
// or a QR" and the card "Sign in at the issuer", side by side. In
// browser storage the page also offers to load a credential file.
func (p *Portal) claimPage(w http.ResponseWriter, r *http.Request) error {
	return p.renderClaim(w, r, "", "")
}

// renderClaim renders the claim page with the text the holder pasted
// and a problem sentence, after a paste the wallet could not read.
func (p *Portal) renderClaim(w http.ResponseWriter, r *http.Request, text, problem string) error {
	b := p.pen(r)
	cards := []template.HTML{p.codeCard(b, text, problem)}
	if !p.opts.Service.BrowserStorage() {
		cards = append(cards, p.signInCard(b, r))
	}
	parts := []template.HTML{b.raw(`<div class="split">`), components.Join(cards...), b.raw(`</div>`)}
	if p.opts.Service.BrowserStorage() {
		parts = append(parts, p.browserCard(b))
	}
	return p.render(w, r, b, components.Page{
		Title: msg.T("holder.home.claim.label"), Lead: msg.T("holder.claim.lead"), Description: msg.T("holder.claim.lead"),
		Content: components.Join(parts...),
	})
}

// codeCard renders the card "I have a code or a QR": the offer, the
// transaction code, and the camera scanner.
func (p *Portal) codeCard(b *pen, text, problem string) template.HTML {
	offer := b.part("field", components.Field{
		ID: "offer-text", Name: "offer", Label: msg.T("holder.claim.offer.label"), Value: text, Required: true,
		Hint: msg.T("holder.claim.offer.hint"), Error: problem,
		Attrs: map[string]string{"placeholder": "openid-credential-offer://", "spellcheck": "false"},
	})
	code := b.part("field", components.Field{
		ID: "tx-code", Name: "tx_code", Label: msg.T("holder.claim.txcode.label"), Hint: msg.T("holder.claim.txcode.hint"),
		Autocomplete: "one-time-code", Attrs: map[string]string{"inputmode": "numeric"},
	})
	esc := template.HTMLEscapeString
	form := b.raw(`<form method="post" action="`+esc(p.opts.Prefix+"/claim/offer")+`">`) +
		b.hidden(session.Field, b.guard.Token(b.who)) + offer + code +
		b.raw(`<div class="form-actions">`) +
		b.part("button", components.Button{Text: msg.T("holder.discover.claim.label"), Type: "submit", Variant: "primary"}) +
		b.raw(`<button type="button" id="scan-start" class="btn btn-secondary">`+esc(msg.T("holder.claim.scan.label"))+`</button>`+
			`</div></form>`)
	return b.part("card", components.Card{
		ID: "claim-code", Title: msg.T("holder.claim.code.label"), Text: msg.T("holder.claim.code.text"),
		Body: components.Join(form, p.scanner(b)),
	})
}

// scanner renders the camera view of qrscan and the form that carries
// its post address and the page token. The start button sits in the
// actions of the code card. The camera frames stay on the device; only
// the decoded text reaches /scan/read.
func (p *Portal) scanner(b *pen) template.HTML {
	esc := template.HTMLEscapeString
	static := p.opts.Prefix + "/static/"
	return b.raw(`<form id="scan-form" data-ingest="`+esc(p.opts.Prefix+"/scan/read")+`">`) +
		b.hidden(session.Field, b.guard.Token(b.who)) +
		b.raw(`</form>`+
			`<video id="scan-video" hidden playsinline muted aria-label="`+esc(msg.T("holder.claim.video.label"))+`"></video>`+
			`<p id="scan-status" class="hint" role="status" aria-live="polite">`+esc(msg.T("holder.claim.camera.off"))+`</p>`+
			`<div id="scan-result" role="status" aria-live="polite"></div>`+
			`<script src="`+esc(static+qrscan.Reader)+`" defer></script>`+
			`<script src="`+esc(static+qrscan.Script)+`" defer></script>`)
}

// signInCard renders the card "Sign in at the issuer" with the
// credentials of the issuers that let the holder sign in and that the
// eligibility hook allows.
func (p *Portal) signInCard(b *pen, r *http.Request) template.HTML {
	card := components.Card{ID: "claim-signin", Title: msg.T("holder.claim.signin.label"), Text: msg.T("holder.claim.signin.text")}
	resp, err := p.opts.Service.ListClaimable(r.Context(), connect.NewRequest(&walletportalv1.ListClaimableRequest{}))
	var options []components.Option
	if err == nil {
		for _, item := range resp.Msg.GetItems() {
			o := item.GetOffering()
			if item.GetEligible() && signsIn(o) {
				options = append(options, components.Option{
					Value: o.GetCredentialIssuer() + " " + configurationOf(o),
					Text:  msg.T("holder.claim.option.label", title(o), issuerName(o)),
				})
			}
		}
	}
	if len(options) == 0 {
		card.Body = b.raw(`<p class="hint">` + template.HTMLEscapeString(msg.T("holder.claim.signin.none")) + `</p>`)
		return b.part("card", card)
	}
	pick := b.part("field", components.Field{
		ID: "offering", Label: msg.T("holder.discover.column.credential.label"), Type: "select", Options: options,
		Hint: msg.T("holder.claim.signin.hint"),
	})
	card.Body = b.form(p.opts.Prefix+"/claim", nil,
		components.Button{Text: msg.T("holder.claim.signin.label"), Type: "submit", Variant: "primary"}, pick)
	return b.part("card", card)
}

// claimCard renders the claim card of board Holder-Discover for one
// offering: the ways the issuer allows, side by side, and a close link.
func (p *Portal) claimCard(b *pen, o *walletportalv1.Offering) template.HTML {
	var cards []template.HTML
	methods := append([]walletportalv1.ClaimMethod(nil), methodsOf(o)...)
	// The board puts the code first, then the sign in.
	sort.SliceStable(methods, func(i, j int) bool {
		return methods[i] == walletportalv1.ClaimMethod_CLAIM_METHOD_PRE_AUTHORIZED_CODE && methods[j] != methods[i]
	})
	for _, m := range methods {
		switch {
		case m == walletportalv1.ClaimMethod_CLAIM_METHOD_PRE_AUTHORIZED_CODE:
			cards = append(cards, p.codeCard(b, "", ""))
		case m == walletportalv1.ClaimMethod_CLAIM_METHOD_AUTHORIZATION_CODE && !p.opts.Service.BrowserStorage():
			form := b.form(p.opts.Prefix+"/claim", map[string]string{
				"credential_issuer": o.GetCredentialIssuer(), "schema_id": configurationOf(o),
			}, components.Button{Text: msg.T("holder.claim.signin.label"), Type: "submit", Variant: "primary"})
			cards = append(cards, b.part("card", components.Card{
				ID: "claim-signin", Title: msg.T("holder.claim.signin.label"), Text: msg.T("holder.claim.signin.text"), Body: form,
			}))
		}
	}
	if len(cards) == 0 {
		// The issuer lets the holder only sign in, which this wallet cannot
		// run. An offer from the issuer still works.
		cards = append(cards, p.codeCard(b, "", ""))
	}
	closeLink := b.raw(`<p><a href="` + template.HTMLEscapeString(p.opts.Prefix+"/discover") + `">` +
		template.HTMLEscapeString(msg.T("holder.claim.close.label")) + `</a></p>`)
	return b.part("card", components.Card{
		ID: "claim", Title: msg.T("holder.claim.for.label", title(o), issuerName(o)),
		Body: components.Join(b.raw(`<div class="split">`), components.Join(cards...), b.raw(`</div>`), closeLink),
	})
}

// chosen returns the offering the claim query names, counted from one.
func chosen(r *http.Request, list []*walletportalv1.Offering) (*walletportalv1.Offering, bool) {
	n, err := strconv.Atoi(r.URL.Query().Get("claim"))
	if err != nil || n < 1 || n > len(list) {
		return nil, false
	}
	return list[n-1], true
}

// signsIn reports whether the issuer of an offering lets the holder
// sign in.
func signsIn(o *walletportalv1.Offering) bool {
	for _, m := range o.GetClaimMethods() {
		if m == walletportalv1.ClaimMethod_CLAIM_METHOD_AUTHORIZATION_CODE {
			return true
		}
	}
	return false
}

// configurationOf returns the configuration id of an offering at its
// issuer, or its schema id.
func configurationOf(o *walletportalv1.Offering) string {
	for _, f := range o.GetSchema().GetFormats() {
		if id := o.GetSchema().GetConfigurationIds()[f.String()]; id != "" {
			return id
		}
	}
	return o.GetSchema().GetId()
}

// claim starts the sign in at the issuer (decision 3). The issuer sends
// the browser back to /claim/callback of the own pair.
func (p *Portal) claim(w http.ResponseWriter, r *http.Request) error {
	if _, ok := p.writer(w, r); !ok {
		return nil
	}
	issuer, schema := r.PostFormValue("credential_issuer"), r.PostFormValue("schema_id")
	if picked := r.PostFormValue("offering"); picked != "" {
		issuer, schema, _ = strings.Cut(picked, " ")
	}
	b := p.pen(r)
	resp, err := p.opts.Service.Claim(r.Context(), connect.NewRequest(&walletportalv1.ClaimRequest{
		CredentialIssuer: issuer, SchemaId: schema, RedirectUri: p.publicBase(r, b) + p.opts.Prefix + "/claim/callback",
	}))
	if err != nil {
		return p.problem(w, r, msg.T("holder.home.claim.label"), msg.T("holder.claim.problem.title"), message(err))
	}
	if next := resp.Msg.GetAuthorizationUrl(); next != "" {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return nil
	}
	if id := resp.Msg.GetOfferId(); id != "" {
		return p.offerPage(w, r, id, false, "")
	}
	http.Redirect(w, r, p.opts.Prefix+"/", http.StatusSeeOther)
	return nil
}

// publicBase returns the public URL of the wallet: the own pair of the
// frame, or the scheme and the host of the request.
func (p *Portal) publicBase(r *http.Request, b *pen) string {
	if own, ok := b.frame.Own(); ok && own.Peer.PublicURL != "" {
		return strings.TrimRight(own.Peer.PublicURL, "/")
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// callback takes the answer of the issuer after the sign in and claims
// the credential into the wallet.
func (p *Portal) callback(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	if _, err := p.opts.Service.ClaimComplete(r.Context(), connect.NewRequest(&walletportalv1.ClaimCompleteRequest{
		State: q.Get("state"), Code: q.Get("code"), Error: q.Get("error"),
	})); err != nil {
		return p.problem(w, r, msg.T("holder.home.claim.label"), msg.T("holder.claim.problem.title"), message(err))
	}
	http.Redirect(w, r, p.opts.Prefix+"/", http.StatusSeeOther)
	return nil
}

// claimOffer reads a pasted offer. With the transaction code the offer
// needs, or with an offer that needs none, the wallet claims at once. An
// offer that needs a code the holder did not give asks for it.
func (p *Portal) claimOffer(w http.ResponseWriter, r *http.Request) error {
	if _, ok := p.writer(w, r); !ok {
		return nil
	}
	text, pin := r.PostFormValue("offer"), strings.TrimSpace(r.PostFormValue("tx_code"))
	resp, err := p.opts.Service.Paste(r.Context(), connect.NewRequest(&walletportalv1.PasteRequest{Text: text}))
	if err != nil {
		return p.renderClaim(w, r, text, msg.T("holder.claim.unread"))
	}
	found := resp.Msg.GetDetected()
	switch found.GetKind() {
	case walletportalv1.Detected_KIND_CREDENTIAL_OFFER:
		offer := found.GetOffer()
		if (offer.GetNeedsPin() && pin == "") || p.opts.Service.BrowserStorage() {
			return p.offerPage(w, r, found.GetOfferId(), offer.GetNeedsPin(), offer.GetIssuerName())
		}
		if _, err := p.opts.Service.Accept(r.Context(), connect.NewRequest(&walletportalv1.AcceptRequest{
			OfferId: found.GetOfferId(), Pin: pin,
		})); err != nil {
			return p.problem(w, r, msg.T("holder.home.claim.label"), msg.T("holder.claim.problem.title"), message(err))
		}
		http.Redirect(w, r, p.opts.Prefix+"/", http.StatusSeeOther)
		return nil
	case walletportalv1.Detected_KIND_PRESENTATION_REQUEST:
		http.Redirect(w, r, p.opts.Prefix+"/present?id="+url.QueryEscape(found.GetPresentationId()), http.StatusSeeOther)
		return nil
	case walletportalv1.Detected_KIND_CREDENTIAL:
		http.Redirect(w, r, p.opts.Prefix+"/", http.StatusSeeOther)
		return nil
	}
	return p.renderClaim(w, r, text, found.GetError().GetMessage())
}

// scan reads a pasted text and shows the next step: the offer page, the
// consent page, or the wallet.
func (p *Portal) scan(w http.ResponseWriter, r *http.Request) error {
	if _, ok := p.writer(w, r); !ok {
		return nil
	}
	text := r.PostFormValue("text")
	resp, err := p.opts.Service.Paste(r.Context(), connect.NewRequest(&walletportalv1.PasteRequest{Text: text}))
	if err != nil {
		return p.renderClaim(w, r, text, msg.T("holder.claim.unread"))
	}
	found := resp.Msg.GetDetected()
	switch found.GetKind() {
	case walletportalv1.Detected_KIND_CREDENTIAL_OFFER:
		return p.offerPage(w, r, found.GetOfferId(), found.GetOffer().GetNeedsPin(), found.GetOffer().GetIssuerName())
	case walletportalv1.Detected_KIND_PRESENTATION_REQUEST:
		http.Redirect(w, r, p.opts.Prefix+"/present?id="+url.QueryEscape(found.GetPresentationId()), http.StatusSeeOther)
		return nil
	case walletportalv1.Detected_KIND_CREDENTIAL:
		http.Redirect(w, r, p.opts.Prefix+"/", http.StatusSeeOther)
		return nil
	}
	return p.renderClaim(w, r, text, found.GetError().GetMessage())
}

// scanRead answers the camera scanner with a fragment: the offer card,
// or a sentence. A request or a credential sends the browser on through
// HX-Redirect.
func (p *Portal) scanRead(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxScanBytes)
	if _, ok := p.writer(w, r); !ok {
		return nil
	}
	b := p.pen(r)
	say := func(text string) error {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, err := w.Write([]byte(`<p class="error">` + template.HTMLEscapeString(text) + `</p>`))
		return err
	}
	resp, err := p.opts.Service.Paste(r.Context(), connect.NewRequest(&walletportalv1.PasteRequest{Text: r.PostFormValue("payload")}))
	if err != nil {
		return say(msg.T("holder.claim.unread"))
	}
	found := resp.Msg.GetDetected()
	next := ""
	switch found.GetKind() {
	case walletportalv1.Detected_KIND_CREDENTIAL_OFFER:
		card := p.offerCard(b, found.GetOfferId(), found.GetOffer().GetNeedsPin(), found.GetOffer().GetIssuerName())
		if b.err != nil {
			return b.err
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, werr := w.Write([]byte(card))
		return werr
	case walletportalv1.Detected_KIND_PRESENTATION_REQUEST:
		next = p.opts.Prefix + "/present?id=" + url.QueryEscape(found.GetPresentationId()) + "#request"
	case walletportalv1.Detected_KIND_CREDENTIAL:
		next = p.opts.Prefix + "/"
	default:
		return say(found.GetError().GetMessage())
	}
	w.Header().Set("HX-Redirect", next)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err = w.Write([]byte(`<p><a href="` + template.HTMLEscapeString(next) + `">` +
		template.HTMLEscapeString(msg.T("holder.claim.next.label")) + `</a></p>`))
	return err
}

// offerPage renders the accept page of one offer.
func (p *Portal) offerPage(w http.ResponseWriter, r *http.Request, offerID string, needsPIN bool, issuer string) error {
	b := p.pen(r)
	card := p.offerCard(b, offerID, needsPIN, issuer)
	return p.render(w, r, b, components.Page{
		Title: msg.T("holder.offer.title.label"), Lead: msg.T("holder.offer.lead"), Description: msg.T("holder.offer.lead"),
		Content: card,
	})
}

// offerCard renders one offer: who offers it, the transaction code when
// the offer needs one, the accept button, and the decline button when
// the stack can decline an offer.
func (p *Portal) offerCard(b *pen, offerID string, needsPIN bool, issuer string) template.HTML {
	var fields []template.HTML
	if needsPIN {
		fields = append(fields, b.part("field", components.Field{
			ID: "pin", Label: msg.T("holder.claim.txcode.label"), Required: true, Hint: msg.T("holder.offer.pin.hint"),
			Autocomplete: "one-time-code", Attrs: map[string]string{"inputmode": "numeric"},
		}))
	}
	parts := []template.HTML{b.form(p.opts.Prefix+"/accept", map[string]string{"offer_id": offerID},
		components.Button{Text: msg.T("holder.offer.accept.label"), Type: "submit", Variant: "primary"}, fields...)}
	if b.frame.Has(backendv1.Feature_FEATURE_WALLET_REJECT_OFFER) {
		parts = append(parts, b.form(p.opts.Prefix+"/reject", map[string]string{"offer_id": offerID},
			components.Button{Text: msg.T("holder.offer.decline.label"), Type: "submit", Variant: "secondary"}))
	}
	text := msg.T("holder.offer.anon")
	if issuer != "" {
		text = msg.T("holder.offer.from", issuer)
	}
	return b.part("card", components.Card{
		ID: "offer-card", Title: msg.T("holder.offer.card.label"), Text: text, Body: components.Join(parts...),
	})
}

// accept accepts a pending offer.
func (p *Portal) accept(w http.ResponseWriter, r *http.Request) error {
	if _, ok := p.writer(w, r); !ok {
		return nil
	}
	_, err := p.opts.Service.Accept(r.Context(), connect.NewRequest(&walletportalv1.AcceptRequest{
		OfferId: r.PostFormValue("offer_id"), Pin: r.PostFormValue("pin"),
	}))
	if err != nil {
		return p.problem(w, r, msg.T("holder.offer.title.label"), msg.T("holder.claim.problem.title"), message(err))
	}
	http.Redirect(w, r, p.opts.Prefix+"/", http.StatusSeeOther)
	return nil
}

// reject declines a pending offer. It exists only when the adapter of
// the own pair lists FEATURE_WALLET_REJECT_OFFER (ADR-034 decision 5).
func (p *Portal) reject(w http.ResponseWriter, r *http.Request) error {
	if !p.pen(r).frame.Has(backendv1.Feature_FEATURE_WALLET_REJECT_OFFER) {
		http.NotFound(w, r)
		return nil
	}
	if _, ok := p.writer(w, r); !ok {
		return nil
	}
	if _, err := p.opts.Service.Reject(r.Context(), connect.NewRequest(&walletportalv1.RejectRequest{
		OfferId: r.PostFormValue("offer_id"),
	})); err != nil {
		return p.problem(w, r, msg.T("holder.offer.title.label"), msg.T("holder.offer.decline.problem"), message(err))
	}
	http.Redirect(w, r, p.opts.Prefix+"/", http.StatusSeeOther)
	return nil
}
