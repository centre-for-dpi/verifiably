// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"

	"connectrpc.com/connect"

	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/present"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/session"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// maxRequestFileBytes caps one uploaded request file.
const maxRequestFileBytes = 64 << 10

// presentPage renders board Holder-Present: the three ways in, and the
// request card when the page names a request (spec HO4, decision 5).
func (p *Portal) presentPage(w http.ResponseWriter, r *http.Request) error {
	id := r.URL.Query().Get("id")
	if id == "" {
		return p.renderPresent(w, r, "", "", nil)
	}
	resp, err := p.opts.Service.PresentStart(r.Context(), connect.NewRequest(&walletportalv1.PresentStartRequest{PresentationId: id}))
	if err != nil {
		return p.problem(w, r, msg.T("holder.nav.present.label"), msg.T("holder.present.unread.title"), message(err))
	}
	return p.renderPresent(w, r, "", "", resp.Msg)
}

// renderPresent renders the present page with the pasted link and a
// problem sentence, and the request card of start when it has one.
func (p *Portal) renderPresent(w http.ResponseWriter, r *http.Request, text, problem string,
	start *walletportalv1.PresentStartResponse,
) error {
	b := p.pen(r)
	parts := []template.HTML{p.intake(b, text, problem)}
	if start != nil {
		parts = append(parts, p.requestCard(b, start))
	}
	return p.render(w, r, b, components.Page{
		Title: msg.T("holder.nav.present.label"), Lead: msg.T("holder.present.lead"), Description: msg.T("holder.present.lead"),
		Content: components.Join(parts...),
	})
}

// intake renders the three ways in: the camera, a pasted link, a file.
func (p *Portal) intake(b *pen, text, problem string) template.HTML {
	esc := template.HTMLEscapeString
	scan := b.part("card", components.Card{
		ID: "present-scan", Title: msg.T("holder.present.scan.label"), Text: msg.T("holder.present.scan.text"),
		Body: b.raw(`<div class="form-actions"><button type="button" id="scan-start" class="btn btn-secondary">`+
			esc(msg.T("holder.claim.scan.label"))+`</button></div>`) + p.scanner(b),
	})
	link := b.part("field", components.Field{
		ID: "request-link", Name: "request", Label: msg.T("holder.present.link.field.label"), Value: text, Required: true,
		Hint: msg.T("holder.present.link.hint"), Error: problem,
		Attrs: map[string]string{"placeholder": "openid4vp://", "spellcheck": "false"},
	})
	paste := b.part("card", components.Card{
		ID: "present-link", Title: msg.T("holder.present.link.label"),
		Body: b.form(p.opts.Prefix+"/present/read", nil,
			components.Button{Text: msg.T("holder.present.open.label"), Type: "submit", Variant: "primary"}, link),
	})
	file := b.part("field", components.Field{
		ID: "request-file", Name: "request_file", Label: msg.T("holder.present.file.field.label"), Type: "file", Required: true,
		Hint: msg.T("holder.present.file.hint"), Attrs: map[string]string{"accept": ".json,.jwt,.txt,application/json,text/plain"},
	})
	upload := b.part("card", components.Card{
		ID: "present-file", Title: msg.T("holder.present.file.label"),
		Body: b.raw(`<form method="post" action="`+esc(p.opts.Prefix+"/present/upload")+`" enctype="multipart/form-data">`) +
			b.hidden(session.Field, b.guard.Token(b.who)) + file +
			b.part("button", components.Button{Text: msg.T("holder.present.open.label"), Type: "submit", Variant: "primary"}) +
			b.raw(`</form>`),
	})
	return components.Join(b.raw(`<div class="split">`), scan, paste, upload, b.raw(`</div>`))
}

// requestCard renders the request of board Holder-Present: who asks and
// whether the trust list names the verifier, the purpose, the matched
// credential, and the claims. A required claim is ticked and locked, an
// optional claim is off. Decline and Share selected answer it.
func (p *Portal) requestCard(b *pen, start *walletportalv1.PresentStartResponse) template.HTML {
	esc := template.HTMLEscapeString
	checked := start.GetTrust() == trustv1.TrustLookupResponse_OUTCOME_TRUSTED
	badge := components.Badge{Text: msg.T("holder.present.unchecked.label"), Status: "warn"}
	if checked {
		badge = components.Badge{Text: msg.T("holder.present.checked.label"), Status: "ok"}
	}
	left := []template.HTML{
		b.raw(`<p class="hint">` + esc(msg.T("holder.present.from.hint.label")) + `</p><p>`),
		b.part("badge", badge), b.raw(`</p>`),
	}
	if start.GetVerifier() != "" {
		left = append(left, b.raw(`<p class="mono">`+esc(start.GetVerifier())+`</p>`))
	}
	if start.GetPurpose() != "" {
		left = append(left, b.raw(`<p>`+esc(msg.T("holder.present.purpose.label", start.GetPurpose()))+`</p>`))
	}
	var right []template.HTML
	sharable := false
	for i, entry := range start.GetRequested() {
		match, ok := p.matched(b, i, entry)
		left = append(left, match)
		sharable = sharable || ok
		right = append(right, p.asked(b, i, entry))
	}
	actions := []template.HTML{
		b.part("button", components.Button{
			Text: msg.T("holder.offer.decline.label"), Type: "submit", Variant: "secondary",
			Attrs: map[string]string{"formaction": p.opts.Prefix + "/present/decline"},
		}),
		b.part("button", components.Button{
			Text: msg.T("holder.present.share.label"), Type: "submit", Variant: "primary", Disabled: !sharable,
		}),
	}
	body := b.raw(`<form method="post" action="`+esc(p.opts.Prefix+"/present")+`">`) +
		b.hidden(session.Field, b.guard.Token(b.who)) + b.hidden("id", start.GetPresentationId()) +
		b.raw(`<div class="split"><div>`) + components.Join(left...) + b.raw(`</div><div>`) + components.Join(right...) +
		b.raw(`</div></div><div class="form-actions">`) + components.Join(actions...) + b.raw(`</div></form>`)
	text := present.Summary(start.GetRequested())
	if start.GetDuringIssuance() {
		text = msg.T("holder.present.issuer.text") + " " + text
	}
	return b.part("card", components.Card{
		ID: "request", Title: msg.T("holder.present.from.label", verifierName(start)),
		Text: text, Body: body,
	})
}

// matched renders the credential the wallet shows for one requested
// credential: one match as text, several as a choice, none as a
// sentence. The second value is false when the wallet holds no match.
func (p *Portal) matched(b *pen, index int, entry *walletportalv1.PresentStartResponse_RequestedCredential) (template.HTML, bool) {
	esc := template.HTMLEscapeString
	name := "card." + entry.GetQueryId()
	matches := entry.GetMatches()
	switch len(matches) {
	case 0:
		return b.raw(`<p class="error">` + esc(msg.T("holder.present.nomatch")) + `</p>`), false
	case 1:
		return b.hidden(name, matches[0].GetId()) + b.raw(`<p><span class="hint">`+esc(msg.T("holder.present.matched.label"))+
			`</span><br><strong>`+esc(matchName(matches[0]))+`</strong></p>`), true
	}
	options := make([]components.Option, 0, len(matches))
	for i, m := range matches {
		options = append(options, components.Option{Value: m.GetId(), Text: matchName(m), Selected: i == 0})
	}
	return b.part("field", components.Field{
		ID: fmt.Sprintf("query-%d", index), Name: name, Label: msg.T("holder.present.matched.label"), Type: "select",
		Options: options, Hint: msg.T("holder.present.pick.hint"),
	}), true
}

// asked renders the claims one requested credential asks for. A locked
// box does not travel with the form, so a hidden field carries each
// required claim.
func (p *Portal) asked(b *pen, index int, entry *walletportalv1.PresentStartResponse_RequestedCredential) template.HTML {
	name := "claim." + entry.GetQueryId()
	choice := components.Choice{
		ID: fmt.Sprintf("ask-%d", index), Name: name, Legend: msg.T("holder.present.ask.label"), Multiple: true,
	}
	var hidden []template.HTML
	for _, c := range entry.GetClaims() {
		o := components.ChoiceOption{Value: c.GetPath(), Title: c.GetPath(), Text: valueText(c.GetValue())}
		if c.GetMandatory() {
			o.Meta, o.Checked, o.Disabled = msg.T("holder.present.required.label"), true, true
			hidden = append(hidden, b.hidden(name, c.GetPath()))
		} else {
			o.Meta = msg.T("holder.present.optional")
		}
		choice.Options = append(choice.Options, o)
	}
	if len(choice.Options) == 0 {
		return b.raw(`<p>` + template.HTMLEscapeString(msg.T("holder.present.noclaim")) + `</p>`)
	}
	return components.Join(append(hidden, b.part("choice", choice))...)
}

// matchName names a matched credential with its issuer.
func matchName(card *walletportalv1.Card) string {
	issuer := card.GetIssuerName()
	if issuer == "" {
		issuer = card.GetIssuer()
	}
	if issuer == "" {
		return card.GetTitle()
	}
	return msg.T("holder.claim.option.label", card.GetTitle(), issuer)
}

// presentRead opens a pasted request link.
func (p *Portal) presentRead(w http.ResponseWriter, r *http.Request) error {
	if _, ok := p.writer(w, r); !ok {
		return nil
	}
	return p.openRequest(w, r, r.PostFormValue("request"))
}

// presentUpload opens a request file: a request link, or a request
// object as JSON or as a signed request.
func (p *Portal) presentUpload(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, 2*maxRequestFileBytes)
	if !multipartRead(r) {
		http.Error(w, "the form could not be read", http.StatusBadRequest)
		return nil
	}
	if _, ok := p.writer(w, r); !ok {
		return nil
	}
	text := ""
	if file, _, err := r.FormFile("request_file"); err == nil {
		raw, rerr := io.ReadAll(io.LimitReader(file, maxRequestFileBytes))
		if cerr := file.Close(); rerr == nil && cerr == nil {
			text = string(raw)
		}
	}
	return p.openRequest(w, r, text)
}

// multipartRead parses the upload form within the size cap.
func multipartRead(r *http.Request) bool {
	return r.ParseMultipartForm(2*maxRequestFileBytes) == nil
}

// openRequest reads a text and opens its request card, or shows the
// intake again with the reason.
func (p *Portal) openRequest(w http.ResponseWriter, r *http.Request, text string) error {
	resp, err := p.opts.Service.Paste(r.Context(), connect.NewRequest(&walletportalv1.PasteRequest{Text: text}))
	if err != nil {
		return p.renderPresent(w, r, "", msg.T("holder.claim.unread"), nil)
	}
	found := resp.Msg.GetDetected()
	if found.GetKind() != walletportalv1.Detected_KIND_PRESENTATION_REQUEST {
		return p.renderPresent(w, r, linkText(text), msg.T("holder.present.notrequest"), nil)
	}
	// The anchor brings the request card into view on a narrow screen.
	http.Redirect(w, r, p.opts.Prefix+"/present?id="+url.QueryEscape(found.GetPresentationId())+"#request", http.StatusSeeOther)
	return nil
}

// linkText keeps a short pasted text in the field, so the holder can fix
// it. A long text, such as a file, stays out.
func linkText(text string) string {
	if len(text) > 2048 || strings.ContainsAny(text, "\n{") {
		return ""
	}
	return text
}

// submit shares the claims the holder kept ticked. The service keeps a
// record of the answer.
func (p *Portal) submit(w http.ResponseWriter, r *http.Request) error {
	if _, ok := p.writer(w, r); !ok {
		return nil
	}
	req := &walletportalv1.PresentConfirmRequest{
		PresentationId: r.PostFormValue("id"),
		SelectedCards:  map[string]string{},
		Disclosed:      map[string]*walletportalv1.PresentConfirmRequest_ClaimPaths{},
	}
	for name, values := range r.PostForm {
		if len(values) == 0 {
			continue
		}
		switch {
		case strings.HasPrefix(name, "card."):
			req.SelectedCards[strings.TrimPrefix(name, "card.")] = values[0]
		case strings.HasPrefix(name, "claim."):
			req.Disclosed[strings.TrimPrefix(name, "claim.")] =
				&walletportalv1.PresentConfirmRequest_ClaimPaths{Paths: unique(values)}
		}
	}
	resp, err := p.opts.Service.PresentConfirm(r.Context(), connect.NewRequest(req))
	if err != nil {
		return p.problem(w, r, msg.T("holder.nav.present.label"), msg.T("holder.present.unsent.title"), message(err))
	}
	if uri := resp.Msg.GetRedirectUri(); uri != "" && resp.Msg.GetAccepted() {
		http.Redirect(w, r, uri, http.StatusSeeOther)
		return nil
	}
	return p.outcome(w, r, resp.Msg)
}

// unique drops repeated values and keeps the order.
func unique(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// decline refuses the request and goes home, where the refusal shows in
// the recent presentations.
func (p *Portal) decline(w http.ResponseWriter, r *http.Request) error {
	if _, ok := p.writer(w, r); !ok {
		return nil
	}
	if _, err := p.opts.Service.PresentDecline(r.Context(), connect.NewRequest(&walletportalv1.PresentDeclineRequest{
		PresentationId: r.PostFormValue("id"),
	})); err != nil {
		return p.problem(w, r, msg.T("holder.nav.present.label"), msg.T("holder.present.unread.title"), message(err))
	}
	http.Redirect(w, r, p.opts.Prefix+"/", http.StatusSeeOther)
	return nil
}

// outcome renders the answer of the verifier.
func (p *Portal) outcome(w http.ResponseWriter, r *http.Request, answer *walletportalv1.PresentConfirmResponse) error {
	b := p.pen(r)
	badge := components.Badge{Text: msg.T("holder.present.result.rejected.label"), Status: "bad"}
	if answer.GetAccepted() {
		badge = components.Badge{Text: msg.T("holder.present.result.accepted.label"), Status: "ok"}
	}
	back := b.part("button", components.Button{Text: msg.T("holder.present.back.label"), Href: p.opts.Prefix + "/"})
	title, lead := msg.T("holder.present.outcome.label"), msg.T("holder.present.outcome.lead")
	if answer.GetCard() != nil {
		title, lead = msg.T("holder.present.issued.label"), msg.T("holder.present.issued.lead")
	}
	card := b.part("card", components.Card{
		ID: "outcome", Title: title, Text: answer.GetMessage(),
		Body: components.Join(b.part("badge", badge), back),
	})
	return p.render(w, r, b, components.Page{
		Title: title, Lead: lead, Description: lead, Content: card,
	})
}

// recent renders the table of the newest presentation records.
func (p *Portal) recent(b *pen, r *http.Request) template.HTML {
	table := components.Table{
		ID: "recent", Caption: msg.T("holder.recent.caption.label"),
		Columns: []string{
			msg.T("holder.recent.when.label"), msg.T("holder.recent.verifier.label"),
			msg.T("holder.recent.shared.label"), msg.T("holder.recent.result.label"),
		},
		Empty: msg.T("holder.recent.empty"),
	}
	resp, err := p.opts.Service.ListPresentations(r.Context(), connect.NewRequest(&walletportalv1.ListPresentationsRequest{}))
	if err == nil {
		for i, rec := range resp.Msg.GetRecords() {
			if i == recentRows {
				break
			}
			status, word := resultBadge(rec.GetResult())
			verifier := rec.GetVerifierName()
			if verifier == "" {
				verifier = rec.GetVerifier()
			}
			shared := strings.Join(rec.GetClaims(), ", ")
			if rec.GetResult() == walletportalv1.PresentationRecord_RESULT_DECLINED {
				shared = msg.T("holder.recent.declined.label")
			}
			table.Rows = append(table.Rows, components.Row{
				{Text: rec.GetAt().AsTime().UTC().Format("2 Jan 2006, 15:04")}, {Text: verifier}, {Text: shared},
				{HTML: b.part("badge", components.Badge{Status: status, Text: word})},
			})
		}
	}
	return b.part("table", table)
}

// recentRows is the number of records the home page shows.
const recentRows = 5

// resultBadge returns the badge status and word of a result.
func resultBadge(result walletportalv1.PresentationRecord_Result) (string, string) {
	switch result {
	case walletportalv1.PresentationRecord_RESULT_ACCEPTED:
		return "ok", msg.T("holder.present.result.accepted.label")
	case walletportalv1.PresentationRecord_RESULT_REJECTED:
		return "bad", msg.T("holder.present.result.rejected.label")
	case walletportalv1.PresentationRecord_RESULT_DECLINED:
		return "info", msg.T("holder.present.result.declined.label")
	}
	return "warn", msg.T("holder.present.result.failed.label")
}
