// SPDX-License-Identifier: Apache-2.0

// Package portal renders the citizen pages of the wallet with the vca
// UI kit (ADR-021, ADR-027).
//
// Every page sits in the holder frame of board Holder-Portal: the role
// chip, the stack switcher of the holder pairs that run, the user menu
// of the wallet session, and the side navigation of internal/rolenav.
//
// The pages, under the configured prefix:
//
//	GET  /           the credentials of the citizen, with trust and status
//	GET  /help       what each wallet page does
//	GET  /keys       the holder identifier and key, when the stack manages keys
//	POST /signout    end the wallet session
//	GET  /discover   the credentials issuers publish (decision 1)
//	GET  /claimable  the credentials the citizen can get (decision 2)
//	POST /claim      start one claim (decision 3)
//	GET  /scan       the scan, paste, and file form (decision 3)
//	POST /scan       read a scanned or pasted text
//	POST /accept     accept a pending offer
//	POST /reject     discard a pending offer
//	POST /delete     remove one credential
//	GET  /present    the consent screen (decision 5)
//	POST /present    send the presentation
//	GET  /wallet.js  the browser script (decision 4)
//
// Every POST carries a synchronizer token. Every page passes the
// accessibility checks of ui/a11ytest.
package portal

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"connectrpc.com/connect"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/cards"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/present"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/session"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/static"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// DefaultPrefix is the URL prefix of the citizen pages.
const DefaultPrefix = "/wallet"

// Options configure the portal.
type Options struct {
	// Service answers the RPCs. It is required.
	Service *service.Service
	// Kit renders the components. Nil builds a new kit.
	Kit *components.Kit
	// Guard makes and checks the synchronizer tokens. It is required.
	Guard session.Guard
	// Prefix is the URL prefix of the pages.
	Prefix string
	// LoginPath is the page a citizen with no session goes to.
	LoginPath string
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
	// Topology places the wallet among the pairs of the deployment. The
	// zero value draws the frame with no stack switcher and no gated page.
	Topology Topology
}

// Topology is what the frame knows about the pairs of the deployment.
type Topology struct {
	// Peers are the candidate pairs, from VCA_PEERS.
	Peers []topology.Peer
	// Snapshot returns the probe of every peer. Nil means no stack
	// switcher and no gated page.
	Snapshot func(ctx context.Context) topology.Snapshot
	// JWKSURL is the key set of the wallet authentication service. The
	// holder pair whose wallet-auth serves it is the own pair.
	JWKSURL string
	// Logout ends a session at the wallet-auth service of authURL and
	// returns the logout URL of the provider, or "". Nil only clears the
	// cookie.
	Logout func(ctx context.Context, authURL, token string) (string, error)
	// SecureCookie sets the Secure attribute of the cookie that clears
	// the session.
	SecureCookie bool
}

// Portal serves the pages.
type Portal struct {
	opts   Options
	kit    *components.Kit
	script http.Handler
	shell  *staffshell.Shell
}

// New builds the portal.
func New(opts Options) (*Portal, error) {
	if opts.Service == nil {
		return nil, errors.New("portal: a wallet portal service is required")
	}
	if opts.Kit == nil {
		kit, err := components.New()
		if err != nil {
			return nil, err
		}
		opts.Kit = kit
	}
	opts.Prefix = "/" + strings.Trim(opts.Prefix, "/")
	if opts.Prefix == "/" {
		opts.Prefix = DefaultPrefix
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	script, err := static.Handler()
	if err != nil {
		return nil, err
	}
	p := &Portal{opts: opts, kit: opts.Kit, script: script}
	p.shell = staffshell.New(staffshell.Options{
		Role: commonv1.Role_ROLE_HOLDER, Peers: opts.Topology.Peers, Snapshot: opts.Topology.Snapshot,
		JWKSURL: opts.Topology.JWKSURL, Home: opts.Prefix + "/", SignOut: opts.Prefix + "/signout",
		User: p.user,
	})
	return p, nil
}

// Prefix returns the URL prefix of the pages.
func (p *Portal) Prefix() string { return p.opts.Prefix }

// Script returns the handler of the browser script. The caller serves
// it outside the session middleware, because the page loads it before
// the citizen logs in.
func (p *Portal) Script() http.Handler { return p.script }

// Register adds every page to mux.
func (p *Portal) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+p.opts.Prefix+"/{$}", p.handle(p.mine))
	mux.HandleFunc("GET "+p.opts.Prefix+"/help", p.handle(p.help))
	mux.HandleFunc("GET "+p.opts.Prefix+"/keys", p.handle(p.keys))
	mux.HandleFunc("POST "+p.opts.Prefix+"/signout", p.signOut)
	mux.HandleFunc("GET "+p.opts.Prefix+"/discover", p.handle(p.discover))
	mux.HandleFunc("GET "+p.opts.Prefix+"/claimable", p.handle(p.claimable))
	mux.HandleFunc("GET "+p.opts.Prefix+"/claim", p.handle(p.scanForm))
	mux.HandleFunc("POST "+p.opts.Prefix+"/claim", p.handle(p.claim))
	mux.HandleFunc("GET "+p.opts.Prefix+"/scan", p.handle(p.scanForm))
	mux.HandleFunc("POST "+p.opts.Prefix+"/scan", p.handle(p.scan))
	mux.HandleFunc("POST "+p.opts.Prefix+"/accept", p.handle(p.accept))
	mux.HandleFunc("POST "+p.opts.Prefix+"/reject", p.handle(p.reject))
	mux.HandleFunc("POST "+p.opts.Prefix+"/delete", p.handle(p.remove))
	mux.HandleFunc("GET "+p.opts.Prefix+"/present", p.handle(p.consent))
	mux.HandleFunc("POST "+p.opts.Prefix+"/present", p.handle(p.submit))
}

// handle answers with one sentence when a page fails.
func (p *Portal) handle(fn func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := fn(w, r); err != nil {
			http.Error(w, "the page could not render", http.StatusInternalServerError)
		}
	}
}

// pen builds the markup of one page. It keeps the first render error,
// so a page builds its parts without an error check on every line.
type pen struct {
	kit   *components.Kit
	guard session.Guard
	who   session.Citizen
	frame staffshell.Frame
	err   error
}

// pen returns a pen for one request. It reads the probe of the peers
// once, for the frame and the feature gates of the page.
func (p *Portal) pen(r *http.Request) *pen {
	who, _ := session.From(r.Context())
	return &pen{kit: p.kit, guard: p.opts.Guard, who: who, frame: p.shell.Frame(r.Context())}
}

// part renders one component. It returns empty markup after an error.
func (b *pen) part(name string, data any) template.HTML {
	if b.err != nil {
		return ""
	}
	out, err := b.kit.HTML(name, data)
	if err != nil {
		b.err = err
	}
	return out
}

// raw returns markup the caller escaped itself.
func (b *pen) raw(markup string) template.HTML {
	return template.HTML(markup) //nolint:gosec // the caller escapes every value
}

// hidden returns one hidden input.
func (b *pen) hidden(name, value string) template.HTML {
	return b.raw(`<input type="hidden" name="` + template.HTMLEscapeString(name) +
		`" value="` + template.HTMLEscapeString(value) + `">`)
}

// form renders one POST form with the synchronizer token, the hidden
// values, the extra parts, and one submit button.
func (b *pen) form(action string, values map[string]string, submit components.Button,
	extra ...template.HTML,
) template.HTML {
	parts := []template.HTML{b.hidden(session.Field, b.guard.Token(b.who))}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		parts = append(parts, b.hidden(name, values[name]))
	}
	parts = append(parts, extra...)
	parts = append(parts, b.part("button", submit))
	return b.raw(`<form method="post" action="`+template.HTMLEscapeString(action)+`">`) +
		components.Join(parts...) + b.raw(`</form>`)
}

// render writes one page, or returns the render error of the pen.
func (p *Portal) render(w http.ResponseWriter, r *http.Request, b *pen, page components.Page) error {
	if b.err != nil {
		return b.err
	}
	return p.shell.Render(p.kit, w, r, b.frame, page)
}

// claimTable returns the claim table of a card.
func claimTable(id string, card *walletportalv1.Card) components.Table {
	table := components.Table{
		ID: id + "-claims", Caption: "What this credential says",
		Columns: []string{"Field", "Value"},
		Empty:   "This credential shows no field",
	}
	for _, name := range cards.ClaimNames(card) {
		table.Rows = append(table.Rows, components.Row{{Text: name}, {Text: card.GetClaims()[name]}})
	}
	return table
}

// browserCard renders the file upload and the paste box of browser
// storage (ADR-021 decision 4).
func (p *Portal) browserCard(b *pen) template.HTML {
	file := b.part("field", components.Field{
		ID: "wallet-file", Label: "Load a credential from a file", Type: "file",
		Hint: "Your browser encrypts the file before it leaves the page.",
	})
	paste := b.part("field", components.Field{
		ID: "wallet-paste", Label: "Or paste the credential text", Type: "textarea",
		Hint: "Your browser encrypts the text before it leaves the page.",
	})
	save := b.raw(`<button type="button" id="wallet-paste-save" class="btn primary">` +
		`Keep it in my browser</button>`)
	token := b.hidden(session.Field, b.guard.Token(b.who))
	status := b.raw(`<p id="wallet-status" role="status"></p>` +
		`<script src="` + template.HTMLEscapeString(p.opts.Prefix+static.Path) + `" defer></script>`)
	return b.part("card", components.Card{
		ID:    "browser-storage",
		Title: "This wallet keeps your credentials in your browser",
		Text: "This deployment has no wallet server. Your browser encrypts each credential " +
			"with a key only it holds.",
		Body: components.Join(file, paste, save, token, status),
	})
}

// claimable renders the credentials the citizen can get (decision 2).
func (p *Portal) claimable(w http.ResponseWriter, r *http.Request) error {
	b := p.pen(r)
	resp, err := p.opts.Service.ListClaimable(r.Context(),
		connect.NewRequest(&walletportalv1.ListClaimableRequest{}))
	if err != nil {
		return p.problem(w, r, "What I can get",
			"The check is not available", "Try again in a few minutes.")
	}
	table := components.Table{
		ID: "claimable", Caption: "The credentials you can get now",
		Columns: []string{"Credential", "Issuer", "Can I get it", "Action"},
		Empty:   "No issuer offers you a credential now",
	}
	for _, item := range resp.Msg.GetItems() {
		answer := b.part("badge", components.Badge{
			Text: yesNo(item.GetEligible()), Status: okBad(item.GetEligible()),
		})
		action := template.HTML("")
		if item.GetEligible() {
			action = b.form(p.opts.Prefix+"/claim", map[string]string{
				"credential_issuer": item.GetOffering().GetCredentialIssuer(),
				"schema_id":         item.GetOffering().GetSchema().GetId(),
			}, components.Button{Text: "Get it", Type: "submit", Variant: "primary"})
		}
		table.Rows = append(table.Rows, components.Row{
			{Text: title(item.GetOffering())}, {Text: issuerName(item.GetOffering())},
			{HTML: answer}, {HTML: action},
		})
	}
	return p.render(w, r, b, components.Page{
		Title:       "What I can get",
		Description: "The credentials the issuers say you can get.",
		Content:     b.part("table", table),
	})
}

// claim starts one claim (decision 3).
func (p *Portal) claim(w http.ResponseWriter, r *http.Request) error {
	if _, ok := p.writer(w, r); !ok {
		return nil
	}
	resp, err := p.opts.Service.Claim(r.Context(), connect.NewRequest(&walletportalv1.ClaimRequest{
		CredentialIssuer: r.PostFormValue("credential_issuer"),
		SchemaId:         r.PostFormValue("schema_id"),
	}))
	if err != nil {
		return p.problem(w, r, "What I can get",
			"The issuer did not give the credential", "Try again in a few minutes.")
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

// scanForm renders the scan, paste, and file form (decision 3).
func (p *Portal) scanForm(w http.ResponseWriter, r *http.Request) error {
	return p.renderScan(w, r, "")
}

// renderScan renders the scan page with an optional problem sentence.
func (p *Portal) renderScan(w http.ResponseWriter, r *http.Request, problem string) error {
	b := p.pen(r)
	field := b.part("field", components.Field{
		ID: "text", Label: "The text of the code", Type: "textarea", Required: true,
		Hint:  "Paste the text of a QR code, an offer, or a credential.",
		Error: problem,
	})
	read := b.form(p.opts.Prefix+"/scan", nil,
		components.Button{Text: "Read it", Type: "submit", Variant: "primary"}, field)
	card := b.part("card", components.Card{
		ID: "scan", Title: "Scan or paste a code",
		Text: "Your camera app reads the QR code. Paste the text it shows here.",
		Body: read,
	})
	return p.render(w, r, b, components.Page{
		Title:       "Scan a code",
		Description: "Read a credential offer or a request from a QR code.",
		Content:     card,
	})
}

// scan reads a pasted text and shows the next step.
func (p *Portal) scan(w http.ResponseWriter, r *http.Request) error {
	if _, ok := p.writer(w, r); !ok {
		return nil
	}
	resp, err := p.opts.Service.Paste(r.Context(), connect.NewRequest(&walletportalv1.PasteRequest{
		Text: r.PostFormValue("text"),
	}))
	if err != nil {
		return p.renderScan(w, r, "The wallet could not read that text. Try again.")
	}
	found := resp.Msg.GetDetected()
	switch found.GetKind() {
	case walletportalv1.Detected_KIND_CREDENTIAL_OFFER:
		return p.offerPage(w, r, found.GetOfferId(), found.GetOffer().GetNeedsPin(),
			found.GetOffer().GetIssuerName())
	case walletportalv1.Detected_KIND_PRESENTATION_REQUEST:
		http.Redirect(w, r, p.opts.Prefix+"/present?id="+url.QueryEscape(found.GetPresentationId()),
			http.StatusSeeOther)
		return nil
	case walletportalv1.Detected_KIND_CREDENTIAL:
		http.Redirect(w, r, p.opts.Prefix+"/", http.StatusSeeOther)
		return nil
	}
	return p.renderScan(w, r, found.GetError().GetMessage())
}

// offerPage renders the accept and reject page of one offer.
func (p *Portal) offerPage(w http.ResponseWriter, r *http.Request,
	offerID string, needsPIN bool, issuer string,
) error {
	b := p.pen(r)
	var fields []template.HTML
	if needsPIN {
		fields = append(fields, b.part("field", components.Field{
			ID: "pin", Label: "The code the issuer gave you", Required: true,
			Hint: "The issuer sent this code to you by another way.",
		}))
	}
	accept := b.form(p.opts.Prefix+"/accept", map[string]string{"offer_id": offerID},
		components.Button{Text: "Add it to my wallet", Type: "submit", Variant: "primary"}, fields...)
	reject := b.form(p.opts.Prefix+"/reject", map[string]string{"offer_id": offerID},
		components.Button{Text: "No thank you", Type: "submit", Variant: "secondary"})
	text := "Read the issuer name before you accept."
	if issuer != "" {
		text = issuer + " offers you a credential. Read the name before you accept."
	}
	card := b.part("card", components.Card{
		ID: "offer", Title: "An issuer offers you a credential", Text: text,
		Body: components.Join(accept, reject),
	})
	return p.render(w, r, b, components.Page{
		Title:       "An offer for you",
		Description: "Accept or refuse the credential an issuer offers.",
		Content:     card,
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
		return p.problem(w, r, "An offer for you",
			"The wallet did not take the credential", message(err))
	}
	http.Redirect(w, r, p.opts.Prefix+"/", http.StatusSeeOther)
	return nil
}

// reject discards a pending offer.
func (p *Portal) reject(w http.ResponseWriter, r *http.Request) error {
	if _, ok := p.writer(w, r); !ok {
		return nil
	}
	if _, err := p.opts.Service.Reject(r.Context(), connect.NewRequest(&walletportalv1.RejectRequest{
		OfferId: r.PostFormValue("offer_id"),
	})); err != nil {
		return p.problem(w, r, "An offer for you",
			"The wallet could not refuse the offer", message(err))
	}
	http.Redirect(w, r, p.opts.Prefix+"/", http.StatusSeeOther)
	return nil
}

// remove deletes one credential.
func (p *Portal) remove(w http.ResponseWriter, r *http.Request) error {
	if _, ok := p.writer(w, r); !ok {
		return nil
	}
	if _, err := p.opts.Service.Delete(r.Context(), connect.NewRequest(&walletportalv1.DeleteRequest{
		Id: r.PostFormValue("id"),
	})); err != nil {
		return p.problem(w, r, "My credentials",
			"The wallet did not remove the credential", message(err))
	}
	http.Redirect(w, r, p.opts.Prefix+"/", http.StatusSeeOther)
	return nil
}

// consent renders the consent screen of a presentation request
// (decision 5).
func (p *Portal) consent(w http.ResponseWriter, r *http.Request) error {
	b := p.pen(r)
	resp, err := p.opts.Service.PresentStart(r.Context(),
		connect.NewRequest(&walletportalv1.PresentStartRequest{
			PresentationId: r.URL.Query().Get("id"),
		}))
	if err != nil {
		return p.problem(w, r, "A request for your credential",
			"The wallet could not read the request", message(err))
	}
	msg := resp.Msg
	parts := []template.HTML{b.part("badge", components.Badge{
		Text:   "Who asks: " + verifierName(msg) + ", " + cards.TrustWord(msg.GetTrust()),
		Status: cards.TrustStatus(msg.GetTrust()),
	})}
	if msg.GetPurpose() != "" {
		parts = append(parts, b.raw("<p>Why: "+template.HTMLEscapeString(msg.GetPurpose())+"</p>"))
	}
	var fields []template.HTML
	for i, entry := range msg.GetRequested() {
		fields = append(fields, p.requested(b, i, entry))
	}
	parts = append(parts, b.form(p.opts.Prefix+"/present",
		map[string]string{"id": msg.GetPresentationId()},
		components.Button{Text: "Send these fields", Type: "submit", Variant: "primary"}, fields...))
	card := b.part("card", components.Card{
		ID: "consent", Title: "A verifier asks for your credential",
		Text: present.Summary(msg.GetRequested()) + " Read every field before you agree.",
		Body: components.Join(parts...),
	})
	return p.render(w, r, b, components.Page{
		Title:       "A request for your credential",
		Description: "Read every field the verifier asks for, then agree or leave.",
		Content:     card,
	})
}

// requested renders one requested credential with its claim list.
func (p *Portal) requested(b *pen, index int,
	entry *walletportalv1.PresentStartResponse_RequestedCredential,
) template.HTML {
	id := fmt.Sprintf("query-%d", index)
	options := make([]components.Option, 0, len(entry.GetMatches()))
	for i, match := range entry.GetMatches() {
		options = append(options, components.Option{
			Value: match.GetId(), Text: match.GetTitle(), Selected: i == 0,
		})
	}
	choose := b.part("field", components.Field{
		ID: id, Label: "The credential to show for " + word(entry.GetType()), Type: "select",
		Name: "card." + entry.GetQueryId(), Options: options,
		Hint: "Choose the credential you want to show.",
	})
	table := components.Table{
		ID: id + "-claims", Caption: "The fields the verifier reads",
		Columns: []string{"Field", "Value the verifier reads"},
		Empty:   "The verifier asks for no field",
	}
	paths := make([]string, 0, len(entry.GetClaims()))
	for _, claim := range entry.GetClaims() {
		table.Rows = append(table.Rows, components.Row{
			{Text: claim.GetPath()}, {Text: valueText(claim.GetValue())},
		})
		paths = append(paths, claim.GetPath())
	}
	return components.Join(choose, b.part("table", table),
		b.hidden("claims."+entry.GetQueryId(), strings.Join(paths, ",")))
}

// submit sends the presentation the citizen agreed to.
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
		case strings.HasPrefix(name, "claims."):
			req.Disclosed[strings.TrimPrefix(name, "claims.")] =
				&walletportalv1.PresentConfirmRequest_ClaimPaths{Paths: splitList(values[0])}
		}
	}
	resp, err := p.opts.Service.PresentConfirm(r.Context(), connect.NewRequest(req))
	if err != nil {
		return p.problem(w, r, "A request for your credential",
			"The wallet did not send the credential", message(err))
	}
	if uri := resp.Msg.GetRedirectUri(); uri != "" && resp.Msg.GetAccepted() {
		http.Redirect(w, r, uri, http.StatusSeeOther)
		return nil
	}
	return p.outcome(w, r, resp.Msg)
}

// outcome renders the result of a presentation.
func (p *Portal) outcome(w http.ResponseWriter, r *http.Request,
	msg *walletportalv1.PresentConfirmResponse,
) error {
	b := p.pen(r)
	status := "bad"
	if msg.GetAccepted() {
		status = "ok"
	}
	badge := b.part("badge", components.Badge{Text: yesNoSent(msg.GetAccepted()), Status: status})
	back := b.part("button", components.Button{
		Text: "Back to my credentials", Href: p.opts.Prefix + "/",
	})
	card := b.part("card", components.Card{
		ID: "outcome", Title: "The result of your answer", Text: msg.GetMessage(),
		Body: components.Join(badge, back),
	})
	return p.render(w, r, b, components.Page{
		Title:       "The result of your answer",
		Description: "What the verifier said about your credential.",
		Content:     card,
	})
}

// problem renders one page that names a problem and the next step.
func (p *Portal) problem(w http.ResponseWriter, r *http.Request, name, heading, next string) error {
	b := p.pen(r)
	card := b.part("card", components.Card{ID: "problem", Title: heading, Text: next})
	return p.render(w, r, b, components.Page{
		Title:       name,
		Description: "The wallet met a problem.",
		Content:     card,
	})
}

// writer returns the citizen of a POST. It answers the request itself
// when the session or the token is missing.
func (p *Portal) writer(w http.ResponseWriter, r *http.Request) (session.Citizen, bool) {
	citizen, ok := session.From(r.Context())
	if !ok {
		if p.opts.LoginPath != "" {
			http.Redirect(w, r, p.opts.LoginPath, http.StatusSeeOther)
			return session.Citizen{}, false
		}
		http.Error(w, "log in first", http.StatusUnauthorized)
		return session.Citizen{}, false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "the form could not be read", http.StatusBadRequest)
		return session.Citizen{}, false
	}
	if err := p.opts.Guard.Check(r, citizen); err != nil {
		http.Error(w, "the page token is not valid, load the page again", http.StatusForbidden)
		return session.Citizen{}, false
	}
	return citizen, true
}

// message returns the sentence of a Connect error, without the code.
func message(err error) string {
	var cerr *connect.Error
	if errors.As(err, &cerr) && cerr.Message() != "" {
		return upperFirst(cerr.Message()) + "."
	}
	return "Try again in a few minutes."
}

// upperFirst returns text with an upper case first letter.
func upperFirst(text string) string {
	if text == "" {
		return text
	}
	return strings.ToUpper(text[:1]) + text[1:]
}

// title returns the credential name of one offering.
func title(o *walletportalv1.Offering) string {
	for _, d := range o.GetSchema().GetDisplay() {
		if d.GetName() != "" {
			return d.GetName()
		}
	}
	if t := o.GetSchema().GetType(); t != "" {
		return t
	}
	return "A credential"
}

// issuerName returns the issuer name of one offering.
func issuerName(o *walletportalv1.Offering) string {
	if o.GetIssuerName() != "" {
		return o.GetIssuerName()
	}
	return o.GetCredentialIssuer()
}

// verifierName returns the verifier name of a consent screen.
func verifierName(msg *walletportalv1.PresentStartResponse) string {
	if msg.GetVerifierName() != "" {
		return msg.GetVerifierName()
	}
	if msg.GetVerifier() != "" {
		return msg.GetVerifier()
	}
	return "an unnamed verifier"
}

// word returns a credential type name for a label.
func word(credentialType string) string {
	if credentialType == "" {
		return "this request"
	}
	return credentialType
}

// valueText returns the value of a claim, or a sentence when the wallet
// holds no value.
func valueText(value string) string {
	if strings.TrimSpace(value) == "" {
		return "no value in your wallet"
	}
	return value
}

// yesNo returns the plain answer of the eligibility check.
func yesNo(eligible bool) string {
	if eligible {
		return "yes"
	}
	return "not now"
}

// yesNoSent returns the plain outcome of a presentation.
func yesNoSent(accepted bool) string {
	if accepted {
		return "sent"
	}
	return "not sent"
}

// okBad maps a yes or no answer to a badge status.
func okBad(ok bool) string {
	if ok {
		return "ok"
	}
	return "warn"
}

// splitList splits a comma separated list and drops empty items.
func splitList(raw string) []string {
	var out []string
	for _, item := range strings.Split(raw, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}
