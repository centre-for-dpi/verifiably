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
//	GET  /claim           the claim page: a code or a QR, or a sign in (spec HO3)
//	POST /claim           start the sign in at the issuer (decision 3)
//	GET  /claim/callback  the answer of the issuer after the sign in
//	POST /claim/offer     claim a pasted offer with its transaction code
//	GET  /claimable       moved to /claim
//	GET  /scan            moved to /claim
//	POST /scan            read a scanned or pasted text
//	POST /scan/read       read the text of the camera scanner, as a fragment
//	GET  /static/{file}   the camera scanner and the QR reader
//	POST /accept          accept a pending offer
//	POST /reject          decline a pending offer, when the stack can
//	POST /delete     remove one credential
//	GET  /pin        set or enter the PIN of the stack wallet (P6-I7c)
//	POST /pin        pass the PIN to the stack wallet
//	GET  /present          the intake and the request card (spec HO4, decision 5)
//	POST /present          share the selected claims
//	POST /present/read     open a pasted request link
//	POST /present/upload   open an uploaded request file
//	POST /present/decline  refuse the request
//	GET  /wallet.js  the browser script (decision 4)
//
// Every POST carries a synchronizer token. Every page passes the
// accessibility checks of ui/a11ytest.
package portal

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"

	"connectrpc.com/connect"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/qrscan"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/cards"
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
	mux.HandleFunc("POST "+p.opts.Prefix+"/keys/key", p.handle(p.createKey))
	mux.HandleFunc("POST "+p.opts.Prefix+"/keys/did", p.handle(p.createDid))
	mux.HandleFunc("POST "+p.opts.Prefix+"/keys/default", p.handle(p.defaultDid))
	mux.HandleFunc("POST "+p.opts.Prefix+"/signout", p.signOut)
	mux.HandleFunc("GET "+p.opts.Prefix+"/discover", p.handle(p.discover))
	mux.HandleFunc("GET "+p.opts.Prefix+"/claim", p.handle(p.claimPage))
	mux.HandleFunc("POST "+p.opts.Prefix+"/claim", p.handle(p.claim))
	mux.HandleFunc("GET "+p.opts.Prefix+"/claim/callback", p.handle(p.callback))
	mux.HandleFunc("POST "+p.opts.Prefix+"/claim/offer", p.handle(p.claimOffer))
	mux.HandleFunc("GET "+p.opts.Prefix+"/claimable", p.moved("/claim"))
	mux.HandleFunc("GET "+p.opts.Prefix+"/scan", p.moved("/claim"))
	mux.HandleFunc("POST "+p.opts.Prefix+"/scan", p.handle(p.scan))
	mux.HandleFunc("POST "+p.opts.Prefix+"/scan/read", p.handle(p.scanRead))
	mux.Handle("GET "+p.opts.Prefix+"/static/", http.StripPrefix(p.opts.Prefix+"/static/", qrscan.Handler()))
	mux.HandleFunc("POST "+p.opts.Prefix+"/accept", p.handle(p.accept))
	mux.HandleFunc("POST "+p.opts.Prefix+"/reject", p.handle(p.reject))
	mux.HandleFunc("POST "+p.opts.Prefix+"/delete", p.handle(p.remove))
	mux.HandleFunc("GET "+p.opts.Prefix+"/document", p.handle(p.document))
	mux.HandleFunc("GET "+p.opts.Prefix+"/pin", p.handle(p.pinPage))
	mux.HandleFunc("POST "+p.opts.Prefix+"/pin", p.handle(p.pinSubmit))
	mux.HandleFunc("GET "+p.opts.Prefix+"/present", p.handle(p.presentPage))
	mux.HandleFunc("POST "+p.opts.Prefix+"/present", p.handle(p.submit))
	mux.HandleFunc("POST "+p.opts.Prefix+"/present/read", p.handle(p.presentRead))
	mux.HandleFunc("POST "+p.opts.Prefix+"/present/upload", p.handle(p.presentUpload))
	mux.HandleFunc("POST "+p.opts.Prefix+"/present/decline", p.handle(p.decline))
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
	title := "This wallet keeps your credentials in your browser"
	text := "This deployment has no wallet server. Your browser encrypts each credential " +
		"with a key only it holds."
	if p.hybrid(b) {
		title, text = msg.T("holder.browser.hybrid.title"), msg.T("holder.browser.hybrid.text")
	}
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
		Title: title,
		Text:  text,
		Body:  components.Join(file, paste, save, token, status),
	})
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

// valueText returns the value of a claim, or a sentence when the wallet
// holds no value.
func valueText(value string) string {
	if strings.TrimSpace(value) == "" {
		return "no value in your wallet"
	}
	return value
}
