// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/pdf"
	"github.com/centre-for-dpi/vc-adapters/core/qr"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/service"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// The presentation request pages of board Verifier-Request (spec VE4).
// A staff member picks a saved query and the verifier that answers it:
// the VCA verifier, or a live stack verifier whose adapter reads the
// query. The request reaches the holder as a QR code, a link, or a PDF
// document. The state block polls every 2 seconds with htmx; a refresh
// link does the same without JavaScript. When the answer arrives the
// service evaluates it with the policy set of the query and stores the
// result, and the page shows the verdict card.
//
//	GET  /requests/                    the requests, newest first
//	GET  /requests/new                 the new request form, ?template=<id> picks a query
//	POST /requests/new/answerers       the verifier choice of one query, for htmx
//	POST /requests/                    send a request
//	GET  /requests/{id}                one request, ?as=qr, link, or document
//	GET  /requests/{id}/state          the state block, for htmx
//	GET  /requests/{id}/document.pdf   the request as a PDF document
//	POST /requests/{id}/dc-api         the answer of the Digital Credentials API
//
// A stack whose adapter lists FEATURE_DC_API_VERIFY also offers the
// delivery "Digital Credentials API" (P6-W2). The page then shows a
// button that the kit script reveals when the browser has the API, and
// the QR code of the same request for every other browser.

// DefaultResultsPath is the page of one result in the results service.
const DefaultResultsPath = "/portal/results/"

// Templates reads the saved queries. The discovery client is one.
type Templates interface {
	ListTemplates(context.Context, *connect.Request[discoveryv1.ListTemplatesRequest]) (*connect.Response[discoveryv1.ListTemplatesResponse], error)
	GetTemplate(context.Context, *connect.Request[discoveryv1.GetTemplateRequest]) (*connect.Response[discoveryv1.GetTemplateResponse], error)
}

// Results reads a stored result. The results client is one.
type Results interface {
	Get(context.Context, *connect.Request[resultsv1.GetRequest]) (*connect.Response[resultsv1.GetResponse], error)
}

// The ways a request reaches the holder.
const (
	deliverQR       = "qr"
	deliverLink     = "link"
	deliverDocument = "document"
	deliverDCAPI    = "dcapi"
)

// vcaVerifier is the form value of the VCA verifier.
const vcaVerifier = "vca"

// expiries are the choices of the expiry select, in seconds.
var expiries = []int{120, 300, 900, 3600}

// requestsPath is the path of the request list.
func (p *Page) requestsPath() string { return p.opts.Prefix + "/requests/" }

// registerRequests adds the request pages to mux.
func (p *Page) registerRequests(mux *http.ServeMux) {
	base := p.requestsPath()
	mux.HandleFunc("GET "+base+"{$}", p.handle(p.requestList))
	mux.HandleFunc("GET "+base+"new", p.handle(p.newRequest))
	mux.HandleFunc("POST "+base+"new/answerers", p.handle(p.answerers))
	mux.HandleFunc("POST "+base+"{$}", p.handle(p.createRequest))
	mux.HandleFunc("GET "+base+"{id}", p.handle(p.requestPage))
	mux.HandleFunc("GET "+base+"{id}/state", p.handle(p.requestState))
	mux.HandleFunc("GET "+base+"{id}/document.pdf", p.handle(p.requestDocument))
	mux.HandleFunc("POST "+base+"{id}/dc-api", p.handle(p.submitDcAPI))
}

// scanTabs renders the tabs between the scanner, a new request, and the
// request list.
func (p *Page) scanTabs(b *blocks, current string) template.HTML {
	return b.add("tabs", components.Tabs{Label: msg.T("verifier.request.tabs.label"), Links: []components.Link{
		{Href: p.opts.Prefix + "/", Text: msg.T("verifier.request.tab.scan.label"), Current: current == "scan"},
		{Href: p.requestsPath() + "new", Text: msg.T("verifier.request.tab.new.label"), Current: current == "new"},
		{Href: p.requestsPath(), Text: msg.T("verifier.request.tab.list.label"), Current: current == "list"},
	}})
}

// clock formats a time for the pages.
func clock(t time.Time) string { return t.UTC().Format("15:04") + " UTC" }

// stacks returns the live verifier stacks.
func (p *Page) stacks(ctx context.Context) []service.Stack {
	if p.opts.Stacks == nil {
		return nil
	}
	return p.opts.Stacks(ctx)
}

// dcAPIStacks names the live stacks whose adapter takes a request of the
// Digital Credentials API.
func (p *Page) dcAPIStacks(ctx context.Context) []string {
	var out []string
	for _, st := range p.stacks(ctx) {
		if st.DcAPI() {
			out = append(out, st.Name)
		}
	}
	return out
}

// throughName names the verifier of a request.
func (p *Page) throughName(ctx context.Context, pair string) string {
	if pair == "" {
		return msg.T("verifier.request.vca.label")
	}
	for _, st := range p.stacks(ctx) {
		if st.Pair == pair {
			return st.Name
		}
	}
	return pair
}

// templateList reads the saved queries, or none without a discovery
// client.
func (p *Page) templateList(ctx context.Context) ([]*discoveryv1.PresentationTemplate, error) {
	if p.opts.Discovery == nil {
		return nil, nil
	}
	resp, err := p.opts.Discovery.ListTemplates(ctx, connect.NewRequest(&discoveryv1.ListTemplatesRequest{}))
	if err != nil {
		return nil, err
	}
	return resp.Msg.GetTemplates(), nil
}

// templateOf reads one saved query. A missing query gives a template
// that holds only the id.
func (p *Page) templateOf(ctx context.Context, id string) *discoveryv1.PresentationTemplate {
	if p.opts.Discovery != nil && id != "" {
		if resp, err := p.opts.Discovery.GetTemplate(ctx, connect.NewRequest(&discoveryv1.GetTemplateRequest{Id: id})); err == nil {
			return resp.Msg.GetTemplate()
		}
	}
	return &discoveryv1.PresentationTemplate{Id: id, DisplayName: id}
}

// kindLabel names the query language of a template.
func kindLabel(t *discoveryv1.PresentationTemplate) string {
	if t.GetKind() == discoveryv1.TemplateKind_TEMPLATE_KIND_PE {
		return "DIF PE"
	}
	return "DCQL"
}

// answererOptions lists the verifiers that can answer a template.
func (p *Page) answererOptions(ctx context.Context, t *discoveryv1.PresentationTemplate, picked string) []components.ChoiceOption {
	var out []components.ChoiceOption
	if service.VCAReads(t) {
		out = append(out, components.ChoiceOption{Value: vcaVerifier, Title: msg.T("verifier.request.vca.label"),
			Text: msg.T("verifier.request.vca.text")})
	}
	for _, st := range p.stacks(ctx) {
		dcqlText, _, ok := service.QueryFor(t, st.Protocols)
		if !ok {
			continue
		}
		text := msg.T("verifier.request.stack.pe")
		if dcqlText != "" {
			text = msg.T("verifier.request.stack.dcql")
		}
		out = append(out, components.ChoiceOption{Value: st.Pair, Title: st.Name, Text: text})
	}
	checked := false
	for i := range out {
		if out[i].Value == picked {
			out[i].Checked, checked = true, true
		}
	}
	if !checked && len(out) > 0 {
		out[0].Checked = true
	}
	return out
}

// answererChoice renders the verifier choice of one template.
func (p *Page) answererChoice(ctx context.Context, b *blocks, t *discoveryv1.PresentationTemplate, picked string) template.HTML {
	options := p.answererOptions(ctx, t, picked)
	var body template.HTML
	if len(options) == 0 {
		body = paragraph(msg.T("verifier.request.through.none"))
	} else {
		body = b.add("choice", components.Choice{ID: "through", Legend: msg.T("verifier.request.through.label"),
			Hint: msg.T("verifier.request.through.hint"), Options: options})
	}
	return template.HTML(`<div id="answerers">`) + body + template.HTML(`</div>`)
}

// paragraph renders one escaped sentence.
func paragraph(text string) template.HTML {
	return template.HTML(`<p>` + template.HTMLEscapeString(text) + `</p>`) //nolint:gosec // the text is escaped
}

// requestForm is what the new request form holds.
type requestForm struct {
	template, through, deliver string
	expires                    int
	problem                    string
}

// newRequest renders the form of a new request.
func (p *Page) newRequest(w http.ResponseWriter, r *http.Request) error {
	return p.renderForm(w, r, requestForm{template: r.URL.Query().Get("template"), deliver: deliverQR, expires: 300})
}

// renderForm renders the new request form, with a problem after a
// refused post.
func (p *Page) renderForm(w http.ResponseWriter, r *http.Request, f requestForm) error {
	list, err := p.templateList(r.Context())
	if err != nil {
		return err
	}
	b := &blocks{kit: p.opts.Kit}
	var picked *discoveryv1.PresentationTemplate
	options := make([]components.Option, 0, len(list))
	for _, t := range list {
		if picked == nil || t.GetId() == f.template {
			picked = t
		}
		options = append(options, components.Option{Value: t.GetId(), Text: t.GetDisplayName() + ", " + kindLabel(t), Selected: t.GetId() == f.template})
	}
	var body template.HTML
	if f.problem != "" {
		body = template.HTML(`<p class="error" role="alert">` + template.HTMLEscapeString(f.problem) + `</p>`) //nolint:gosec // the text is escaped
	}
	if picked == nil {
		body += b.add("empty", components.Empty{Title: msg.T("verifier.request.empty.title"), Text: msg.T("verifier.request.empty.text"),
			Action: components.Button{Text: msg.T("verifier.nav.dcql.label"), Href: "/discovery/dcql/", Variant: "primary"}})
	} else {
		esc := template.HTMLEscapeString
		delivery := make([]components.ChoiceOption, 0, 4)
		for _, d := range []string{deliverQR, deliverLink, deliverDocument} {
			delivery = append(delivery, components.ChoiceOption{Value: d, Title: msg.T("verifier.request.deliver." + d + ".label"),
				Text: msg.T("verifier.request.deliver." + d + ".text"), Checked: d == f.deliver})
		}
		// The Digital Credentials API delivery shows only when a live
		// stack adapter lists FEATURE_DC_API_VERIFY (P6-W2).
		if names := p.dcAPIStacks(r.Context()); len(names) > 0 {
			delivery = append(delivery, components.ChoiceOption{Value: deliverDCAPI, Title: msg.T("verifier.request.deliver.dcapi.label"),
				Text: msg.T("verifier.request.deliver.dcapi.text", strings.Join(names, ", ")), Checked: f.deliver == deliverDCAPI})
		}
		times := make([]components.Option, 0, len(expiries))
		for _, n := range expiries {
			times = append(times, components.Option{Value: strconv.Itoa(n), Text: msg.T("verifier.request.expires." + strconv.Itoa(n) + ".label"), Selected: n == f.expires})
		}
		fields := components.Join(
			b.add("field", components.Field{ID: "template", Label: msg.T("verifier.request.query.label"), Type: "select", Options: options,
				Hint: msg.T("verifier.request.query.hint"), Attrs: map[string]string{
					"hx-post": p.requestsPath() + "new/answerers", "hx-trigger": "change", "hx-target": "#answerers", "hx-swap": "outerHTML",
				}}),
			p.answererChoice(r.Context(), b, picked, f.through),
			b.add("choice", components.Choice{ID: "deliver", Legend: msg.T("verifier.request.deliver.label"), Options: delivery}),
			b.add("field", components.Field{ID: "expires", Label: msg.T("verifier.request.expires.label"), Type: "select", Options: times,
				Hint: msg.T("verifier.request.expires.hint")}),
			b.add("button", components.Button{Text: msg.T("verifier.request.send.label"), Type: "submit", Variant: "primary"}),
		)
		body += template.HTML(`<form method="post" action="`+esc(p.requestsPath())+`">`) + //nolint:gosec // the action is escaped
			staffsession.HiddenField(r.Context()) + fields + template.HTML(`</form>`)
	}
	card := b.add("card", components.Card{ID: "request-form", Title: msg.T("verifier.request.form.label"), Body: body})
	if b.err != nil {
		return b.err
	}
	if f.problem != "" {
		w.WriteHeader(http.StatusBadRequest)
	}
	return p.render(w, r, components.Page{
		Title: msg.T("verifier.request.title.label"), Lead: msg.T("verifier.request.lead"), Description: msg.T("verifier.request.lead"),
		Content: components.Join(p.scanTabs(b, "new"), card),
	})
}

// answerers answers the htmx post of the query select with the verifier
// choice of that query.
func (p *Page) answerers(w http.ResponseWriter, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	b := &blocks{kit: p.opts.Kit}
	out := p.answererChoice(r.Context(), b, p.templateOf(r.Context(), r.PostForm.Get("template")), "")
	if b.err != nil {
		return b.err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err := w.Write([]byte(out))
	return err
}

// createRequest sends a request and opens its page.
func (p *Page) createRequest(w http.ResponseWriter, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	f := requestForm{
		template: r.PostForm.Get("template"), through: r.PostForm.Get("through"),
		deliver: r.PostForm.Get("deliver"), expires: 300,
	}
	if n, err := strconv.Atoi(r.PostForm.Get("expires")); err == nil {
		f.expires = n
	}
	switch f.deliver {
	case deliverLink, deliverDocument, deliverDCAPI:
	default:
		f.deliver = deliverQR
	}
	stack := f.through
	if stack == vcaVerifier {
		stack = ""
	}
	resp, err := p.opts.Client.CreateOid4VpRequest(r.Context(), connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{
		TemplateId: f.template, Stack: stack, ExpiresInSeconds: int32(min(max(f.expires, 0), 3600)), //nolint:gosec // the value is clamped to one hour
		DcApi: f.deliver == deliverDCAPI,
	}))
	if err != nil {
		f.problem = msg.T("verifier.request.problem.send") + " " + connectReason(err)
		return p.renderForm(w, r, f)
	}
	http.Redirect(w, r, p.requestsPath()+url.PathEscape(resp.Msg.GetTransactionId())+"?as="+f.deliver, http.StatusSeeOther)
	return nil
}

// transaction reads one request. A missing request answers 404.
func (p *Page) transaction(w http.ResponseWriter, r *http.Request) (*ingestv1.GetTransactionResponse, bool, error) {
	resp, err := p.opts.Client.GetTransaction(r.Context(), connect.NewRequest(&ingestv1.GetTransactionRequest{TransactionId: r.PathValue("id")}))
	if connect.CodeOf(err) == connect.CodeNotFound {
		http.NotFound(w, r)
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return resp.Msg, true, nil
}

// requestPage renders one request: the query, the delivery, and the
// state block.
func (p *Page) requestPage(w http.ResponseWriter, r *http.Request) error {
	tx, ok, err := p.transaction(w, r)
	if !ok {
		return err
	}
	id := r.PathValue("id")
	as := r.URL.Query().Get("as")
	ways := []string{deliverQR, deliverLink, deliverDocument}
	if tx.GetDcApiRequest() != "" {
		ways = append(ways, deliverDCAPI)
	}
	if !slices.Contains(ways, as) {
		as = deliverQR
	}
	t := p.templateOf(r.Context(), tx.GetTemplateId())
	b := &blocks{kit: p.opts.Kit}
	through := p.throughName(r.Context(), tx.GetStack())
	summary := b.add("card", components.Card{ID: "request-query", Title: msg.T("verifier.request.query.label"),
		Text:   msg.T("verifier.request.query.text", t.GetDisplayName(), kindLabel(t), through),
		Footer: footerOf(tx)})
	links := make([]components.Link, 0, len(ways))
	for _, d := range ways {
		links = append(links, components.Link{Href: p.requestsPath() + url.PathEscape(id) + "?as=" + d,
			Text: msg.T("verifier.request.deliver." + d + ".label"), Current: d == as})
	}
	tabs := b.add("tabs", components.Tabs{Label: msg.T("verifier.request.deliver.label"), Links: links})
	delivery := template.HTML(`<div id="request-delivery">`) + p.delivery(b, tx, id, as, staffsession.HiddenField(r.Context())) + template.HTML(`</div>`)
	state := p.stateBlock(r.Context(), b, tx, id)
	if b.err != nil {
		return b.err
	}
	body := components.Join(template.HTML(`<div class="split"><div>`), tabs, delivery, template.HTML(`</div><div>`), state, template.HTML(`</div></div>`))
	if !pending(tx) {
		body = state
	}
	return p.render(w, r, components.Page{
		Title: msg.T("verifier.request.title.label"), Lead: msg.T("verifier.request.page.lead"), Description: msg.T("verifier.request.page.lead"),
		Content: components.Join(p.scanTabs(b, "list"), summary, body),
	})
}

// footerOf says when a waiting request expires, or when the answer came.
func footerOf(tx *ingestv1.GetTransactionResponse) string {
	switch {
	case pending(tx) || tx.GetState() == ingestv1.GetTransactionResponse_STATE_EXPIRED:
		return msg.T("verifier.request.expires.at", clock(tx.GetExpiresAt().AsTime()))
	case tx.GetPresentation().GetReceivedAt() != nil:
		return msg.T("verifier.request.answered.at", clock(tx.GetPresentation().GetReceivedAt().AsTime()))
	}
	return ""
}

// pending reports whether a request still waits for a wallet.
func pending(tx *ingestv1.GetTransactionResponse) bool {
	return tx.GetState() == ingestv1.GetTransactionResponse_STATE_PENDING
}

// delivery renders the request the way the holder gets it. A request
// that no longer waits shows a sentence instead. hidden holds the form
// token of the Digital Credentials API form.
func (p *Page) delivery(b *blocks, tx *ingestv1.GetTransactionResponse, id, as string, hidden template.HTML) template.HTML {
	if !pending(tx) {
		return paragraph(msg.T("verifier.request.delivery.closed"))
	}
	uri := tx.GetRequestUri()
	switch as {
	case deliverDCAPI:
		button := b.add("dcapi", components.DCAPI{Text: msg.T("verifier.request.dcapi.button.label"), Request: tx.GetDcApiRequest(),
			Action: p.requestsPath() + url.PathEscape(id) + "/dc-api", Hidden: hidden,
			Cancel: msg.T("verifier.request.dcapi.cancel"), Fail: msg.T("verifier.request.dcapi.fail")})
		return paragraph(msg.T("verifier.request.dcapi.text")) + button +
			template.HTML(`<p class="hint">`+template.HTMLEscapeString(msg.T("verifier.request.dcapi.fallback"))+`</p>`) + //nolint:gosec // the text is escaped
			p.qrBlock(b, uri)
	case deliverLink:
		return b.add("field", components.Field{ID: "request-link", Label: msg.T("verifier.request.link.label"), Value: uri,
			Hint: msg.T("verifier.request.link.hint"), Attrs: map[string]string{"readonly": "readonly", "spellcheck": "false"}}) +
			b.add("button", components.Button{Text: msg.T("verifier.request.link.open.label"), Href: uri})
	case deliverDocument:
		return paragraph(msg.T("verifier.request.document.text")) +
			b.add("button", components.Button{Text: msg.T("verifier.request.document.label"), Href: p.requestsPath() + url.PathEscape(id) + "/document.pdf", Variant: "primary"})
	}
	return p.qrBlock(b, uri)
}

// qrBlock renders the QR code of a request URI, its hint, and the link.
func (p *Page) qrBlock(b *blocks, uri string) template.HTML {
	src, ok := qrImage(uri)
	if !ok {
		return paragraph(msg.T("verifier.request.qr.long"))
	}
	return b.add("qr", components.QR{Src: src, Alt: msg.T("verifier.request.qr.alt"), Size: 288}) +
		template.HTML(`<p class="hint">`+template.HTMLEscapeString(msg.T("verifier.request.qr.hint"))+`</p>`) + //nolint:gosec // the text is escaped
		b.add("field", components.Field{ID: "request-link", Label: msg.T("verifier.request.link.label"), Value: uri,
			Attrs: map[string]string{"readonly": "readonly", "spellcheck": "false"}})
}

// submitDcAPI takes the answer that the kit script posts after
// navigator.credentials.get and hands it to the stack of the request.
func (p *Page) submitDcAPI(w http.ResponseWriter, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	id := r.PathValue("id")
	_, err := p.opts.Client.SubmitBrowserAnswer(r.Context(), connect.NewRequest(&ingestv1.SubmitBrowserAnswerRequest{
		TransactionId: id, Response: r.PostForm.Get("response"),
	}))
	switch connect.CodeOf(err) {
	case connect.CodeNotFound:
		http.NotFound(w, r)
		return nil
	case connect.CodeInvalidArgument, connect.CodeFailedPrecondition, connect.CodeUnavailable:
		b := &blocks{kit: p.opts.Kit}
		card := b.add("card", components.Card{ID: "dcapi-problem", Title: msg.T("verifier.request.title.label"),
			Body: template.HTML(`<p class="error" role="alert">`+template.HTMLEscapeString(msg.T("verifier.request.problem.dcapi")+" "+connectReason(err))+`</p>`) + //nolint:gosec // the text is escaped
				b.add("button", components.Button{Text: msg.T("verifier.request.dcapi.back.label"), Href: p.requestsPath() + url.PathEscape(id) + "?as=" + deliverDCAPI})})
		if b.err != nil {
			return b.err
		}
		w.WriteHeader(http.StatusBadRequest)
		return p.render(w, r, components.Page{Title: msg.T("verifier.request.title.label"), Lead: msg.T("verifier.request.page.lead"),
			Description: msg.T("verifier.request.page.lead"), Content: card})
	}
	if err != nil {
		return err
	}
	http.Redirect(w, r, p.requestsPath()+url.PathEscape(id)+"?as="+deliverDCAPI, http.StatusSeeOther)
	return nil
}

// qrQuiet is the margin of a QR image in modules.
const qrQuiet = 4

// qrImage draws the QR code of a payload as an SVG data URI. ok is
// false when the payload is empty or too long for a QR code.
func qrImage(payload string) (template.URL, bool) {
	code, err := qr.Encode([]byte(payload))
	if payload == "" || err != nil {
		return "", false
	}
	n := strconv.Itoa(code.Size + 2*qrQuiet)
	var path strings.Builder
	for y := 0; y < code.Size; y++ {
		for x := 0; x < code.Size; x++ {
			if code.Module(x, y) {
				path.WriteString("M" + strconv.Itoa(x+qrQuiet) + " " + strconv.Itoa(y+qrQuiet) + "h1v1h-1z")
			}
		}
	}
	svg := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ` + n + ` ` + n + `" shape-rendering="crispEdges">` +
		`<rect width="` + n + `" height="` + n + `" fill="#fff"/><path fill="#000" d="` + path.String() + `"/></svg>`
	return template.URL("data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(svg))), true //nolint:gosec // the page builds the SVG from the QR modules alone
}

// requestState answers the htmx poll with the state block. A request
// that no longer waits also clears the delivery out of band.
func (p *Page) requestState(w http.ResponseWriter, r *http.Request) error {
	tx, ok, err := p.transaction(w, r)
	if !ok {
		return err
	}
	b := &blocks{kit: p.opts.Kit}
	out := p.stateBlock(r.Context(), b, tx, r.PathValue("id"))
	if !pending(tx) {
		out += template.HTML(`<div id="request-delivery" hx-swap-oob="true">`) + paragraph(msg.T("verifier.request.delivery.closed")) + template.HTML(`</div>`)
	}
	if b.err != nil {
		return b.err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err = w.Write([]byte(out))
	return err
}

// stepOf returns the step of the stepper: 1 waiting, 2 received, 3
// verified.
func stepOf(tx *ingestv1.GetTransactionResponse) int {
	switch {
	case tx.GetResultId() != "":
		return 3
	case tx.GetState() == ingestv1.GetTransactionResponse_STATE_RECEIVED:
		return 2
	}
	return 1
}

// stateBlock renders the state of a request. A waiting request polls
// every 2 seconds and carries a refresh link. A finished one shows the
// verdict card.
func (p *Page) stateBlock(ctx context.Context, b *blocks, tx *ingestv1.GetTransactionResponse, id string) template.HTML {
	page := p.requestsPath() + url.PathEscape(id)
	steps := b.add("stepper", components.Stepper{Label: msg.T("verifier.request.progress.label"), Current: stepOf(tx),
		Steps: []string{msg.T("verifier.request.step.waiting.label"), msg.T("verifier.request.step.received.label"), msg.T("verifier.request.step.verified.label")}})
	var body template.HTML
	var attrs map[string]string
	switch {
	case pending(tx):
		attrs = map[string]string{"hx-get": page + "/state", "hx-trigger": "every 2s", "hx-swap": "outerHTML"}
		body = paragraph(msg.T("verifier.request.state.waiting")) +
			template.HTML(`<p><a href="`+template.HTMLEscapeString(page)+`">`+template.HTMLEscapeString(msg.T("verifier.request.refresh.label"))+`</a></p>`) //nolint:gosec // both parts are escaped
	case tx.GetState() == ingestv1.GetTransactionResponse_STATE_EXPIRED:
		body = b.add("badge", components.Badge{Status: "warn", Text: msg.T("verifier.request.state.expired.label")}) +
			paragraph(msg.T("verifier.request.state.expired")) + p.againButton(b, tx)
	case tx.GetState() == ingestv1.GetTransactionResponse_STATE_REFUSED:
		body = b.add("badge", components.Badge{Status: "bad", Text: msg.T("verifier.request.state.refused.label")}) +
			paragraph(msg.T("verifier.request.state.refused", tx.GetError())) + p.againButton(b, tx)
	case tx.GetResultId() == "":
		body = paragraph(msg.T("verifier.request.state.unchecked")) + p.stackChecks(ctx, b, tx)
	default:
		body = p.verdictCard(ctx, b, tx)
	}
	return b.add("block", components.Block{ID: "request-state", Title: msg.T("verifier.request.state.label"), Body: steps + body, Attrs: attrs})
}

// againButton leads to a new request of the same query.
func (p *Page) againButton(b *blocks, tx *ingestv1.GetTransactionResponse) template.HTML {
	return b.add("button", components.Button{Text: msg.T("verifier.request.again.label"),
		Href: p.requestsPath() + "new?template=" + url.QueryEscape(tx.GetTemplateId())})
}

// verdictCard renders the stored result: the verdict, the checks, the
// checks of the stack, the claims, and the result id.
func (p *Page) verdictCard(ctx context.Context, b *blocks, tx *ingestv1.GetTransactionResponse) template.HTML {
	id := tx.GetResultId()
	saved := template.HTML(`<p>`+template.HTMLEscapeString(msg.T("verifier.request.saved", id))+` `) + //nolint:gosec // the text is escaped
		template.HTML(`<a href="`+template.HTMLEscapeString(p.opts.ResultsPath+url.PathEscape(id))+`">`+template.HTMLEscapeString(msg.T("verifier.request.open_result.label"))+`</a></p>`) //nolint:gosec // both parts are escaped
	done := b.add("button", components.Button{Text: msg.T("verifier.request.done.label"), Href: p.requestsPath()})
	var result *resultsv1.VerificationResult
	if p.opts.Results != nil {
		if resp, err := p.opts.Results.Get(ctx, connect.NewRequest(&resultsv1.GetRequest{Id: id})); err == nil {
			result = resp.Msg.GetResult()
		}
	}
	if result == nil {
		return b.add("card", components.Card{ID: "verdict", Title: msg.T("verifier.request.step.verified.label"),
			Text: msg.T("verifier.request.result.missing"), Body: saved + done})
	}
	badge := template.HTML(`<p>`) + b.add("badge", verdictBadge(result.GetVerdict())) + template.HTML(`</p>`)
	meta := msg.T("verifier.request.verified.at", clock(result.GetEvaluatedAt().AsTime()), p.throughName(ctx, tx.GetStack()))
	var rows []components.Row
	checks := append([]*policyv1.CheckResult(nil), result.GetChecks()...)
	for _, c := range result.GetCredentials() {
		checks = append(checks, c.GetChecks()...)
	}
	for _, c := range checks {
		rows = append(rows, components.Row{{Text: c.GetName()}, {Text: outcomeWord(c.GetOutcome())}, {Text: c.GetDetail()}})
	}
	table := b.add("table", components.Table{ID: "verdict-checks", Caption: msg.T("verifier.request.checks.label"),
		Columns: []string{msg.T("verifier.scan.stack.column.check.label"), msg.T("verifier.scan.stack.column.outcome.label"), msg.T("verifier.scan.stack.column.reason.label")},
		Rows:    rows, Empty: msg.T("verifier.request.checks.none")})
	var claims []components.Row
	for _, c := range result.GetCredentials() {
		fields := c.GetDisplayFields()
		names := make([]string, 0, len(fields))
		for k := range fields {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			claims = append(claims, components.Row{{Text: k}, {Text: fields[k]}})
		}
	}
	claimTable := b.add("table", components.Table{ID: "verdict-claims", Caption: msg.T("verifier.request.claims.label"),
		Columns: []string{msg.T("verifier.request.claims.column.claim.label"), msg.T("verifier.request.claims.column.value.label")},
		Rows:    claims, Empty: msg.T("verifier.request.claims.none")})
	if age := result.GetMaterialAge(); age != nil {
		badge += template.HTML(`<p>` + template.HTMLEscapeString(msg.T("verifier.request.material", msg.Age(age.AsDuration()))) + `</p>`) //nolint:gosec // the text is escaped
	}
	report := b.add("button", components.Button{Text: msg.T("verifier.report.download.label"),
		Href: p.opts.ResultsPath + url.PathEscape(id) + "/report.pdf"})
	return b.add("card", components.Card{ID: "verdict", Title: msg.T("verifier.request.step.verified.label"), Text: meta,
		Body: components.Join(badge, table, p.stackChecks(ctx, b, tx), claimTable, saved, report, done)})
}

// stackChecks renders the checks the stack ran, or nothing.
func (p *Page) stackChecks(ctx context.Context, b *blocks, tx *ingestv1.GetTransactionResponse) template.HTML {
	if len(tx.GetStackChecks()) == 0 {
		return ""
	}
	rows := make([]components.Row, 0, len(tx.GetStackChecks()))
	for _, c := range tx.GetStackChecks() {
		rows = append(rows, components.Row{{Text: c.GetName()}, {Text: stackWord(c)}, {Text: c.GetReason()}})
	}
	return b.add("table", components.Table{ID: "verdict-stack-checks", Caption: msg.T("verifier.request.stack_checks.label", p.throughName(ctx, tx.GetStack())),
		Columns: []string{msg.T("verifier.scan.stack.column.check.label"), msg.T("verifier.scan.stack.column.outcome.label"), msg.T("verifier.scan.stack.column.reason.label")},
		Rows:    rows})
}

// stackWord names the outcome of a check of a stack.
func stackWord(c *backendv1.GetResultResponse_DpgCheck) string {
	if c.GetPassed() {
		return msg.T("verifier.scan.stack.passed.label")
	}
	return msg.T("verifier.scan.stack.failed.label")
}

// verdictBadge returns the badge of a verdict.
func verdictBadge(v policyv1.EvaluateResponse_Verdict) components.Badge {
	switch v {
	case policyv1.EvaluateResponse_VERDICT_VALID:
		return components.Badge{Status: "ok", Text: msg.T("verifier.request.verdict.valid.label")}
	case policyv1.EvaluateResponse_VERDICT_INVALID:
		return components.Badge{Status: "bad", Text: msg.T("verifier.request.verdict.invalid.label")}
	}
	return components.Badge{Status: "warn", Text: msg.T("verifier.request.verdict.unknown.label")}
}

// outcomeWord names the outcome of a check.
func outcomeWord(o policyv1.Outcome) string {
	switch o {
	case policyv1.Outcome_OUTCOME_PASS:
		return msg.T("verifier.request.outcome.pass.label")
	case policyv1.Outcome_OUTCOME_FAIL:
		return msg.T("verifier.request.outcome.fail.label")
	case policyv1.Outcome_OUTCOME_SKIP:
		return msg.T("verifier.request.outcome.skip.label")
	}
	return msg.T("verifier.request.outcome.error.label")
}

// stateWord names the state of a request in the list.
func stateWord(s *ingestv1.TransactionSummary) components.Badge {
	switch {
	case s.GetResultId() != "":
		return components.Badge{Status: "info", Text: msg.T("verifier.request.state.checked.label")}
	case s.GetState() == ingestv1.GetTransactionResponse_STATE_RECEIVED:
		return components.Badge{Status: "info", Text: msg.T("verifier.request.step.received.label")}
	case s.GetState() == ingestv1.GetTransactionResponse_STATE_REFUSED:
		return components.Badge{Status: "bad", Text: msg.T("verifier.request.state.refused.label")}
	case s.GetState() == ingestv1.GetTransactionResponse_STATE_EXPIRED:
		return components.Badge{Status: "warn", Text: msg.T("verifier.request.state.expired.label")}
	}
	return components.Badge{Status: "info", Text: msg.T("verifier.request.step.waiting.label")}
}

// requestList renders the requests, newest first.
func (p *Page) requestList(w http.ResponseWriter, r *http.Request) error {
	resp, err := p.opts.Client.ListTransactions(r.Context(), connect.NewRequest(&ingestv1.ListTransactionsRequest{}))
	if err != nil {
		return err
	}
	list, err := p.templateList(r.Context())
	if err != nil {
		return err
	}
	names := map[string]string{}
	for _, t := range list {
		names[t.GetId()] = t.GetDisplayName()
	}
	b := &blocks{kit: p.opts.Kit}
	rows := make([]components.Row, 0, len(resp.Msg.GetTransactions()))
	for _, s := range resp.Msg.GetTransactions() {
		name := names[s.GetTemplateId()]
		if name == "" {
			name = msg.T("verifier.request.query.adhoc.label")
		}
		result := components.Cell{}
		if id := s.GetResultId(); id != "" {
			result.HTML = link(p.opts.ResultsPath+url.PathEscape(id), id)
		}
		rows = append(rows, components.Row{
			{HTML: link(p.requestsPath()+url.PathEscape(s.GetTransactionId()), name)},
			{Text: p.throughName(r.Context(), s.GetStack())},
			{HTML: b.add("badge", stateWord(s))},
			{HTML: b.add("badge", listVerdict(s.GetVerdict()))},
			{Text: clock(s.GetCreatedAt().AsTime())},
			result,
		})
	}
	table := b.add("table", components.Table{ID: "requests", Caption: msg.T("verifier.request.list.caption.label"),
		Columns: []string{
			msg.T("verifier.request.query.label"), msg.T("verifier.request.column.through.label"), msg.T("verifier.request.column.state.label"),
			msg.T("verifier.results.verdict.label"), msg.T("verifier.request.column.created.label"), msg.T("verifier.request.column.result.label"),
		},
		Rows: rows, Empty: msg.T("verifier.request.list.empty")})
	action := b.add("button", components.Button{Text: msg.T("verifier.request.tab.new.label"), Href: p.requestsPath() + "new", Variant: "primary"})
	if b.err != nil {
		return b.err
	}
	return p.render(w, r, components.Page{
		Title: msg.T("verifier.request.list.title.label"), Lead: msg.T("verifier.request.list.lead"), Description: msg.T("verifier.request.list.lead"),
		Content: components.Join(p.scanTabs(b, "list"), template.HTML(`<div class="form-actions">`), action, template.HTML(`</div>`), table),
	})
}

// listVerdict is the verdict of a request in the list, or a word that
// says no evaluation ran yet. The verdict enums share their values.
func listVerdict(v commonv1.Verdict) components.Badge {
	if v == commonv1.Verdict_VERDICT_UNSPECIFIED {
		return components.Badge{Status: "info", Text: msg.T("verifier.request.verdict.none.label")}
	}
	return verdictBadge(policyv1.EvaluateResponse_Verdict(v))
}

// link renders one anchor. Both parts are escaped.
func link(href, text string) template.HTML {
	return template.HTML(`<a href="` + template.HTMLEscapeString(href) + `">` + template.HTMLEscapeString(text) + `</a>`) //nolint:gosec // both parts are escaped
}

// Layout of the request document, in points.
const (
	docMargin = 72.0
	docTitleY = 770.0
	docLeadY  = 744.0
	docQRSize = 260.0
	docQRY    = 440.0
	docLinkY  = 410.0
	docLine   = 11.0
	docChars  = 80
	docFootY  = 60.0
)

// requestDocument serves the request as a PDF document: the query name,
// a sentence for the holder, the QR code, the link, and the expiry.
func (p *Page) requestDocument(w http.ResponseWriter, r *http.Request) error {
	tx, ok, err := p.transaction(w, r)
	if !ok {
		return err
	}
	t := p.templateOf(r.Context(), tx.GetTemplateId())
	data, err := RequestPDF(t.GetDisplayName(), tx.GetRequestUri(), tx.GetExpiresAt().AsTime())
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="presentation-request.pdf"`)
	_, err = w.Write(data)
	return err
}

// RequestPDF draws the PDF document of a request.
func RequestPDF(title, uri string, expires time.Time) ([]byte, error) {
	code, err := qr.Encode([]byte(uri))
	if err != nil {
		return nil, fmt.Errorf("scanner: encode the QR code: %w", err)
	}
	scale := max(2, min(8, 520/code.Size))
	bitmap := code.Bitmap(scale, qrQuiet)
	doc := pdf.New(title)
	doc.TextCentered(pdf.HelveticaBold, 22, docTitleY, 0.15, title)
	doc.TextCentered(pdf.Helvetica, 11, docLeadY, 0.3, msg.T("verifier.request.document.lead"))
	doc.Line(docMargin, docLeadY-14, pdf.PageWidth-docMargin, docLeadY-14, 0.6, 0.8)
	if err := doc.Image(pdf.Image{Width: bitmap.Width, Height: bitmap.Height, Pixels: bitmap.Pixels}, (pdf.PageWidth-docQRSize)/2, docQRY, docQRSize); err != nil {
		return nil, fmt.Errorf("scanner: place the QR code: %w", err)
	}
	y := docLinkY
	for start := 0; start < len(uri); start += docChars {
		doc.Text(pdf.Courier, 8, docMargin, y, 0.3, uri[start:min(start+docChars, len(uri))])
		y -= docLine
	}
	doc.TextCentered(pdf.Helvetica, 9, docFootY, 0.5, msg.T("verifier.request.expires.at", clock(expires)))
	return doc.Bytes(), nil
}
