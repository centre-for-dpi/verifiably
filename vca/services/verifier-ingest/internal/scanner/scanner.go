// SPDX-License-Identifier: Apache-2.0

// Package scanner serves the camera page of the ingestion service
// (ADR-023 decision 6). The page reads a QR code in the browser and
// posts only the decoded text. The camera frames never leave the device.
//
// The page also works without a camera. A file upload, a paste box, and
// a link field post to the same endpoint, so an image, a PDF, an XML
// document, a pasted credential, or a fetched link all reach the same
// decoders. The service fetches a pasted link through core/fetchguard.
//
// When the live adapter of the own pair lists FEATURE_VERIFY_UPLOAD, each
// form offers "Check with the stack": the input then goes to
// VerifyCredential of the adapter too, and the answer shows the checks of
// the DPG beside the decoders.
//
// Paths, under the configured prefix:
//
//	GET  /                 the camera page
//	POST /ingest           decode one upload, one paste, or one QR text
//	GET  /static/{file}    the vendored scanner and QR reader
//	POST /signout          end the session at verifier-auth
//
// With a shell the page sits in the verifier frame of
// services/internal/staffshell (board Verifier-Portal).
package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/fetchguard"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1/ingestv1connect"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/qrscan"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// DefaultPrefix is the URL prefix of the page.
const DefaultPrefix = "/scan"

// MaxUploadBytes caps one upload.
const MaxUploadBytes = 16 << 20

// Options configure the page.
type Options struct {
	// Client calls the IngestService. The service satisfies it in
	// process.
	Client ingestv1connect.IngestServiceClient
	// Kit renders the components. Nil builds a new kit.
	Kit *components.Kit
	// Prefix is the URL prefix of the page. Empty means DefaultPrefix.
	Prefix string
	// Shell draws the verifier frame. Nil draws the plain navigation of
	// the service.
	Shell *staffshell.Shell
	// SignOut ends the session. Nil answers the sign out form with 404.
	SignOut http.Handler
	// Links fetches a pasted link through the guard of core/fetchguard.
	// Nil hides the link field and refuses a link.
	Links Getter
	// Stack returns the verifier of the adapter at a URL. Nil means a
	// Connect client with StackTimeout.
	Stack func(adapterURL string) StackVerifier
	// StackTimeout bounds one call to the adapter. Zero means 30 seconds.
	StackTimeout time.Duration
}

// Getter reads one document. A fetchguard.Fetcher is one.
type Getter interface {
	Get(ctx context.Context, url string) (fetchguard.Doc, error)
}

// StackVerifier checks an input with the verifier of a DPG.
type StackVerifier interface {
	VerifyCredential(context.Context, *connect.Request[backendv1.VerifyCredentialRequest]) (*connect.Response[backendv1.VerifyCredentialResponse], error)
}

// Page serves the camera page.
type Page struct {
	opts Options
}

// New builds the page.
func New(opts Options) (*Page, error) {
	if opts.Client == nil {
		return nil, errors.New("scanner: an IngestService client is required")
	}
	if opts.Prefix == "" {
		opts.Prefix = DefaultPrefix
	}
	opts.Prefix = "/" + strings.Trim(opts.Prefix, "/")
	if opts.Kit == nil {
		kit, err := components.New()
		if err != nil {
			return nil, err
		}
		opts.Kit = kit
	}
	if opts.StackTimeout <= 0 {
		opts.StackTimeout = 30 * time.Second
	}
	if opts.Stack == nil {
		client := &http.Client{Timeout: opts.StackTimeout}
		opts.Stack = func(adapterURL string) StackVerifier {
			return backendv1connect.NewVerifierBackendServiceClient(client, adapterURL)
		}
	}
	return &Page{opts: opts}, nil
}

// Prefix returns the URL prefix of the page.
func (p *Page) Prefix() string { return p.opts.Prefix }

// Register adds the page to mux.
func (p *Page) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+p.opts.Prefix+"/{$}", p.handle(p.show))
	mux.HandleFunc("POST "+p.opts.Prefix+"/ingest", p.handle(p.ingest))
	mux.Handle("GET "+p.opts.Prefix+"/static/", http.StripPrefix(p.opts.Prefix+"/static/", qrscan.Handler()))
	if p.opts.SignOut != nil {
		mux.Handle("POST "+p.opts.Prefix+"/signout", p.opts.SignOut)
	}
}

// SignOutPath returns the action of the sign out form of the shell.
func (p *Page) SignOutPath() string { return p.opts.Prefix + "/signout" }

// render writes a page: inside the verifier frame when the page has a
// shell, else with the navigation of the service.
func (p *Page) render(w http.ResponseWriter, r *http.Request, page components.Page) error {
	if p.opts.Shell != nil {
		return p.opts.Shell.Render(p.opts.Kit, w, r, p.opts.Shell.Frame(r.Context()), page)
	}
	page.Nav = p.nav()
	return p.opts.Kit.RenderPage(w, r, page)
}

// handle answers with a short sentence when a page fails.
func (p *Page) handle(fn func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := fn(w, r); err != nil {
			http.Error(w, "the page could not render", http.StatusInternalServerError)
		}
	}
}

// nav returns the navigation of the page.
func (p *Page) nav() components.Nav {
	return components.Nav{
		Label: msg.T("verifier.scan.brand.label"),
		Brand: components.Link{Href: p.opts.Prefix + "/", Text: msg.T("verifier.scan.brand.label")},
		Links: []components.Link{{Href: p.opts.Prefix + "/", Text: msg.T("verifier.scan.nav.label"), Current: true}},
	}
}

// stackOffer returns the name of the own stack when its live adapter
// lists FEATURE_VERIFY_UPLOAD, else "".
func (p *Page) stackOffer(ctx context.Context) (name, adapter string) {
	if p.opts.Shell == nil {
		return "", ""
	}
	f := p.opts.Shell.Frame(ctx)
	own, ok := f.Own()
	if !ok || !f.Has(backendv1.Feature_FEATURE_VERIFY_UPLOAD) || own.Peer.Adapter() == "" {
		return "", ""
	}
	return f.Snapshot().StackName(own.Peer.Dpg), own.Peer.Adapter()
}

// show renders the camera page.
func (p *Page) show(w http.ResponseWriter, r *http.Request) error {
	b := &blocks{kit: p.opts.Kit}
	csrf := staffsession.HiddenField(r.Context())
	stack, _ := p.stackOffer(r.Context())
	parts := []template.HTML{p.cameraCard(b, csrf, stack)}
	parts = append(parts, template.HTML(`<div id="scan-result" role="status" aria-live="polite"></div>`)) //nolint:gosec // literal
	parts = append(parts, template.HTML(`<div class="split">`), p.uploadCard(b, csrf, stack), p.pasteCard(b, csrf, stack))
	if p.opts.Links != nil {
		parts = append(parts, p.linkCard(b, csrf, stack))
	}
	parts = append(parts, template.HTML(`</div>`))
	if b.err != nil {
		return b.err
	}
	static := template.HTMLEscapeString(p.opts.Prefix) + "/static/"
	parts = append(parts, template.HTML(`<script src="`+static+qrscan.Reader+`" defer></script>`+ //nolint:gosec // the prefix is escaped
		`<script src="`+static+qrscan.Script+`" defer></script>`))
	return p.render(w, r, components.Page{
		Title: msg.T("verifier.scan.title.label"), Lead: msg.T("verifier.scan.lead"), Description: msg.T("verifier.scan.lead"),
		Content: components.Join(parts...),
	})
}

// stackChoice renders the "Check with the stack" box of one form, or
// nothing when the own stack does not check uploads.
func stackChoice(b *blocks, id, stack string) template.HTML {
	if stack == "" {
		return ""
	}
	return b.add("choice", components.Choice{
		ID: "stack-check-" + id, Name: "stack_check", Legend: msg.T("verifier.scan.stack.legend.label"), Multiple: true,
		Options: []components.ChoiceOption{{Value: "on", Title: msg.T("verifier.scan.stack.label"), Text: msg.T("verifier.scan.stack.hint", stack)}},
	})
}

// cameraCard renders the camera part of the page. The start button is a
// plain button with the id the shared scanner script reads; the kit
// disclosure script leaves it alone, because it has no aria-controls.
// csrf is the hidden field that binds the posts of the page to the
// session; the script sends it with the other fields of the scan form.
func (p *Page) cameraCard(b *blocks, csrf template.HTML, stack string) template.HTML {
	esc := template.HTMLEscapeString
	body := template.HTML(`<form id="scan-form" data-ingest="`+esc(p.opts.Prefix+"/ingest")+`">`) + csrf + //nolint:gosec // the values are escaped
		stackChoice(b, "camera", stack) +
		template.HTML(`<div class="form-actions"><button type="button" id="scan-start" class="btn btn-primary">`+ //nolint:gosec // the text is escaped
			esc(msg.T("verifier.scan.camera.start.label"))+`</button></div></form>`+
			`<video id="scan-video" hidden playsinline muted aria-label="`+esc(msg.T("verifier.scan.camera.video.label"))+`"></video>`+
			`<p id="scan-status" class="hint" role="status" aria-live="polite">`+esc(msg.T("verifier.scan.camera.off"))+`</p>`)
	return b.add("card", components.Card{
		ID: "camera", Title: msg.T("verifier.scan.camera.label"), Text: msg.T("verifier.scan.camera.text"),
		Body: body, Footer: msg.T("verifier.scan.camera.footer"),
	})
}

// uploadCard renders the file upload.
func (p *Page) uploadCard(b *blocks, csrf template.HTML, stack string) template.HTML {
	field := b.add("field", components.Field{
		ID: "upload", Name: "upload", Label: msg.T("verifier.scan.upload.field.label"), Type: "file",
		Hint: msg.T("verifier.scan.upload.hint"),
	})
	button := b.add("button", components.Button{Text: msg.T("verifier.scan.upload.submit.label"), Type: "submit", Variant: "primary"})
	return b.add("card", components.Card{
		ID: "upload-card", Title: msg.T("verifier.scan.upload.label"), Text: msg.T("verifier.scan.upload.text"),
		Body: formOf(p.opts.Prefix+"/ingest", "multipart/form-data", components.Join(csrf, field, stackChoice(b, "upload", stack), button)),
	})
}

// pasteCard renders the paste box.
func (p *Page) pasteCard(b *blocks, csrf template.HTML, stack string) template.HTML {
	field := b.add("field", components.Field{
		ID: "payload", Name: "payload", Label: msg.T("verifier.scan.paste.field.label"), Type: "textarea",
		Hint: msg.T("verifier.scan.paste.hint"),
	})
	button := b.add("button", components.Button{Text: msg.T("verifier.scan.paste.submit.label"), Type: "submit", Variant: "primary"})
	return b.add("card", components.Card{
		ID: "paste-card", Title: msg.T("verifier.scan.paste.label"),
		Body: formOf(p.opts.Prefix+"/ingest", "", components.Join(csrf, field, stackChoice(b, "paste", stack), button)),
	})
}

// linkCard renders the link field. The service fetches the link through
// the guard, never the browser.
func (p *Page) linkCard(b *blocks, csrf template.HTML, stack string) template.HTML {
	field := b.add("field", components.Field{
		ID: "link", Name: "link", Label: msg.T("verifier.scan.link.field.label"), Type: "url",
		Hint: msg.T("verifier.scan.link.hint"), Attrs: map[string]string{"placeholder": "https://", "spellcheck": "false"},
	})
	button := b.add("button", components.Button{Text: msg.T("verifier.scan.link.submit.label"), Type: "submit", Variant: "primary"})
	return b.add("card", components.Card{
		ID: "link-card", Title: msg.T("verifier.scan.link.label"), Text: msg.T("verifier.scan.link.text"),
		Body: formOf(p.opts.Prefix+"/ingest", "", components.Join(csrf, field, stackChoice(b, "link", stack), button)),
	})
}

// formOf wraps content in a post form.
func formOf(action, encoding string, content template.HTML) template.HTML {
	open := `<form action="` + template.HTMLEscapeString(action) + `" method="post"`
	if encoding != "" {
		open += ` enctype="` + template.HTMLEscapeString(encoding) + `"`
	}
	open += `>`
	return components.Join(template.HTML(open), content, template.HTML(`</form>`)) //nolint:gosec // both parts are escaped
}

// outcome is what one post found: the decoder answer or a problem,
// the link the service fetched, and the answer of the stack.
type outcome struct {
	msg     *ingestv1.IngestResponse
	problem string
	source  string
	stack   *stackAnswer
}

// stackAnswer is the answer of the verifier of the own stack.
type stackAnswer struct {
	name  string
	reply *backendv1.VerifyCredentialResponse
}

// ingest decodes one upload, one paste, one link, or one decoded QR
// text, and asks the stack too when the staff member chose that.
func (p *Page) ingest(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, MaxUploadBytes)
	payload, mediaType, err := readInput(r)
	if err != nil {
		return p.answer(w, r, outcome{problem: err.Error()})
	}
	var out outcome
	if link := linkOf(r, payload); link != "" {
		out.source = link
		if payload, err = p.fetch(r.Context(), link); err != nil {
			return p.answer(w, r, outcome{problem: msg.T("verifier.scan.link.refused") + " " + reasonOf(err)})
		}
		mediaType = ""
	}
	resp, err := p.opts.Client.Ingest(r.Context(), connect.NewRequest(&ingestv1.IngestRequest{
		Payload: payload, MediaType: mediaType,
	}))
	if err != nil {
		return p.answer(w, r, outcome{problem: "The service could not read the input: " + connectReason(err)})
	}
	out.msg = resp.Msg
	if r.PostFormValue("stack_check") == "on" {
		out.stack = p.askStack(r.Context(), payload, mediaType)
	}
	return p.answer(w, r, out)
}

// linkOf returns the link of the post: the link field, or pasted text
// that is one http or https URL. Other pasted text gives "".
func linkOf(r *http.Request, payload []byte) string {
	if link := strings.TrimSpace(r.PostFormValue("link")); link != "" {
		return link
	}
	text := strings.TrimSpace(string(payload))
	if strings.ContainsAny(text, " \n\t") {
		return ""
	}
	lower := strings.ToLower(text)
	if strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "http://") {
		return text
	}
	return ""
}

// fetch reads a link through the guard. A page without a fetcher takes
// no link.
func (p *Page) fetch(ctx context.Context, link string) ([]byte, error) {
	if p.opts.Links == nil {
		return nil, errors.New(msg.T("verifier.scan.link.off"))
	}
	doc, err := p.opts.Links.Get(ctx, link)
	if err != nil {
		return nil, err
	}
	return doc.Body, nil
}

// reasonOf returns the sentence of a fetch error for the page. A refusal
// of the guard names the rule; any other fault stays general, so no
// internal address reaches the page.
func reasonOf(err error) string {
	switch {
	case errors.Is(err, fetchguard.ErrRefused):
		return msg.T("verifier.scan.link.guard")
	case strings.HasPrefix(err.Error(), msg.T("verifier.scan.link.off")):
		return err.Error()
	}
	return msg.T("verifier.scan.link.failed")
}

// askStack sends the input to VerifyCredential of the own adapter, when
// its live adapter lists FEATURE_VERIFY_UPLOAD. A failed call gives an
// answer without a reply.
func (p *Page) askStack(ctx context.Context, payload []byte, mediaType string) *stackAnswer {
	name, adapter := p.stackOffer(ctx)
	if name == "" {
		return nil
	}
	res, err := p.opts.Stack(adapter).VerifyCredential(ctx, connect.NewRequest(&backendv1.VerifyCredentialRequest{
		Payload: payload, MediaType: mediaType,
	}))
	if err != nil {
		return &stackAnswer{name: name}
	}
	return &stackAnswer{name: name, reply: res.Msg}
}

// readInput reads the posted file or text.
func readInput(r *http.Request) ([]byte, string, error) {
	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "multipart/form-data") {
		if err := r.ParseMultipartForm(MaxUploadBytes); err != nil {
			return nil, "", errors.New("the upload is too large or not a form")
		}
		file, header, err := r.FormFile("upload")
		if err != nil {
			return textOf(r)
		}
		defer func() { ignoredClose := file.Close(); _ = ignoredClose }()
		return readFile(file, header)
	}
	if err := r.ParseForm(); err != nil {
		return nil, "", errors.New("the form could not be read")
	}
	return textOf(r)
}

// textOf reads the pasted text of a form. A form with only a link gives
// no text; the caller fetches the link.
func textOf(r *http.Request) ([]byte, string, error) {
	text := strings.TrimSpace(r.PostFormValue("payload"))
	if text == "" && strings.TrimSpace(r.PostFormValue("link")) == "" {
		return nil, "", errors.New("the page received no file and no text")
	}
	return []byte(text), "", nil
}

// readFile reads one uploaded file.
func readFile(file multipart.File, header *multipart.FileHeader) ([]byte, string, error) {
	data, err := io.ReadAll(io.LimitReader(file, MaxUploadBytes+1))
	if err != nil {
		return nil, "", errors.New("the file could not be read")
	}
	if len(data) > MaxUploadBytes {
		return nil, "", fmt.Errorf("the file is larger than %d bytes", MaxUploadBytes)
	}
	if len(data) == 0 {
		return nil, "", errors.New("the file is empty")
	}
	return data, header.Header.Get("Content-Type"), nil
}

// answer renders the result fragment, or the full page for a plain form
// post without htmx.
func (p *Page) answer(w http.ResponseWriter, r *http.Request, out outcome) error {
	b := &blocks{kit: p.opts.Kit}
	body := p.resultCard(b, out)
	if out.stack != nil {
		body += p.stackCard(b, out.stack)
	}
	if b.err != nil {
		return b.err
	}
	if components.IsHTMX(r) || isFetch(r) {
		_, err := w.Write([]byte(body))
		return err
	}
	back := b.add("button", components.Button{Text: msg.T("verifier.scan.again.label"), Href: p.opts.Prefix + "/"})
	return p.render(w, r, components.Page{
		Title: msg.T("verifier.scan.result.label"), Lead: msg.T("verifier.scan.result.lead"), Description: msg.T("verifier.scan.result.lead"),
		Content: components.Join(body, back),
	})
}

// stackCard renders the answer of the verifier of the own stack.
func (p *Page) stackCard(b *blocks, a *stackAnswer) template.HTML {
	title := msg.T("verifier.scan.stack.title.label", a.name)
	if a.reply == nil {
		return b.add("card", components.Card{ID: "stack-result", Title: title, Text: msg.T("verifier.scan.stack.failed"),
			Body: b.add("badge", components.Badge{Status: "warn", Text: msg.T("common.unknown.label")})})
	}
	badge := components.Badge{Status: "bad", Text: msg.T("verifier.scan.stack.rejected.label")}
	if a.reply.GetVerified() {
		badge = components.Badge{Status: "ok", Text: msg.T("verifier.scan.stack.accepted.label")}
	}
	rows := make([]components.Row, 0, len(a.reply.GetDpgChecks()))
	for _, c := range a.reply.GetDpgChecks() {
		word := msg.T("verifier.scan.stack.passed.label")
		if !c.GetPassed() {
			word = msg.T("verifier.scan.stack.failed.label")
		}
		rows = append(rows, components.Row{{Text: c.GetName()}, {Text: word}, {Text: c.GetReason()}})
	}
	table := b.add("table", components.Table{
		ID: "stack-checks", Caption: msg.T("verifier.scan.stack.caption.label"),
		Columns: []string{msg.T("verifier.scan.stack.column.check.label"), msg.T("verifier.scan.stack.column.outcome.label"), msg.T("verifier.scan.stack.column.reason.label")},
		Rows:    rows, Empty: msg.T("verifier.scan.stack.none"),
	})
	return b.add("card", components.Card{ID: "stack-result", Title: title, Body: components.Join(b.add("badge", badge), table)})
}

// isFetch reports whether the browser script sent the request.
func isFetch(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "*/*") && r.Header.Get("Sec-Fetch-Mode") == "cors"
}

// resultCard renders what the decoders found.
func (p *Page) resultCard(b *blocks, out outcome) template.HTML {
	if out.problem != "" {
		badge := b.add("badge", components.Badge{Status: "bad", Text: "Not read"})
		return b.add("card", components.Card{ID: "result", Title: "The input did not decode", Text: out.problem, Body: badge})
	}
	presentation := out.msg.GetPresentation()
	rows := []components.Row{
		{{Text: "Carrier"}, {Text: CarrierText(presentation.GetCarrier())}},
		{{Text: "Content"}, {Text: DetectedText(presentation.GetDetectedType())}},
		{{Text: "Credentials"}, {Text: fmt.Sprint(len(presentation.GetCredentials()))}},
		{{Text: "Decoder steps"}, {Text: strings.Join(out.msg.GetSteps(), ", ")}},
		{{Text: "Input hash"}, {Text: presentation.GetInputHash()}},
	}
	if out.source != "" {
		rows = append(rows, components.Row{{Text: msg.T("verifier.scan.link.source.label")}, {Text: out.source}})
	}
	table := b.add("table", components.Table{
		ID: "result-table", Caption: "What the decoders found",
		Columns: []string{"Item", "Value"}, Rows: rows,
	})
	payload := b.add("json", components.JSON{ID: "payload", Summary: "Decoded payload", Data: payloadValue(presentation.GetPayload())})
	badge := b.add("badge", components.Badge{Status: "ok", Text: "Read"})
	return b.add("card", components.Card{
		ID: "result", Title: "The service read the input",
		Body: components.Join(badge, table, payload),
	})
}

// payloadValue turns the decoded payload into a value the JSON component
// renders. Bytes that are not JSON become one text member.
func payloadValue(payload []byte) any {
	trimmed := strings.TrimSpace(string(payload))
	if trimmed == "" {
		return map[string]any{}
	}
	var v any
	if err := json.Unmarshal([]byte(trimmed), &v); err != nil {
		return map[string]any{"text": trimmed}
	}
	return v
}

// CarrierText returns the reader facing name of a carrier.
func CarrierText(c ingestv1.Carrier) string {
	switch c {
	case ingestv1.Carrier_CARRIER_OID4VP, ingestv1.Carrier_CARRIER_OID4VP_RESPONSE: //nolint:staticcheck // the deprecated value stays readable
		return "OID4VP response"
	case ingestv1.Carrier_CARRIER_OID4VP_REQUEST:
		return "OID4VP request"
	case ingestv1.Carrier_CARRIER_IMAGE:
		return "Image"
	case ingestv1.Carrier_CARRIER_PDF:
		return "PDF"
	case ingestv1.Carrier_CARRIER_XML:
		return "XML"
	case ingestv1.Carrier_CARRIER_JSON:
		return "JSON"
	case ingestv1.Carrier_CARRIER_QR:
		return "QR code"
	case ingestv1.Carrier_CARRIER_QR_CLAIM169:
		return "Claim 169 QR code"
	}
	return "Unknown"
}

// DetectedText returns the reader facing name of a detected type.
func DetectedText(d ingestv1.DetectedType) string {
	switch d {
	case ingestv1.DetectedType_DETECTED_TYPE_CREDENTIAL:
		return "One credential"
	case ingestv1.DetectedType_DETECTED_TYPE_PRESENTATION:
		return "A presentation"
	case ingestv1.DetectedType_DETECTED_TYPE_CWT_CLAIM169:
		return "A CWT with claim 169"
	case ingestv1.DetectedType_DETECTED_TYPE_PIXELPASS:
		return "A legacy PixelPass code"
	}
	return "Bytes the decoders do not know"
}

// connectReason returns the short sentence of a Connect error.
func connectReason(err error) string {
	var cerr *connect.Error
	if errors.As(err, &cerr) {
		return cerr.Message()
	}
	return err.Error()
}

// blocks renders components and keeps the first error.
type blocks struct {
	kit *components.Kit
	err error
}

// add renders one component and returns its markup.
func (b *blocks) add(name string, data any) template.HTML {
	if b.err != nil {
		return ""
	}
	h, err := b.kit.HTML(name, data)
	if err != nil {
		b.err = err
	}
	return h
}
