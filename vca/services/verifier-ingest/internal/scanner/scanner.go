// SPDX-License-Identifier: Apache-2.0

// Package scanner serves the camera page of the ingestion service
// (ADR-023 decision 6). The page reads a QR code in the browser and
// posts only the decoded text. The camera frames never leave the device.
//
// The page also works without a camera. A file upload and a paste box
// post to the same endpoint, so an image, a PDF, an XML document, or a
// pasted credential all reach the same decoders.
//
// Paths, under the configured prefix:
//
//	GET  /                 the camera page
//	POST /ingest           decode one upload, one paste, or one QR text
//	GET  /static/{file}    the vendored scanner and QR reader
package scanner

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"mime/multipart"
	"net/http"
	"strings"

	"connectrpc.com/connect"

	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1/ingestv1connect"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// Static holds the vendored browser assets.
//
//go:embed static
var Static embed.FS

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
	return &Page{opts: opts}, nil
}

// Prefix returns the URL prefix of the page.
func (p *Page) Prefix() string { return p.opts.Prefix }

// Register adds the page to mux.
func (p *Page) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+p.opts.Prefix+"/{$}", p.handle(p.show))
	mux.HandleFunc("POST "+p.opts.Prefix+"/ingest", p.handle(p.ingest))
	mux.Handle("GET "+p.opts.Prefix+"/static/", http.StripPrefix(p.opts.Prefix+"/static/", assets()))
}

// assets serves the vendored files with a long cache lifetime.
func assets() http.Handler {
	files, err := fsSub()
	if err != nil {
		return http.NotFoundHandler()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		http.FileServerFS(files).ServeHTTP(w, r)
	})
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
		Label: "Verifier ingestion",
		Brand: components.Link{Href: p.opts.Prefix + "/", Text: "Verifier ingestion"},
		Links: []components.Link{{Href: p.opts.Prefix + "/", Text: "Scan or upload", Current: true}},
	}
}

// show renders the camera page.
func (p *Page) show(w http.ResponseWriter, r *http.Request) error {
	b := &blocks{kit: p.opts.Kit}
	camera := p.cameraCard(b)
	upload := p.uploadCard(b)
	paste := p.pasteCard(b)
	if b.err != nil {
		return b.err
	}
	scripts := template.HTML(`<script src="` + template.HTMLEscapeString(p.opts.Prefix) + `/static/jsqr.min.js" defer></script>` + //nolint:gosec // the prefix is escaped
		`<script src="` + template.HTMLEscapeString(p.opts.Prefix) + `/static/scanner.js" defer></script>`)
	result := template.HTML(`<div id="scan-result" role="status" aria-live="polite"></div>`) //nolint:gosec // literal
	return p.opts.Kit.RenderPage(w, r, components.Page{
		Title:       "Scan or upload a credential",
		Description: "Read a QR code with the camera, upload an image or a PDF, or paste a credential.",
		Nav:         p.nav(),
		Content:     components.Join(camera, result, upload, paste, scripts),
	})
}

// cameraCard renders the camera part of the page.
func (p *Page) cameraCard(b *blocks) template.HTML {
	button := b.add("button", components.Button{
		Text: "Start camera", Variant: "primary", Controls: "scan-video", Expanded: false,
	})
	video := template.HTML(`<video id="scan-video" hidden playsinline muted aria-label="Camera view"></video>` + //nolint:gosec // literal
		`<p id="scan-status" role="status" aria-live="polite">The camera is off.</p>`)
	body := components.Join(button, video)
	card := b.add("card", components.Card{
		ID: "camera", Title: "Scan with the camera",
		Text: "The page reads the QR code on this device. Only the decoded text reaches the service.",
		Body: body, Footer: "The camera needs a secure origin, so use https or localhost.",
	})
	open := `<form id="scan-form" data-ingest="` + template.HTMLEscapeString(p.opts.Prefix+"/ingest") + `">`
	return components.Join(template.HTML(open), card, template.HTML(`</form>`)) //nolint:gosec // the value is escaped
}

// uploadCard renders the file upload fallback.
func (p *Page) uploadCard(b *blocks) template.HTML {
	field := b.add("field", components.Field{
		ID: "upload", Name: "upload", Label: "Image, PDF, or XML file", Type: "file",
		Hint: "The service reads the QR code of an image or a PDF, or the credential of an XML document.",
	})
	button := b.add("button", components.Button{Text: "Check the file", Type: "submit", Variant: "primary"})
	card := b.add("card", components.Card{
		ID: "upload-card", Title: "Upload a file",
		Text: "Use this when the device has no camera.",
		Body: components.Join(field, button),
	})
	return formOf(p.opts.Prefix+"/ingest", "multipart/form-data", card)
}

// pasteCard renders the paste box.
func (p *Page) pasteCard(b *blocks) template.HTML {
	field := b.add("field", components.Field{
		ID: "payload", Name: "payload", Label: "Credential or QR text", Type: "textarea",
		Hint: "Paste a credential, a presentation, an OID4VP request, or the text of a QR code.",
	})
	button := b.add("button", components.Button{Text: "Check the text", Type: "submit", Variant: "primary"})
	card := b.add("card", components.Card{
		ID: "paste-card", Title: "Paste a credential",
		Body: components.Join(field, button),
	})
	return formOf(p.opts.Prefix+"/ingest", "", card)
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

// ingest decodes one upload, one paste, or one decoded QR text.
func (p *Page) ingest(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, MaxUploadBytes)
	payload, mediaType, err := readInput(r)
	if err != nil {
		return p.answer(w, r, nil, err.Error())
	}
	resp, err := p.opts.Client.Ingest(r.Context(), connect.NewRequest(&ingestv1.IngestRequest{
		Payload: payload, MediaType: mediaType,
	}))
	if err != nil {
		return p.answer(w, r, nil, "The service could not read the input: "+connectReason(err))
	}
	return p.answer(w, r, resp.Msg, "")
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

// textOf reads the pasted text of a form.
func textOf(r *http.Request) ([]byte, string, error) {
	text := strings.TrimSpace(r.PostFormValue("payload"))
	if text == "" {
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
func (p *Page) answer(w http.ResponseWriter, r *http.Request, msg *ingestv1.IngestResponse, problem string) error {
	b := &blocks{kit: p.opts.Kit}
	body := p.resultCard(b, msg, problem)
	if b.err != nil {
		return b.err
	}
	if components.IsHTMX(r) || isFetch(r) {
		_, err := w.Write([]byte(body))
		return err
	}
	return p.opts.Kit.RenderPage(w, r, components.Page{
		Title:       "Ingestion result",
		Description: "What the decoders found in the input.",
		Nav:         p.nav(),
		Content:     body,
	})
}

// isFetch reports whether the browser script sent the request.
func isFetch(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "*/*") && r.Header.Get("Sec-Fetch-Mode") == "cors"
}

// resultCard renders what the decoders found.
func (p *Page) resultCard(b *blocks, msg *ingestv1.IngestResponse, problem string) template.HTML {
	if problem != "" {
		badge := b.add("badge", components.Badge{Status: "bad", Text: "Not read"})
		return b.add("card", components.Card{ID: "result", Title: "The input did not decode", Text: problem, Body: badge})
	}
	presentation := msg.GetPresentation()
	rows := []components.Row{
		{{Text: "Carrier"}, {Text: CarrierText(presentation.GetCarrier())}},
		{{Text: "Content"}, {Text: DetectedText(presentation.GetDetectedType())}},
		{{Text: "Credentials"}, {Text: fmt.Sprint(len(presentation.GetCredentials()))}},
		{{Text: "Decoder steps"}, {Text: strings.Join(msg.GetSteps(), ", ")}},
		{{Text: "Input hash"}, {Text: presentation.GetInputHash()}},
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

// fsSub returns the static directory of the embedded file system.
func fsSub() (fs.FS, error) {
	return fs.Sub(Static, "static")
}
