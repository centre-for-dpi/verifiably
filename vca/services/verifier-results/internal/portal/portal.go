// SPDX-License-Identifier: Apache-2.0

// Package portal renders the pages of the verifier results service with
// the vca UI kit (ADR-025 decisions 2, 4, 5, and 6).
//
// Staff pages, under the configured prefix, inside the verifier frame of
// services/internal/staffshell (board Verifier-Portal):
//
//	GET  /             the overview; a URL with a query is an old list URL
//	                   and moves to /results/ with the query kept
//	GET  /results/     the result list with filters and export links
//	GET  /results/{id} the card list of one result
//	GET  /export       the CSV or JSON download of the filtered results
//	GET  /cache/       how the verifier checks trust and status
//	GET  /help/        what each verifier page does, and every RPC
//	POST /signout      end the session at verifier-auth
//
// Citizen page, under the public prefix:
//
//	GET  /            the paste form
//	POST /            the card list of a pasted presentation, stored nowhere
package portal

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-results/internal/cards"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-results/internal/export"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-results/internal/service"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// DefaultPrefix is the URL prefix of the staff pages.
const DefaultPrefix = "/portal"

// DefaultPublicPrefix is the URL prefix of the citizen page.
const DefaultPublicPrefix = "/verify"

// DefaultMaxPasteBytes caps a pasted presentation.
const DefaultMaxPasteBytes = 1 << 20

// Evaluator checks one pasted presentation. The citizen page stores
// nothing, so it calls this function and renders the answer
// (ADR-025 decision 5).
type Evaluator func(ctx context.Context, payload []byte) (*resultsv1.VerificationResult, error)

// Discovery reads the saved queries and the catalogue of the discovery
// service of the pair. The overview counts and lists from it.
type Discovery interface {
	ListTemplates(context.Context, *connect.Request[discoveryv1.ListTemplatesRequest]) (*connect.Response[discoveryv1.ListTemplatesResponse], error)
	ListCredentialTypes(context.Context, *connect.Request[discoveryv1.ListCredentialTypesRequest]) (*connect.Response[discoveryv1.ListCredentialTypesResponse], error)
	GetFields(context.Context, *connect.Request[discoveryv1.GetFieldsRequest]) (*connect.Response[discoveryv1.GetFieldsResponse], error)
}

// Requests lists the OID4VP transactions of the ingestion service of the
// pair. The overview counts the open requests from it.
type Requests interface {
	ListTransactions(context.Context, *connect.Request[ingestv1.ListTransactionsRequest]) (*connect.Response[ingestv1.ListTransactionsResponse], error)
}

// Options configure the portal.
type Options struct {
	// Service answers the queries. The in process service satisfies it.
	Service *service.Service
	// Cards renders the result cards. Nil builds a new renderer.
	Cards *cards.Cards
	// Prefix is the URL prefix of the staff pages.
	Prefix string
	// PublicPrefix is the URL prefix of the citizen page.
	PublicPrefix string
	// Evaluate checks a pasted presentation. Nil turns the citizen page
	// into a page that says the check is not available.
	Evaluate Evaluator
	// MaxPasteBytes caps a pasted presentation. Zero means
	// DefaultMaxPasteBytes.
	MaxPasteBytes int64
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
	// Shell draws the verifier frame of the staff pages. Nil draws the
	// plain navigation of the service.
	Shell *staffshell.Shell
	// SignOut ends the session. Nil answers the sign out form with 404.
	SignOut http.Handler
	// Discovery reads the saved queries and the catalogue. Nil shows
	// them as unknown.
	Discovery Discovery
	// Requests lists the requests of the ingestion service. Nil shows
	// the open requests as unknown.
	Requests Requests
	// DocsURL is the base of the documents the help page links. Empty
	// means DefaultDocsURL.
	DocsURL string
}

// Portal serves the pages.
type Portal struct {
	opts Options
}

// New builds the portal.
func New(opts Options) (*Portal, error) {
	if opts.Service == nil {
		return nil, errors.New("portal: a results service is required")
	}
	if opts.Cards == nil {
		c, err := cards.New(nil)
		if err != nil {
			return nil, err
		}
		opts.Cards = c
	}
	opts.Prefix = clean(opts.Prefix, DefaultPrefix)
	opts.PublicPrefix = clean(opts.PublicPrefix, DefaultPublicPrefix)
	if opts.MaxPasteBytes <= 0 {
		opts.MaxPasteBytes = DefaultMaxPasteBytes
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Portal{opts: opts}, nil
}

// clean returns a prefix with one leading slash and no trailing slash.
func clean(prefix, fallback string) string {
	if strings.Trim(prefix, "/") == "" {
		prefix = fallback
	}
	return "/" + strings.Trim(prefix, "/")
}

// Prefix returns the URL prefix of the staff pages.
func (p *Portal) Prefix() string { return p.opts.Prefix }

// PublicPrefix returns the URL prefix of the citizen page.
func (p *Portal) PublicPrefix() string { return p.opts.PublicPrefix }

// resultsPath returns the path of the result list.
func (p *Portal) resultsPath() string { return p.opts.Prefix + "/results/" }

// Register adds every page to mux.
func (p *Portal) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+p.opts.Prefix+"/{$}", p.handle(p.overview))
	mux.HandleFunc("GET "+p.opts.Prefix+"/results/{$}", p.handle(p.list))
	mux.HandleFunc("GET "+p.opts.Prefix+"/results/{id}", p.handle(p.detail))
	mux.HandleFunc("GET "+p.opts.Prefix+"/export", p.handle(p.download))
	mux.HandleFunc("GET "+p.opts.Prefix+"/cache/{$}", p.handle(p.cache))
	mux.HandleFunc("GET "+p.opts.Prefix+"/help/{$}", p.handle(p.help))
	if p.opts.SignOut != nil {
		mux.Handle("POST "+p.opts.Prefix+"/signout", p.opts.SignOut)
	}
	mux.HandleFunc("GET "+p.opts.PublicPrefix+"/{$}", p.handle(p.publicForm))
	mux.HandleFunc("POST "+p.opts.PublicPrefix+"/{$}", p.handle(p.publicCheck))
}

// handle answers with a short sentence when a page fails.
func (p *Portal) handle(fn func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := fn(w, r); err != nil {
			http.Error(w, msg.T("common.render_failed"), http.StatusInternalServerError)
		}
	}
}

// nav returns the navigation of a staff page without the shell.
func (p *Portal) nav(current string) components.Nav {
	return components.Nav{
		Label: "Main",
		Brand: components.Link{Href: p.opts.Prefix + "/", Text: msg.T("verifier.results.brand.label")},
		Links: []components.Link{
			{Href: p.opts.Prefix + "/", Text: msg.T("common.overview.label"), Current: current == "overview"},
			{Href: p.resultsPath(), Text: msg.T("verifier.nav.results.label"), Current: current == "list"},
			{Href: p.opts.PublicPrefix + "/", Text: msg.T("verifier.check.nav.label"), Current: current == "public"},
		},
	}
}

// render writes a staff page: inside the verifier frame when the portal
// has a shell, else with the navigation of the service.
func (p *Portal) render(w http.ResponseWriter, r *http.Request, current string, page components.Page) error {
	kit := p.opts.Cards.Kit()
	if p.opts.Shell != nil {
		return p.opts.Shell.Render(kit, w, r, p.opts.Shell.Frame(r.Context()), page)
	}
	page.Nav = p.nav(current)
	return kit.RenderPage(w, r, page)
}

// list renders the result list with the filter form.
func (p *Portal) list(w http.ResponseWriter, r *http.Request) error {
	filter, problem := filterOf(r.URL.Query())
	var body []template.HTML
	form, err := p.filterForm(r.URL.Query(), problem)
	if err != nil {
		return err
	}
	body = append(body, form)
	if problem == "" {
		table, terr := p.resultTable(r.Context(), filter)
		if terr != nil {
			return terr
		}
		body = append(body, table)
	}
	return p.render(w, r, "list", components.Page{
		Title:       msg.T("verifier.nav.results.label"),
		Lead:        msg.T("verifier.results.lead"),
		Description: msg.T("verifier.results.lead"),
		Content:     components.Join(body...),
	})
}

// filterForm renders the query form and the export links.
func (p *Portal) filterForm(values url.Values, problem string) (template.HTML, error) {
	kit := p.opts.Cards.Kit()
	fields := []components.Field{
		{ID: "from", Label: msg.T("verifier.results.from.label"), Type: "date", Value: values.Get("from"),
			Hint: msg.T("verifier.results.from.hint")},
		{ID: "to", Label: msg.T("verifier.results.to.label"), Type: "date", Value: values.Get("to"),
			Hint: msg.T("verifier.results.to.hint")},
		{ID: "verdict", Label: msg.T("verifier.results.verdict.label"), Type: "select", Value: values.Get("verdict"),
			Options: verdictOptions(values.Get("verdict"))},
		{ID: "issuer", Label: msg.T("verifier.results.issuer.label"), Value: values.Get("issuer"),
			Hint: msg.T("verifier.results.issuer.hint")},
		{ID: "template", Label: msg.T("verifier.results.query.label"), Value: values.Get("template"),
			Hint: msg.T("verifier.results.query.hint")},
	}
	if problem != "" {
		fields[0].Error = problem
	}
	parts := make([]template.HTML, 0, len(fields)+3)
	for _, f := range fields {
		html, err := kit.HTML("field", f)
		if err != nil {
			return "", err
		}
		parts = append(parts, html)
	}
	apply, err := kit.HTML("button", components.Button{Text: msg.T("verifier.results.apply.label"), Type: "submit", Variant: "primary"})
	if err != nil {
		return "", err
	}
	parts = append(parts, apply)
	query := values.Encode()
	for _, e := range []struct{ encoding, text string }{
		{"csv", msg.T("verifier.results.csv.label")}, {"json", msg.T("verifier.results.json.label")},
	} {
		link, lerr := kit.HTML("button", components.Button{
			Text: e.text, Href: p.opts.Prefix + "/export?encoding=" + e.encoding + "&" + query,
		})
		if lerr != nil {
			return "", lerr
		}
		parts = append(parts, link)
	}
	return kit.HTML("card", components.Card{
		ID:    "filters",
		Title: msg.T("verifier.results.filter.label"),
		Text:  msg.T("verifier.results.filter.text"),
		Body: template.HTML(`<form method="get" action="`+template.HTMLEscapeString(p.resultsPath())+`">`) + //nolint:gosec // the path is escaped
			components.Join(parts...) + template.HTML(`</form>`),
	})
}

// resultTable renders the matching results as a table.
func (p *Portal) resultTable(ctx context.Context, filter *resultsv1.Filter) (template.HTML, error) {
	page, err := p.opts.Service.QueryAll(ctx, filter)
	if err != nil {
		return "", err
	}
	table := components.Table{
		ID: "results", Caption: msg.T("verifier.results.caption.label"),
		Columns: []string{
			msg.T("verifier.results.column.at.label"), msg.T("verifier.results.verdict.label"),
			msg.T("verifier.results.column.credentials.label"), msg.T("verifier.results.query.label"),
			msg.T("common.detail.label"),
		},
		Empty: msg.T("verifier.results.none"),
	}
	kit := p.opts.Cards.Kit()
	for _, r := range page {
		link, lerr := kit.HTML("button", components.Button{
			Text: msg.T("common.open.label"), Href: p.resultsPath() + url.PathEscape(r.GetId()),
		})
		if lerr != nil {
			return "", lerr
		}
		table.Rows = append(table.Rows, components.Row{
			{Text: at(r)}, {Text: verdictText(r.GetVerdict())},
			{Text: fmt.Sprint(len(r.GetCredentials()))},
			{Text: r.GetTemplateId()}, {HTML: link},
		})
	}
	return kit.HTML("table", table)
}

// detail renders the card list of one result.
func (p *Portal) detail(w http.ResponseWriter, r *http.Request) error {
	got, ok := p.read(r)
	if !ok {
		http.Error(w, "no such verification", http.StatusNotFound)
		return nil
	}
	list, err := p.opts.Cards.Result(got)
	if err != nil {
		return err
	}
	back, err := p.opts.Cards.Kit().HTML("button", components.Button{
		Text: msg.T("verifier.results.back.label"), Href: p.resultsPath(),
	})
	if err != nil {
		return err
	}
	return p.render(w, r, "list", components.Page{
		Title:       msg.T("verifier.results.detail.title", got.GetId()),
		Heading:     msg.T("verifier.results.detail.label"),
		Description: msg.T("verifier.results.detail.lead"),
		Content:     components.Join(back, list),
	})
}

// download writes the export of the filtered results.
func (p *Portal) download(w http.ResponseWriter, r *http.Request) error {
	filter, problem := filterOf(r.URL.Query())
	if problem != "" {
		http.Error(w, problem, http.StatusBadRequest)
		return nil
	}
	list, err := p.opts.Service.QueryAll(r.Context(), filter)
	if err != nil {
		return err
	}
	encoding := resultsv1.ExportRequest_ENCODING_CSV
	mediaType := "text/csv; charset=utf-8"
	if r.URL.Query().Get("encoding") == "json" {
		encoding = resultsv1.ExportRequest_ENCODING_JSON
		mediaType = "application/jsonl; charset=utf-8"
	}
	body, err := service.Encode(encoding, list)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", mediaType)
	w.Header().Set("Content-Disposition",
		`attachment; filename="`+export.Filename(encoding, p.opts.Now())+`"`)
	_, err = w.Write(body)
	return err
}

// publicForm renders the citizen paste form (ADR-025 decision 5).
func (p *Portal) publicForm(w http.ResponseWriter, r *http.Request) error {
	return p.renderPublic(w, r, "", nil)
}

// publicCheck evaluates a pasted presentation and stores nothing.
func (p *Portal) publicCheck(w http.ResponseWriter, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return p.renderPublic(w, r, "The form could not be read.", nil)
	}
	pasted := strings.TrimSpace(r.PostFormValue("presentation"))
	switch {
	case pasted == "":
		return p.renderPublic(w, r, "Paste a credential or a presentation first.", nil)
	case int64(len(pasted)) > p.opts.MaxPasteBytes:
		return p.renderPublic(w, r, "The pasted text is too long.", nil)
	case p.opts.Evaluate == nil:
		return p.renderPublic(w, r, "This deployment does not offer the citizen check.", nil)
	}
	got, err := p.opts.Evaluate(r.Context(), []byte(pasted))
	if err != nil {
		return p.renderPublic(w, r, "The check did not run. Try again later.", nil)
	}
	return p.renderPublic(w, r, "", got)
}

// renderPublic renders the citizen page with an optional problem and an
// optional result.
func (p *Portal) renderPublic(w http.ResponseWriter, r *http.Request, problem string,
	got *resultsv1.VerificationResult) error {
	kit := p.opts.Cards.Kit()
	field, err := kit.HTML("field", components.Field{
		ID: "presentation", Label: "Credential or presentation", Type: "textarea",
		Hint:  "Paste the text of the credential. This page stores nothing.",
		Error: problem, Required: true,
	})
	if err != nil {
		return err
	}
	check, err := kit.HTML("button", components.Button{Text: "Check", Type: "submit", Variant: "primary"})
	if err != nil {
		return err
	}
	form, err := kit.HTML("card", components.Card{
		ID: "paste", Title: "Check a credential",
		Text: "The result stays on this page. Nothing is written to a store.",
		Body: template.HTML(`<form method="post" action="`+template.HTMLEscapeString(p.opts.PublicPrefix)+`/">`) + //nolint:gosec // the prefix is escaped
			components.Join(field, check) + template.HTML(`</form>`),
	})
	if err != nil {
		return err
	}
	content := []template.HTML{form}
	if got != nil {
		list, lerr := p.opts.Cards.Result(got)
		if lerr != nil {
			return lerr
		}
		content = append(content, list)
	}
	return kit.RenderPage(w, r, components.Page{
		Title:       "Check a credential",
		Description: "Check a credential without an account.",
		Nav: components.Nav{
			Label: "Main",
			Brand: components.Link{Href: p.opts.PublicPrefix + "/", Text: "Credential check"},
			Links: []components.Link{{Href: p.opts.PublicPrefix + "/", Text: "Check", Current: true}},
		},
		Content: components.Join(content...),
	})
}

// verdictOptions returns the choices of the verdict filter.
func verdictOptions(selected string) []components.Option {
	words := []string{"", "valid", "invalid", "indeterminate"}
	out := make([]components.Option, 0, len(words))
	for _, w := range words {
		text := verdictText(verdictOf(w))
		if w == "" {
			text = msg.T("verifier.results.every_verdict.label")
		}
		out = append(out, components.Option{Value: w, Text: text, Selected: w == selected})
	}
	return out
}

// filterOf builds a filter from the query values. It returns a sentence
// when a value is not a date.
func filterOf(values url.Values) (*resultsv1.Filter, string) {
	f := &resultsv1.Filter{
		Issuer:     strings.TrimSpace(values.Get("issuer")),
		TemplateId: strings.TrimSpace(values.Get("template")),
		Verdict:    verdictOf(values.Get("verdict")),
	}
	if raw := strings.TrimSpace(values.Get("from")); raw != "" {
		t, err := time.Parse(time.DateOnly, raw)
		if err != nil {
			return nil, "Use the date form YYYY-MM-DD."
		}
		f.From = timestamppb.New(t)
	}
	if raw := strings.TrimSpace(values.Get("to")); raw != "" {
		t, err := time.Parse(time.DateOnly, raw)
		if err != nil {
			return nil, "Use the date form YYYY-MM-DD."
		}
		f.To = timestamppb.New(t.Add(24*time.Hour - time.Second))
	}
	return f, ""
}

// verdictOf maps a plain word to a verdict.
func verdictOf(word string) policyv1.EvaluateResponse_Verdict {
	switch word {
	case "valid":
		return policyv1.EvaluateResponse_VERDICT_VALID
	case "invalid":
		return policyv1.EvaluateResponse_VERDICT_INVALID
	case "indeterminate":
		return policyv1.EvaluateResponse_VERDICT_INDETERMINATE
	}
	return policyv1.EvaluateResponse_VERDICT_UNSPECIFIED
}

// TimeFormat is how the pages print a check time.
const TimeFormat = "2006-01-02 15:04 UTC"

// at returns the check time of a result as text.
func at(r *resultsv1.VerificationResult) string {
	if r.GetEvaluatedAt() == nil {
		return "not known"
	}
	return r.GetEvaluatedAt().AsTime().UTC().Format(TimeFormat)
}

// read returns one result by the id in the path. A result that is
// missing, or a store fault, gives false.
func (p *Portal) read(r *http.Request) (*resultsv1.VerificationResult, bool) {
	got, err := p.opts.Service.Read(r.Context(), r.PathValue("id"))
	if err != nil {
		return nil, false
	}
	return got, true
}
