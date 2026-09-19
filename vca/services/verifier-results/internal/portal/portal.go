// SPDX-License-Identifier: Apache-2.0

// Package portal renders the pages of the verifier results service with
// the vca UI kit (ADR-025 decisions 2, 4, 5, and 6).
//
// Staff pages, under the configured prefix:
//
//	GET  /            the result list with filters and export links
//	GET  /results/{id} the card list of one result
//	GET  /export      the CSV or JSON download of the filtered results
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

	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-results/internal/cards"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-results/internal/export"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-results/internal/service"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
	"google.golang.org/protobuf/types/known/timestamppb"
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

// Register adds every page to mux.
func (p *Portal) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+p.opts.Prefix+"/{$}", p.handle(p.list))
	mux.HandleFunc("GET "+p.opts.Prefix+"/results/{id}", p.handle(p.detail))
	mux.HandleFunc("GET "+p.opts.Prefix+"/export", p.handle(p.download))
	mux.HandleFunc("GET "+p.opts.PublicPrefix+"/{$}", p.handle(p.publicForm))
	mux.HandleFunc("POST "+p.opts.PublicPrefix+"/{$}", p.handle(p.publicCheck))
}

// handle answers with a short sentence when a page fails.
func (p *Portal) handle(fn func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := fn(w, r); err != nil {
			http.Error(w, "the page could not render", http.StatusInternalServerError)
		}
	}
}

// nav returns the navigation of a staff page.
func (p *Portal) nav(current string) components.Nav {
	return components.Nav{
		Label: "Main",
		Brand: components.Link{Href: p.opts.Prefix + "/", Text: "Verifier results"},
		Links: []components.Link{
			{Href: p.opts.Prefix + "/", Text: "Verifications", Current: current == "list"},
			{Href: p.opts.PublicPrefix + "/", Text: "Citizen check", Current: current == "public"},
		},
	}
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
	return p.opts.Cards.Kit().RenderPage(w, r, components.Page{
		Title:       "Verifications",
		Description: "The verifications this deployment stored.",
		Nav:         p.nav("list"),
		Content:     components.Join(body...),
	})
}

// filterForm renders the query form and the export links.
func (p *Portal) filterForm(values url.Values, problem string) (template.HTML, error) {
	kit := p.opts.Cards.Kit()
	fields := []components.Field{
		{ID: "from", Label: "From", Type: "date", Value: values.Get("from"),
			Hint: "The earliest check date."},
		{ID: "to", Label: "To", Type: "date", Value: values.Get("to"),
			Hint: "The latest check date."},
		{ID: "verdict", Label: "Verdict", Type: "select", Value: values.Get("verdict"),
			Options: verdictOptions(values.Get("verdict"))},
		{ID: "issuer", Label: "Issuer", Value: values.Get("issuer"),
			Hint: "The issuer DID or URL."},
		{ID: "template", Label: "Template", Value: values.Get("template"),
			Hint: "The presentation template id."},
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
	apply, err := kit.HTML("button", components.Button{Text: "Apply", Type: "submit", Variant: "primary"})
	if err != nil {
		return "", err
	}
	parts = append(parts, apply)
	query := values.Encode()
	for _, e := range []struct{ encoding, text string }{{"csv", "Download CSV"}, {"json", "Download JSON"}} {
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
		Title: "Filter",
		Text:  "Narrow the list by time, verdict, issuer, or template.",
		Body: template.HTML(`<form method="get" action="`+template.HTMLEscapeString(p.opts.Prefix)+`/">`) + //nolint:gosec // the prefix is escaped
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
		ID: "results", Caption: "Verifications, newest first",
		Columns: []string{"Checked at", "Verdict", "Credentials", "Template", "Detail"},
		Empty:   "No verification matches the filter",
	}
	kit := p.opts.Cards.Kit()
	for _, r := range page {
		link, lerr := kit.HTML("button", components.Button{
			Text: "Open", Href: p.opts.Prefix + "/results/" + url.PathEscape(r.GetId()),
		})
		if lerr != nil {
			return "", lerr
		}
		table.Rows = append(table.Rows, components.Row{
			{Text: at(r)}, {Text: export.VerdictWord(r.GetVerdict())},
			{Text: fmt.Sprint(len(r.GetCredentials()))},
			{Text: r.GetTemplateId()}, {HTML: link},
		})
	}
	return kit.HTML("table", table)
}

// detail renders the card list of one result.
func (p *Portal) detail(w http.ResponseWriter, r *http.Request) error {
	got, err := p.opts.Service.Read(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, "no such verification", http.StatusNotFound)
		return nil
	}
	list, err := p.opts.Cards.Result(got)
	if err != nil {
		return err
	}
	back, err := p.opts.Cards.Kit().HTML("button", components.Button{
		Text: "Back to the list", Href: p.opts.Prefix + "/",
	})
	if err != nil {
		return err
	}
	return p.opts.Cards.Kit().RenderPage(w, r, components.Page{
		Title:       "Verification " + got.GetId(),
		Heading:     "Verification detail",
		Description: "The cards of one verification.",
		Nav:         p.nav("list"),
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
		text := w
		if w == "" {
			text = "Every verdict"
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

// at returns the check time of a result as text.
func at(r *resultsv1.VerificationResult) string {
	if r.GetEvaluatedAt() == nil {
		return "not known"
	}
	return r.GetEvaluatedAt().AsTime().UTC().Format(time.RFC3339)
}
