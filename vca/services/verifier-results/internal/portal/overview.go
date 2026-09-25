// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// The pages of the other verifier services on the same host, from the
// verifier navigation of internal/rolenav.
const (
	// DiscoveryPath is the schema discovery of verifier-discovery.
	DiscoveryPath = "/discovery/"
	// QueriesPath is the list of saved queries.
	QueriesPath = "/discovery/templates"
	// NewQueryPath is the DCQL builder, where a new query starts.
	NewQueryPath = "/discovery/dcql/"
	// RequestsPath is the request and scanner page of verifier-ingest.
	RequestsPath = "/scan/"
)

// The overview caps its lists.
const (
	overviewSchemas = 6
	overviewResults = 5
	overviewClaims  = 6
)

// overview draws board Verifier-Portal: the saved queries, the open
// requests, the trust cache state, the schemas the catalogue offers, and
// the recent results. A URL with a query is an old link to the result
// list, so it moves there with the query kept.
func (p *Portal) overview(w http.ResponseWriter, r *http.Request) error {
	if r.URL.RawQuery != "" {
		http.Redirect(w, r, p.resultsPath()+"?"+r.URL.RawQuery, http.StatusMovedPermanently)
		return nil
	}
	b := &blocks{kit: p.opts.Cards.Kit()}
	names := p.templateNames(r)
	actions := components.Join(
		b.add("button", components.Button{Text: msg.T("verifier.overview.new_query.label"), Href: NewQueryPath}),
		b.add("button", components.Button{Text: msg.T("verifier.overview.new_request.label"), Href: RequestsPath, Variant: "primary"}),
	)
	stats := components.Join(
		b.add("stat", queriesStat(names)),
		b.add("stat", p.requestsStat(r)),
		b.add("stat", p.cacheStat(r)),
	)
	schemas := p.schemasBlock(r, b)
	recent := p.recentBlock(r, b, names)
	if b.err != nil {
		return b.err
	}
	return p.render(w, r, "overview", components.Page{
		Title: msg.T("common.overview.label"), Lead: msg.T("verifier.overview.lead"), Description: msg.T("verifier.overview.lead"),
		Actions: actions,
		Content: components.Join(template.HTML(`<div class="stats">`), stats, template.HTML(`</div>`), schemas, recent),
	})
}

// savedQueries are the saved queries of the discovery service: the
// name of each id and the count of each kind. A nil value means the
// service did not answer.
type savedQueries struct {
	names    map[string]string
	dcql, pe int
}

// templateNames reads the saved queries, or nil when the discovery
// service does not answer.
func (p *Portal) templateNames(r *http.Request) *savedQueries {
	if p.opts.Discovery == nil {
		return nil
	}
	res, err := p.opts.Discovery.ListTemplates(r.Context(), connect.NewRequest(&discoveryv1.ListTemplatesRequest{}))
	if err != nil {
		return nil
	}
	out := &savedQueries{names: make(map[string]string, len(res.Msg.GetTemplates()))}
	for _, t := range res.Msg.GetTemplates() {
		out.names[t.GetId()] = t.GetDisplayName()
		if t.GetKind() == discoveryv1.TemplateKind_TEMPLATE_KIND_PE {
			out.pe++
			continue
		}
		out.dcql++
	}
	return out
}

// name returns the name of a saved query, or its id.
func (q *savedQueries) name(id string) string {
	if q != nil && q.names[id] != "" {
		return q.names[id]
	}
	return id
}

// queriesStat is the card of the saved queries by kind.
func queriesStat(q *savedQueries) components.Stat {
	s := components.Stat{Label: msg.T("verifier.stat.queries.label"), Text: msg.T("verifier.stat.queries.text"), Href: QueriesPath}
	if q == nil {
		s.Value = msg.T("common.unknown.label")
		return s
	}
	s.Value = msg.T("verifier.stat.queries.value.label", strconv.Itoa(q.dcql), strconv.Itoa(q.pe))
	return s
}

// requestsStat is the card of the requests that wait for a wallet.
func (p *Portal) requestsStat(r *http.Request) components.Stat {
	s := components.Stat{Label: msg.T("verifier.stat.requests.label"), Text: msg.T("verifier.stat.requests.text"), Href: RequestsPath}
	s.Value = msg.T("common.unknown.label")
	if p.opts.Requests == nil {
		return s
	}
	res, err := p.opts.Requests.ListTransactions(r.Context(), connect.NewRequest(&ingestv1.ListTransactionsRequest{
		State: ingestv1.GetTransactionResponse_STATE_PENDING, Page: &commonv1.Pagination{PageSize: 1},
	}))
	if err == nil {
		s.Value = msg.T("verifier.stat.requests.value.label", strconv.FormatInt(res.Msg.GetPage().GetTotalSize(), 10))
	}
	return s
}

// schemasBlock lists the credential types a request can ask for, with
// their claims and a link that starts a query.
func (p *Portal) schemasBlock(r *http.Request, b *blocks) template.HTML {
	var rows []components.Row
	if p.opts.Discovery != nil {
		res, err := p.opts.Discovery.ListCredentialTypes(r.Context(), connect.NewRequest(&discoveryv1.ListCredentialTypesRequest{}))
		if err == nil {
			types := res.Msg.GetTypes()
			if len(types) > overviewSchemas {
				types = types[:overviewSchemas]
			}
			for _, t := range types {
				rows = append(rows, p.schemaRow(r, b, t))
			}
		}
	}
	return b.add("block", components.Block{
		ID: "schemas", Title: msg.T("verifier.overview.schemas.label"),
		Body: b.add("table", components.Table{
			ID: "schema-list", Caption: msg.T("verifier.overview.schemas.caption.label"),
			Columns: []string{
				msg.T("verifier.results.issuer.label"), msg.T("verifier.overview.credential.label"),
				msg.T("verifier.overview.format.label"), msg.T("verifier.overview.claims.label"), msg.T("verifier.results.query.label"),
			},
			Rows: rows, Empty: msg.T("verifier.overview.schemas.none"),
		}),
	})
}

// schemaRow is one credential type of the catalogue.
func (p *Portal) schemaRow(r *http.Request, b *blocks, t *discoveryv1.CredentialType) components.Row {
	format := formatName(t.GetFormat())
	claims := ""
	fields, err := p.opts.Discovery.GetFields(r.Context(), connect.NewRequest(&discoveryv1.GetFieldsRequest{
		CredentialIssuer: t.GetCredentialIssuer(), Type: t.GetType(),
	}))
	if err == nil {
		var paths []string
		for _, f := range fields.Msg.GetFields() {
			paths = append(paths, f.GetPath())
		}
		if len(paths) > overviewClaims {
			paths = append(paths[:overviewClaims], msg.T("verifier.overview.more.label", strconv.Itoa(len(paths)-overviewClaims)))
		}
		claims = strings.Join(paths, ", ")
	}
	href := NewQueryPath + "?credential_issuer=" + url.QueryEscape(t.GetCredentialIssuer()) +
		"&type=" + url.QueryEscape(t.GetType()) + "&format=" + url.QueryEscape(format)
	return components.Row{
		{Text: t.GetCredentialIssuer()}, {Text: t.GetType()}, {Text: format}, {Text: claims},
		{HTML: b.add("button", components.Button{Text: msg.T("verifier.overview.build.label"), Href: href})},
	}
}

// recentBlock lists the newest results with the query, the issuer, and
// the verdict with the reason of the first failed check.
func (p *Portal) recentBlock(r *http.Request, b *blocks, names *savedQueries) template.HTML {
	list, err := p.opts.Service.QueryAll(r.Context(), &resultsv1.Filter{})
	if err != nil {
		list = nil
	}
	if len(list) > overviewResults {
		list = list[:overviewResults]
	}
	rows := make([]components.Row, 0, len(list))
	for _, res := range list {
		query := names.name(res.GetTemplateId())
		issuer := ""
		if creds := res.GetCredentials(); len(creds) > 0 {
			issuer = creds[0].GetIssuerName()
			if issuer == "" {
				issuer = creds[0].GetIssuer()
			}
		}
		verdict := b.add("badge", components.Badge{Status: verdictStatus(res.GetVerdict()), Text: verdictText(res.GetVerdict())})
		if reason := failReason(res); reason != "" {
			verdict += template.HTML(" ") + template.HTML(template.HTMLEscapeString(reason)) //nolint:gosec // the reason is escaped
		}
		rows = append(rows, components.Row{
			{HTML: link(p.resultsPath()+url.PathEscape(res.GetId()), at(res))}, {Text: query}, {Text: issuer}, {HTML: verdict},
		})
	}
	return b.add("block", components.Block{
		ID: "recent", Title: msg.T("verifier.overview.recent.label"),
		Body: b.add("table", components.Table{
			ID: "recent-results", Caption: msg.T("verifier.overview.recent.caption.label"),
			Columns: []string{
				msg.T("common.when.label"), msg.T("verifier.results.query.label"),
				msg.T("verifier.results.issuer.label"), msg.T("verifier.overview.result.label"),
			},
			Rows: rows, Empty: msg.T("verifier.results.empty.text"),
		}) + b.add("button", components.Button{Text: msg.T("verifier.overview.all_results.label"), Href: p.resultsPath()}),
	})
}

// failReason returns the detail of the first failed check of a result,
// or "".
func failReason(res *resultsv1.VerificationResult) string {
	checks := res.GetChecks()
	for _, c := range res.GetCredentials() {
		checks = append(checks, c.GetChecks()...)
	}
	for _, c := range checks {
		if c.GetOutcome() == policyv1.Outcome_OUTCOME_FAIL {
			return c.GetDetail()
		}
	}
	return ""
}

// verdictText returns the reader facing word of a verdict.
func verdictText(v policyv1.EvaluateResponse_Verdict) string {
	switch v {
	case policyv1.EvaluateResponse_VERDICT_VALID:
		return msg.T("verifier.verdict.valid.label")
	case policyv1.EvaluateResponse_VERDICT_INVALID:
		return msg.T("verifier.verdict.invalid.label")
	case policyv1.EvaluateResponse_VERDICT_INDETERMINATE:
		return msg.T("verifier.verdict.indeterminate.label")
	}
	return msg.T("common.unknown.label")
}

// verdictStatus returns the badge status of a verdict.
func verdictStatus(v policyv1.EvaluateResponse_Verdict) string {
	switch v {
	case policyv1.EvaluateResponse_VERDICT_VALID:
		return "ok"
	case policyv1.EvaluateResponse_VERDICT_INVALID:
		return "bad"
	case policyv1.EvaluateResponse_VERDICT_INDETERMINATE:
		return "warn"
	}
	return "info"
}

// formatName returns the wire name of a format.
func formatName(f commonv1.Format) string {
	switch f {
	case commonv1.Format_FORMAT_VC_SD_JWT:
		return "vc+sd-jwt"
	case commonv1.Format_FORMAT_DC_SD_JWT:
		return "dc+sd-jwt"
	case commonv1.Format_FORMAT_JWT_VC_JSON:
		return "jwt_vc_json"
	case commonv1.Format_FORMAT_LDP_VC:
		return "ldp_vc"
	case commonv1.Format_FORMAT_MSO_MDOC:
		return "mso_mdoc"
	}
	return ""
}

// link renders one anchor. Both parts are escaped.
func link(href, text string) template.HTML {
	return template.HTML(`<a href="` + template.HTMLEscapeString(href) + `">` + template.HTMLEscapeString(text) + `</a>`) //nolint:gosec // both parts are escaped
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
