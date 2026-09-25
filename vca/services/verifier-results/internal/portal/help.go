// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"html/template"
	"net/http"
	"strconv"
	"strings"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1/discoveryv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1/ingestv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1/policyv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1/resultsv1connect"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/internal/rolenav"
	"github.com/centre-for-dpi/vc-adapters/services/internal/helptext"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// DefaultDocsURL is the docs folder of the repository. The help page
// links each document under it.
const DefaultDocsURL = "https://github.com/centre-for-dpi/verifiably/tree/main/vca/docs"

// helpServices are the services a verifier calls, in the order of the
// work: queries, requests, checks, results.
var helpServices = []struct {
	name  string
	label string
}{
	{discoveryv1connect.DiscoveryServiceName, "verifier.nav.discover.label"},
	{ingestv1connect.IngestServiceName, "verifier.nav.requests.label"},
	{policyv1connect.PolicyServiceName, "verifier.help.checks.label"},
	{resultsv1connect.ResultsServiceName, "verifier.nav.results.label"},
}

// helpPages says what each verifier page does and which document covers
// it, by the path of the page in internal/rolenav.
var helpPages = map[string]struct{ key, doc string }{
	"/portal/":         {"verifier.help.page.overview", "verifier-results.md"},
	"/discovery/":      {"verifier.help.page.discover", "verifier-discovery.md"},
	"/discovery/dcql/": {"verifier.help.page.dcql", "verifier-discovery.md"},
	"/discovery/pe/":   {"verifier.help.page.pe", "verifier-discovery.md"},
	"/scan/":           {"verifier.help.page.requests", "verifier-ingest.md"},
	"/portal/results/": {"verifier.help.page.results", "verifier-results.md"},
	"/portal/cache/":   {"verifier.help.page.cache", "verifier-policy.md"},
	"/portal/help/":    {"verifier.help.page.help", "verifier-results.md"},
}

// help lists what each verifier page does with a link to its document,
// then every verifier RPC with the help text of its proto file (ADR-009
// decision 3).
func (p *Portal) help(w http.ResponseWriter, r *http.Request) error {
	b := &blocks{kit: p.opts.Cards.Kit()}
	parts := []template.HTML{p.helpPages(r, b)}
	for i, s := range helpServices {
		entries := helptext.Service(s.name)
		rows := make([]components.Row, 0, len(entries))
		for _, e := range entries {
			rows = append(rows, components.Row{{Text: e.Method}, {Text: e.Description}})
		}
		parts = append(parts, b.add("table", components.Table{
			ID:      "rpcs-" + strconv.Itoa(i+1),
			Caption: msg.T("verifier.help.caption.label", msg.T(s.label), strconv.Itoa(len(rows))),
			Columns: []string{msg.T("verifier.help.column.rpc.label"), msg.T("verifier.help.column.text.label")},
			Rows:    rows,
		}))
	}
	if b.err != nil {
		return b.err
	}
	return p.render(w, r, "help", components.Page{
		Title: msg.T("common.help.label"), Lead: msg.T("verifier.help.lead"), Description: msg.T("verifier.help.lead"),
		Content: components.Join(parts...),
	})
}

// helpPages is the block of the verifier pages this deployment shows.
func (p *Portal) helpPages(r *http.Request, b *blocks) template.HTML {
	docs := strings.TrimRight(p.opts.DocsURL, "/")
	if docs == "" {
		docs = DefaultDocsURL
	}
	var has rolenav.Has
	if p.opts.Shell != nil {
		has = p.opts.Shell.Frame(r.Context()).Has
	}
	var rows []components.Row
	for _, s := range rolenav.Visible(commonv1.Role_ROLE_VERIFIER, has) {
		for _, page := range s.Pages {
			info, ok := helpPages[page.Path]
			if !ok {
				continue
			}
			rows = append(rows, components.Row{
				{HTML: link(page.Path, page.Label())}, {Text: msg.T(info.key)}, {HTML: link(docs+"/"+info.doc, info.doc)},
			})
		}
	}
	return b.add("block", components.Block{
		ID: "pages", Title: msg.T("verifier.help.pages.label"),
		Body: b.add("table", components.Table{
			ID: "page-list", Caption: msg.T("verifier.help.pages.caption.label", strconv.Itoa(len(rows))),
			Columns: []string{
				msg.T("verifier.help.column.page.label"), msg.T("verifier.help.column.text.label"), msg.T("verifier.help.column.doc.label"),
			},
			Rows: rows,
		}),
	})
}
