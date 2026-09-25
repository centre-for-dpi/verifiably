// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"html/template"
	"strconv"
	"strings"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1/datasourcev1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1/issuancev1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1/issuedv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1/schemav1connect"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/internal/rolenav"
	"github.com/centre-for-dpi/vc-adapters/services/internal/helptext"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// DefaultDocsURL is the docs folder of the repository. The help page
// links each document under it.
const DefaultDocsURL = "https://github.com/centre-for-dpi/verifiably/tree/main/vca/docs"

// helpServices are the services an issuer calls, in the order of the
// work: schemas, issuance, bulk sources, issued credentials.
var helpServices = []struct {
	name  string
	label string
}{
	{schemav1connect.SchemaServiceName, "issuer.nav.schemas.label"},
	{issuancev1connect.IssuanceServiceName, "issuer.nav.issue.label"},
	{datasourcev1connect.DataSourceServiceName, "issuer.nav.sources.label"},
	{issuedv1connect.IssuedServiceName, "issuer.nav.issued.label"},
}

// helpPages says what each issuer page does and which document covers
// it, by the path of the page in internal/rolenav.
var helpPages = map[string]struct{ key, doc string }{
	"/issuer/":        {"issuer.help.page.overview", "issuance.md"},
	"/identity/":      {"issuer.help.page.identity", "issuance.md"},
	"/portal/":        {"issuer.help.page.schemas", "schema-registry.md"},
	"/builder/":       {"issuer.help.page.builder", "schema-builder-ui.md"},
	"/issue/":         {"issuer.help.page.issue", "issuance.md"},
	"/sources/":       {"issuer.help.page.sources", "data-source.md"},
	"/issued/":        {"issuer.help.page.issued", "issued-credentials.md"},
	"/notifications/": {"issuer.help.page.notifications", "issuance.md"},
	"/help/":          {"issuer.help.page.help", "issuance.md"},
}

// help lists what each issuer page does with a link to its document,
// then every issuer RPC with the help text of its proto file (ADR-009
// decision 3). The CLI shows the same sentences.
func (p *Pages) help(pg page) error {
	b := p.blocks()
	parts := []template.HTML{p.helpPages(b, pg), b.add("card", components.Card{
		ID: "intro", Title: msg.T("issuer.help.intro.label"), Text: msg.T("issuer.help.intro.text"),
	})}
	for i, s := range helpServices {
		entries := helptext.Service(s.name)
		rows := make([]components.Row, 0, len(entries))
		for _, e := range entries {
			rows = append(rows, components.Row{{Text: e.Method}, {Text: e.Description}})
		}
		parts = append(parts, b.add("table", components.Table{
			ID:      "rpcs-" + strconv.Itoa(i+1),
			Caption: msg.T("issuer.help.caption.label", msg.T(s.label), strconv.Itoa(len(rows))),
			Columns: []string{msg.T("issuer.help.column.rpc.label"), msg.T("issuer.help.column.text.label")},
			Rows:    rows, Empty: msg.T("issuer.help.none"),
		}))
	}
	if b.err != nil {
		return b.err
	}
	return p.render(pg, components.Page{
		Title: msg.T("common.help.label"), Lead: msg.T("issuer.help.lead"), Description: msg.T("issuer.help.lead"),
		Content: components.Join(parts...),
	})
}

// helpPages is the block of the issuer pages this deployment shows, with
// what each does and its document.
func (p *Pages) helpPages(b *blocks, pg page) template.HTML {
	docs := strings.TrimRight(p.opts.DocsURL, "/")
	if docs == "" {
		docs = DefaultDocsURL
	}
	var rows []components.Row
	for _, s := range rolenav.Visible(commonv1.Role_ROLE_ISSUER, pg.f.Has) {
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
		ID: "pages", Title: msg.T("issuer.help.pages.label"), Lead: msg.T("issuer.help.pages.lead"),
		Body: b.add("table", components.Table{
			ID: "page-list", Caption: msg.T("issuer.help.pages.caption.label", strconv.Itoa(len(rows))),
			Columns: []string{
				msg.T("issuer.help.column.page.label"), msg.T("issuer.help.column.text.label"), msg.T("issuer.help.column.doc.label"),
			},
			Rows: rows,
		}),
	})
}
