// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"html/template"
	"net/url"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	datasourcev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/ui/components"

	"connectrpc.com/connect"
)

// maxSources caps the sources the list shows.
const maxSources = 50

// dateLayout shows the day of a change.
const dateLayout = "2 Jan 2006"

// list draws the sources of the pair. With a schema in the query, the
// page is the source step of a bulk run: each row starts the field map.
func (p *Pages) list(pg page) error {
	ctx := pg.ctx()
	ref := pg.r.URL.Query().Get("schema")
	schema, withSchema, err := p.schemaOf(ctx, ref)
	if err != nil {
		return err
	}
	if !withSchema {
		ref = ""
	}
	res, err := p.opts.Sources.List(ctx, connect.NewRequest(&datasourcev1.ListRequest{Page: &commonv1.Pagination{PageSize: maxSources}}))
	if err != nil {
		return err
	}
	b := p.blocks()
	var parts []template.HTML
	if withSchema {
		parts = append(parts, p.stepper(b, stepSource), p.chosen(b, schema))
	}
	add := p.addButtons(b, ref)
	sources := res.Msg.GetSources()
	if len(sources) == 0 {
		parts = append(parts, b.add("empty", components.Empty{
			Title: msg.T("issuer.sources.empty.title"), Text: msg.T("issuer.sources.empty.text"),
			Action: components.Button{Text: msg.T("issuer.sources.add.csv.label"), Href: newPath("csv", ref), Variant: "primary"},
		}))
	} else {
		rows := make([]components.Row, 0, len(sources))
		for _, s := range sources {
			action := link(sourcePath(s.GetId(), "", ""), msg.T("common.open.label"))
			if withSchema {
				action = link(sourcePath(s.GetId(), "/map", ref), msg.T("issuer.sources.use.label"))
			}
			rows = append(rows, components.Row{
				{HTML: link(sourcePath(s.GetId(), "", ref), s.GetDisplayName())}, {Text: kindLabel(s)},
				{Text: s.GetUpdatedAt().AsTime().Format(dateLayout)}, {HTML: action},
			})
		}
		lead := msg.T("issuer.sources.list.lead")
		if withSchema {
			lead = msg.T("issuer.sources.list.pick", schemaName(schema))
		}
		parts = append(parts, b.add("block", components.Block{ID: "sources", Title: msg.T("issuer.sources.list.label"), Lead: lead,
			Body: b.add("table", components.Table{ID: "source-list", Caption: msg.T("issuer.sources.caption.label"),
				Columns: []string{msg.T("issuer.sources.column.name.label"), msg.T("issuer.sources.column.kind.label"),
					msg.T("issuer.sources.column.updated.label"), msg.T("issuer.issue.column.action.label")},
				Rows: rows})}))
	}
	if b.err != nil {
		return b.err
	}
	return p.render(pg, components.Page{
		Title: msg.T("issuer.nav.sources.label"), Lead: msg.T("issuer.sources.lead"), Actions: add,
		Content: components.Join(parts...),
	})
}

// addButtons returns the three buttons that add a source.
func (p *Pages) addButtons(b *blocks, ref string) template.HTML {
	return components.Join(
		b.add("button", components.Button{Text: msg.T("issuer.sources.add.csv.label"), Href: newPath("csv", ref), Variant: "primary"}),
		b.add("button", components.Button{Text: msg.T("issuer.sources.add.sql.label"), Href: newPath("sql", ref)}),
		b.add("button", components.Button{Text: msg.T("issuer.sources.add.http.label"), Href: newPath("http", ref)}),
	)
}

// newPath returns the path of the form of one kind of source.
func newPath(kind, ref string) string {
	q := url.Values{"kind": {kind}}
	if ref != "" {
		q.Set("schema", ref)
	}
	return NewPath + "?" + q.Encode()
}
