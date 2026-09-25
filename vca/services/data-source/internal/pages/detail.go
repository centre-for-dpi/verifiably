// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"html/template"
	"net/http"
	"strconv"

	"connectrpc.com/connect"

	datasourcev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// previewRows is the number of masked rows the preview shows.
const previewRows = 10

// typeKeys names the inferred type of a field.
var typeKeys = map[string]string{
	"string": "issuer.sources.type.text.label", "integer": "issuer.sources.type.integer.label",
	"number": "issuer.sources.type.number.label", "boolean": "issuer.sources.type.boolean.label",
	"date": "issuer.sources.type.date.label",
}

// source reads one source for a page.
func (p *Pages) source(pg page) (*datasourcev1.Source, error) {
	res, err := p.opts.Sources.Get(pg.ctx(), connect.NewRequest(&datasourcev1.GetRequest{Id: pg.r.PathValue("id")}))
	if err != nil {
		return nil, err
	}
	return res.Msg.GetSource(), nil
}

// detail draws one source: its fields with their types, and a preview
// in which the service masked every value (ADR-015 decision 4).
func (p *Pages) detail(pg page) error {
	src, err := p.source(pg)
	if err != nil {
		return err
	}
	ctx := pg.ctx()
	ref := pg.r.URL.Query().Get("schema")
	schema, withSchema, err := p.schemaOf(ctx, ref)
	if err != nil {
		return err
	}
	if !withSchema {
		ref = ""
	}
	b := p.blocks()
	var parts []template.HTML
	if withSchema {
		parts = append(parts, p.stepper(b, stepSource), p.chosen(b, schema))
	}
	fields, ferr := p.opts.Sources.PreviewFields(ctx, connect.NewRequest(&datasourcev1.PreviewFieldsRequest{SourceId: src.GetId()}))
	if roleDenied(ferr) {
		return ferr
	}
	if ferr != nil {
		parts = append(parts, b.add("block", components.Block{ID: "fields", Title: msg.T("issuer.sources.fields.label"), Lead: msg.T("issuer.sources.read.failed")}))
	} else {
		parts = append(parts, p.fieldsBlock(b, fields.Msg.GetFields()), p.previewBlock(pg, b, src, fields.Msg.GetFields()))
	}
	mapLabel := msg.T("issuer.sources.map.label")
	actions := components.Join(
		b.add("button", components.Button{Text: mapLabel, Href: sourcePath(src.GetId(), "/map", ref), Variant: "primary"}),
		b.add("button", components.Button{Text: msg.T("issuer.sources.back.label"), Href: listPath(ref), Variant: "ghost"}),
	)
	parts = append(parts, b.add("block", components.Block{ID: "delete", Title: msg.T("issuer.sources.delete.title.label"), Lead: msg.T("issuer.sources.delete.lead"),
		Body: form(pg, sourcePath(src.GetId(), "/delete", ""), false,
			b.add("button", components.Button{Text: msg.T("issuer.sources.delete.label"), Type: "submit", Variant: "danger"}))}))
	if b.err != nil {
		return b.err
	}
	return p.render(pg, components.Page{
		Title: src.GetDisplayName(), Lead: msg.T("issuer.sources.detail.lead", kindLabel(src)), Actions: actions,
		Content: components.Join(parts...),
	})
}

// fieldsBlock lists the fields with their inferred types and a masked
// example.
func (p *Pages) fieldsBlock(b *blocks, fields []*datasourcev1.Field) template.HTML {
	rows := make([]components.Row, 0, len(fields))
	for _, f := range fields {
		rows = append(rows, components.Row{{Text: f.GetName()}, {Text: msg.T(typeKeys[f.GetType()])}, {HTML: code(f.GetExample())}})
	}
	return b.add("block", components.Block{ID: "fields", Title: msg.T("issuer.sources.fields.label"), Lead: msg.T("issuer.sources.fields.lead"),
		Body: b.add("table", components.Table{ID: "field-list", Caption: msg.T("issuer.sources.fields.caption.label", strconv.Itoa(len(fields))),
			Columns: []string{msg.T("issuer.sources.column.field.label"), msg.T("issuer.sources.column.type.label"), msg.T("issuer.sources.column.example.label")},
			Rows:    rows})})
}

// previewBlock shows the first rows with every value masked. A role
// without the preview rule sees a sentence instead.
func (p *Pages) previewBlock(pg page, b *blocks, src *datasourcev1.Source, fields []*datasourcev1.Field) template.HTML {
	res, err := p.opts.Sources.PreviewRows(pg.ctx(), connect.NewRequest(&datasourcev1.PreviewRowsRequest{SourceId: src.GetId(), Limit: previewRows}))
	if err != nil {
		lead := msg.T("issuer.sources.read.failed")
		if roleDenied(err) {
			lead = msg.T("issuer.sources.preview.denied")
		}
		return b.add("block", components.Block{ID: "preview", Title: msg.T("issuer.sources.preview.label"), Lead: lead})
	}
	columns := make([]string, 0, len(fields))
	for _, f := range fields {
		columns = append(columns, f.GetName())
	}
	if len(columns) == 0 {
		columns = []string{msg.T("issuer.sources.column.field.label")}
	}
	rows := make([]components.Row, 0, len(res.Msg.GetRows()))
	for _, r := range res.Msg.GetRows() {
		row := make(components.Row, 0, len(fields))
		for _, f := range fields {
			row = append(row, components.Cell{HTML: code(r.GetValues()[f.GetName()])})
		}
		rows = append(rows, row)
	}
	total := res.Msg.GetTotalRows()
	return b.add("block", components.Block{ID: "preview", Title: msg.T("issuer.sources.preview.label"),
		Lead: msg.T("issuer.sources.preview.lead"), Meta: msg.T("issuer.sources.preview.meta.label", strconv.Itoa(len(rows)), strconv.FormatInt(total, 10)),
		Body: b.add("table", components.Table{ID: "preview-rows", Caption: msg.T("issuer.sources.preview.caption.label"), Columns: columns, Rows: rows,
			Empty: msg.T("issuer.sources.preview.empty")})})
}

// code shows a value in the monospace stack.
func code(text string) template.HTML {
	return template.HTML(`<code>`+template.HTMLEscapeString(text)) + template.HTML(`</code>`) //nolint:gosec // the text is escaped
}

// remove deletes a source and goes back to the list.
func (p *Pages) remove(pg page) error {
	if !canIssue(pg.r.Context()) {
		return errForbidden
	}
	if _, err := p.opts.Sources.Delete(pg.ctx(), connect.NewRequest(&datasourcev1.DeleteRequest{Id: pg.r.PathValue("id")})); err != nil {
		return err
	}
	http.Redirect(pg.w, pg.r, Prefix, http.StatusSeeOther)
	return nil
}
