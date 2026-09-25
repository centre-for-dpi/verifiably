// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"context"
	"encoding/base64"
	"html/template"
	"strings"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// maxRenderBytes caps an SVG template the page embeds.
const maxRenderBytes = 256 << 10

// displayBlock shows how a wallet shows the credential: the display
// entries of the version, then the card templates the stack renders the
// type with. A template goes in as an image from a data URL, so no
// script of the stack runs in the page.
func (p *Portal) displayBlock(ctx context.Context, m *schemav1.Schema, t target) (template.HTML, error) {
	rows := make([]components.Row, 0, len(m.GetDisplay()))
	for _, d := range m.GetDisplay() {
		rows = append(rows, components.Row{
			{Text: d.GetName()}, {Text: dash(d.GetLocale())}, {Text: dash(d.GetBackgroundColor())},
			{Text: dash(d.GetTextColor())}, {Text: dash(d.GetLogoUri())},
		})
	}
	table, err := p.opts.Kit.HTML("table", components.Table{
		ID: "display-table", Caption: msg.T("issuer.schemas.display.caption.label"),
		Columns: []string{
			msg.T("issuer.schemas.display.column.name.label"), msg.T("issuer.schemas.display.column.locale.label"),
			msg.T("issuer.schemas.display.column.background.label"), msg.T("issuer.schemas.display.column.text.label"),
			msg.T("issuer.schemas.display.column.logo.label"),
		},
		Rows: rows, Empty: msg.T("issuer.schemas.display.none"),
	})
	if err != nil {
		return "", err
	}
	parts := []template.HTML{table}
	for _, r := range p.renders(ctx, m) {
		name := r.GetName()
		if name == "" {
			name = Name(m)
		}
		stack := t.name
		if stack == "" {
			stack = msg.T("issuer.stack.this.label")
		}
		src := "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(r.GetContent()))
		parts = append(parts, template.HTML(`<h3>`+template.HTMLEscapeString(msg.T("issuer.schemas.display.render.label"))+`</h3>`+ //nolint:gosec // every part is escaped
			`<p>`+template.HTMLEscapeString(msg.T("issuer.schemas.display.render.text", stack))+`</p>`+
			`<img src="`+template.HTMLEscapeString(src)+`" alt="`+template.HTMLEscapeString(msg.T("issuer.schemas.display.render.alt", name, stack))+`">`+
			`<p>`), link(r.GetUrl(), msg.T("issuer.schemas.display.render.link.label")), template.HTML(`</p>`))
	}
	return p.opts.Kit.HTML("card", components.Card{
		ID: "display", Title: msg.T("issuer.schemas.display.title.label"), Text: msg.T("issuer.schemas.display.lead"),
		Body: components.Join(parts...),
	})
}

// renders returns the SVG templates the stack keeps for the type of a
// published version. A draft has no configuration on the stack, and a
// failed call shows nothing.
func (p *Portal) renders(ctx context.Context, m *schemav1.Schema) []*backendv1.RenderTemplate {
	if p.opts.Catalog == nil || m.GetState() != schemav1.State_STATE_PUBLISHED {
		return nil
	}
	res, err := p.opts.Catalog.GetIssuerMetadata(ctx, connect.NewRequest(&backendv1.GetIssuerMetadataRequest{}))
	if err != nil {
		return nil
	}
	var out []*backendv1.RenderTemplate
	seen := map[string]bool{}
	for _, c := range res.Msg.GetConfigurations() {
		if c.GetType() != m.GetType() {
			continue
		}
		for _, r := range c.GetRenderTemplates() {
			svg := r.GetContent()
			if seen[r.GetUrl()] || len(svg) > maxRenderBytes || !strings.Contains(svg, "<svg") {
				continue
			}
			seen[r.GetUrl()] = true
			out = append(out, r)
		}
	}
	return out
}

// dash returns v, or a dash for an empty value.
func dash(v string) string {
	if v == "" {
		return "-"
	}
	return v
}
