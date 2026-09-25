// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"html/template"
	"net/http"
	"net/url"
	"strconv"

	"connectrpc.com/connect"

	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	tmpl "github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/template"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// exchangeList renders the DIF Presentation Exchange 2.0 form of every
// saved query, for the stacks that read only that form (ADR-042).
func (p *Portal) exchangeList(w http.ResponseWriter, r *http.Request) error {
	resp, err := p.opts.Client.ListTemplates(r.Context(), connect.NewRequest(&discoveryv1.ListTemplatesRequest{}))
	if err != nil {
		return err
	}
	b := p.blocks()
	parts := make([]template.HTML, 0, len(resp.Msg.GetTemplates())+1)
	for i, t := range resp.Msg.GetTemplates() {
		record := tmpl.Template{ID: t.GetId(), DCQL: t.GetDcql(), Purpose: t.GetPurpose()}
		var body template.HTML
		if data, perr := record.PresentationExchange(); perr == nil {
			body = b.add("json", components.JSON{
				ID: "pe-" + strconv.Itoa(i+1), Summary: msg.T("verifier.pe.definition.label"), Data: rawJSON(string(data)),
			})
		} else {
			body = template.HTML(`<p>` + template.HTMLEscapeString(msg.T("verifier.pe.lossy")) + `</p>`) //nolint:gosec // the text is escaped
		}
		body += b.add("button", components.Button{
			Text: msg.T("verifier.pe.open.label"), Href: p.opts.Prefix + "/templates/" + url.PathEscape(t.GetId()),
		})
		parts = append(parts, b.add("block", components.Block{
			ID: "query-" + strconv.Itoa(i+1), Title: t.GetDisplayName(), Lead: queryText(t),
			Meta: msg.T("verifier.pe.version.label", strconv.Itoa(int(t.GetVersion()))), Body: body,
		}))
	}
	if len(parts) == 0 {
		parts = append(parts, b.add("empty", components.Empty{
			Title: msg.T("verifier.pe.empty.title"), Text: msg.T("verifier.pe.empty.text"),
			Action: components.Button{Text: msg.T("verifier.overview.new_query.label"), Href: p.opts.Prefix + "/types", Variant: "primary"},
		}))
	}
	if b.err != nil {
		return b.err
	}
	return p.render(w, r, "templates", components.Page{
		Title: msg.T("verifier.nav.pe.label"), Lead: msg.T("verifier.pe.lead"), Description: msg.T("verifier.pe.lead"),
		Content: components.Join(parts...),
	})
}
