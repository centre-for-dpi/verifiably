// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"html/template"
	"strconv"

	"github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1/issuancev1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1/issuedv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1/schemav1connect"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/helptext"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// helpServices are the services an issuer calls, in the order of the
// work: schemas, issuance, issued credentials.
var helpServices = []struct {
	name  string
	label string
}{
	{schemav1connect.SchemaServiceName, "issuer.nav.schemas.label"},
	{issuancev1connect.IssuanceServiceName, "issuer.nav.issue.label"},
	{issuedv1connect.IssuedServiceName, "issuer.nav.issued.label"},
}

// help lists every issuer RPC with the help text of its proto file
// (ADR-009 decision 3). The CLI shows the same sentences.
func (p *Pages) help(pg page) error {
	b := p.blocks()
	parts := []template.HTML{b.add("card", components.Card{
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
