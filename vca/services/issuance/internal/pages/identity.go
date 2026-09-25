// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// identity draws board Issuer-Identity.
func (p *Pages) identity(pg page) error {
	b := p.blocks()
	back := b.add("button", components.Button{Text: msg.T("issuer.identity.back.label"), Href: HomePath})
	if b.err != nil {
		return b.err
	}
	return p.render(pg, components.Page{
		Title: msg.T("issuer.nav.identity.label"), Lead: msg.T("issuer.identity.lead"),
		Description: msg.T("issuer.identity.lead"), Actions: back,
	})
}
