// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"html/template"
	"strconv"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// counts are the numbers of the overview. A negative count means the
// service did not answer.
type counts struct {
	published int
	issued    int
}

// overview draws board Issuer-Portal.
func (p *Pages) overview(pg page) error {
	caps := p.caps(pg)
	c := p.counts(pg)
	b := p.blocks()
	actions := components.Join(
		b.add("button", components.Button{Text: msg.T("issuer.overview.publish.label"), Href: BuilderPath}),
		b.add("button", components.Button{Text: msg.T("issuer.overview.issue.label"), Href: IssuePath, Variant: "primary"}),
	)
	stats := components.Join(
		b.add("stat", c.schemaStat()),
		b.add("stat", c.issuedStat()),
	)
	if b.err != nil {
		return b.err
	}
	lead := msg.T("issuer.overview.lead", stackName(caps))
	return p.render(pg, components.Page{
		Title: msg.T("common.overview.label"), Lead: lead, Description: lead, Actions: actions,
		Content: template.HTML(`<div class="stats">`) + stats + template.HTML(`</div>`), //nolint:gosec // literal wrappers around kit output
	})
}

// counts reads the published schemas and the issued credentials. Each
// call to the issued credentials service names the staff member.
func (p *Pages) counts(pg page) counts {
	c := counts{published: -1, issued: -1}
	ctx := pg.r.Context()
	if p.opts.Schemas != nil {
		res, err := p.opts.Schemas.List(ctx, staffshell.AsActor(ctx, &schemav1.ListRequest{
			State: schemav1.State_STATE_PUBLISHED, Page: &commonv1.Pagination{PageSize: 1},
		}))
		if err == nil {
			c.published = int(res.Msg.GetPage().GetTotalSize())
		}
	}
	if p.opts.Issued != nil {
		res, err := p.opts.Issued.List(ctx, staffshell.AsActor(ctx, &issuedv1.ListRequest{
			Page: &commonv1.Pagination{PageSize: 1},
		}))
		if err == nil {
			c.issued = int(res.Msg.GetPage().GetTotalSize())
		}
	}
	return c
}

// schemaStat is the card of the published schemas.
func (c counts) schemaStat() components.Stat {
	s := components.Stat{Label: msg.T("issuer.nav.schemas.label"), Href: SchemasPath, LinkText: msg.T("issuer.stat.schemas.link.label")}
	switch {
	case c.published < 0:
		s.Value = msg.T("common.unknown.label")
	case c.published == 0:
		s.Value = msg.T("issuer.stat.schemas.none.label")
	default:
		s.Value = msg.T("issuer.stat.schemas.value.label", strconv.Itoa(c.published))
	}
	return s
}

// issuedStat is the card of the issued credentials. With nothing issued
// it leads to the issue page.
func (c counts) issuedStat() components.Stat {
	s := components.Stat{Label: msg.T("issuer.stat.issued.label"), Href: IssuePath, LinkText: msg.T("issuer.overview.issue.label")}
	switch {
	case c.issued < 0:
		s.Value = msg.T("common.unknown.label")
	case c.issued == 0:
		s.Value, s.LinkText = msg.T("issuer.stat.issued.none.label"), msg.T("issuer.stat.issued.link.label")
	default:
		s.Value = msg.T("issuer.stat.issued.value.label", strconv.Itoa(c.issued))
	}
	return s
}
