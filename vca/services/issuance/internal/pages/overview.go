// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"html/template"
	"strconv"
	"strings"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// counts are the numbers of the overview. A negative count means the
// service did not answer.
type counts struct {
	published int
	issued    int
}

// overview draws board Issuer-Portal: the four steps that unlock in
// order, the identity, schema, and issued cards, and the recent activity
// of this pair.
func (p *Pages) overview(pg page) error {
	v := p.identityView(pg)
	c := p.counts(pg)
	b := p.blocks()
	actions := components.Join(
		b.add("button", components.Button{Text: msg.T("issuer.overview.publish.label"), Href: BuilderPath}),
		b.add("button", components.Button{Text: msg.T("issuer.overview.issue.label"), Href: IssuePath, Variant: "primary"}),
	)
	steps := b.add("steps", components.Steps{Items: steps(v.state == "registered" || v.state == "stack", c), Text: components.StepText{
		Done: msg.T("common.done.label"), Current: msg.T("common.current.label"), Locked: msg.T("common.locked.label"),
	}})
	stats := components.Join(
		b.add("stat", identityStat(v)),
		b.add("stat", c.schemaStat()),
		b.add("stat", c.issuedStat()),
	)
	activity := p.activity(pg, b)
	if b.err != nil {
		return b.err
	}
	lead := msg.T("issuer.overview.lead", stackName(v.caps))
	return p.render(pg, components.Page{
		Title: msg.T("common.overview.label"), Lead: lead, Description: lead, Actions: actions,
		Content: components.Join(steps, template.HTML(`<div class="stats">`)+stats+template.HTML(`</div>`), activity), //nolint:gosec // literal wrappers around kit output
	})
}

// steps are the four steps of the issuer. A step is done when its fact
// holds and every step before it is done; the first step that is not
// done is current, and every later step is locked.
func steps(identity bool, c counts) []components.Step {
	facts := []bool{identity, c.published > 0, c.issued > 0, false}
	items := []components.Step{
		{Title: msg.T("issuer.step.identity.label"), Text: msg.T("issuer.step.identity.text"), Href: IdentityPath, LinkText: msg.T("issuer.step.identity.link.label")},
		{Title: msg.T("issuer.step.schema.label"), Text: msg.T("issuer.step.schema.text"), Href: BuilderPath, LinkText: msg.T("issuer.overview.publish.label")},
		{Title: msg.T("issuer.step.issue.label"), Text: msg.T("issuer.step.issue.text"), Href: IssuePath, LinkText: msg.T("issuer.overview.issue.label")},
		{Title: msg.T("issuer.step.manage.label"), Text: msg.T("issuer.step.manage.text"), Href: SchemasPath, LinkText: msg.T("issuer.stat.schemas.link.label")},
	}
	if identity {
		items[0].LinkText = msg.T("common.open.label")
	}
	open := true
	for i := range items {
		switch {
		case open && facts[i]:
			items[i].State = "done"
		case open:
			items[i].State, open = "current", false
		default:
			items[i].State, items[i].Href = "locked", ""
		}
	}
	return items
}

// identityStat is the card of the identity: the identifier and its
// state in the trust registry.
func identityStat(v identityView) components.Stat {
	s := components.Stat{Label: msg.T("issuer.stat.identity.label"), Href: IdentityPath, LinkText: msg.T("issuer.step.identity.link.label")}
	switch v.state {
	case "registered":
		// The heading font draws capitals, and a DID is case sensitive,
		// so the identifier goes in the text under the value.
		s.Value, s.LinkText = msg.T("issuer.identity.status.registered.label"), msg.T("common.open.label")
		s.Text = firstIdentifier(v.identity)
		switch v.entry.GetStatus() {
		case trustv1.Status_STATUS_PENDING:
			s.Text = msg.T("issuer.stat.identity.text", s.Text, msg.T("issuer.stat.in_registry.label"))
		case trustv1.Status_STATUS_ACTIVE:
			s.Text = msg.T("issuer.stat.identity.text", s.Text, msg.T("issuer.stat.on_list.label"))
		}
	case "stack":
		s.Value, s.LinkText = msg.T("issuer.stat.identity.stack.label"), msg.T("common.open.label")
	case "down":
		s.Value = msg.T("common.unknown.label")
	default:
		s.Value = msg.T("issuer.identity.status.none.label")
	}
	return s
}

// activityRows caps the recent activity.
const activityRows = 8

// activity is the recent activity of this pair from its audit log
// (ADR-039 decision 1).
func (p *Pages) activity(pg page, b *blocks) template.HTML {
	var rows []components.Row
	if p.opts.Audit != nil {
		page, err := p.opts.Audit.Query(pg.r.Context(), auditlog.Filter{PageSize: activityRows})
		if err == nil {
			for _, rec := range page.Records {
				detail := rec.Target
				if rec.Detail != "" {
					detail = strings.TrimSpace(rec.Target + " " + rec.Detail)
				}
				event := escape(eventLabel(rec.Action))
				if !rec.OK {
					event += " " + b.add("badge", components.Badge{Status: "bad", Text: msg.T("issuer.activity.failed.label")})
				}
				rows = append(rows, components.Row{{Text: rec.At.UTC().Format(TimeFormat)}, {HTML: event}, {Text: detail}})
			}
		}
	}
	return b.add("block", components.Block{
		ID: "activity", Title: msg.T("common.recent_activity.label"),
		Body: b.add("table", components.Table{
			ID: "events", Caption: msg.T("issuer.activity.caption.label"),
			Columns: []string{msg.T("common.when.label"), msg.T("common.event.label"), msg.T("common.detail.label")},
			Rows:    rows, Empty: msg.T("issuer.activity.none"),
		}),
	})
}

// TimeFormat is how the overview prints a time.
const TimeFormat = "2006-01-02 15:04 UTC"

// eventLabel names an audit action, or returns it as it is.
func eventLabel(action string) string {
	switch action {
	case "issuance.Issue":
		return msg.T("issuer.activity.issue.label")
	case ActionProvisionIdentity, ActionImportIdentity:
		return msg.T("issuer.activity.identity.label")
	case ActionRequestTrust:
		return msg.T("issuer.activity.trust.label")
	}
	return action
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
