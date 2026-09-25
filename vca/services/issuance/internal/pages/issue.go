// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"strconv"
	"strings"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// channels lists the delivery channels the issue page names, in the
// order of board Issuer-Issue, with the catalogue key of each.
var channels = []struct {
	channel backendv1.Channel
	key     string
}{
	{backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, "issuer.issue.pre_auth"},
	{backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE, "issuer.issue.auth_code"},
	{backendv1.Channel_CHANNEL_DC_API, "issuer.issue.dc_api"},
	{backendv1.Channel_CHANNEL_PDF, "issuer.issue.pdf"},
}

// maxSchemas caps the published schemas the issue page lists.
const maxSchemas = 100

// issue lists the published schemas a staff member can issue and the
// delivery channels the stack of the pair offers. The page shows only
// what the stack can do (ADR-016 decision 6).
func (p *Pages) issue(pg page) error {
	caps := p.caps(pg)
	b := p.blocks()
	var schemas []*schemav1.Schema
	if p.opts.Schemas != nil {
		ctx := pg.r.Context()
		res, err := p.opts.Schemas.List(ctx, staffshell.AsActor(ctx, &schemav1.ListRequest{
			State: schemav1.State_STATE_PUBLISHED, Page: &commonv1.Pagination{PageSize: maxSchemas},
		}))
		if err != nil && connect.CodeOf(err) != connect.CodeUnavailable {
			return err
		}
		if err == nil {
			schemas = res.Msg.GetSchemas()
		}
	}
	var list components.Block
	list.ID, list.Title = "published", msg.T("issuer.issue.schemas.label")
	if len(schemas) == 0 {
		list.Body = b.add("empty", components.Empty{
			Title: msg.T("issuer.schemas.empty.title"), Text: msg.T("issuer.schemas.empty.text"),
			Action: components.Button{Text: msg.T("issuer.schemas.build.label"), Href: BuilderPath, Variant: "primary"},
		})
	} else {
		rows := make([]components.Row, 0, len(schemas))
		for _, s := range schemas {
			rows = append(rows, components.Row{
				{HTML: link(SchemasPath+"schemas/"+s.GetId(), schemaName(s))},
				{Text: strconv.Itoa(int(s.GetVersion()))},
				{Text: formats(s.GetFormats())},
			})
		}
		list.Lead = msg.T("issuer.issue.schemas.lead")
		list.Body = b.add("table", components.Table{
			ID: "schemas", Caption: msg.T("issuer.issue.schemas.caption.label", strconv.Itoa(len(rows))),
			Columns: []string{msg.T("common.name.label"), msg.T("common.version.label"), msg.T("issuer.issue.column.formats.label")},
			Rows:    rows,
		})
	}
	var rows []components.Row
	for _, c := range channels {
		if offers(caps, c.channel) {
			rows = append(rows, components.Row{{Text: msg.T(c.key + ".label")}, {Text: msg.T(c.key + ".text")}})
		}
	}
	delivery := b.add("block", components.Block{
		ID: "delivery", Title: msg.T("issuer.issue.channels.label", stackName(caps)), Lead: msg.T("issuer.issue.hidden_note"),
		Body: b.add("table", components.Table{
			ID: "channels", Caption: msg.T("issuer.issue.channels.caption.label"),
			Columns: []string{msg.T("issuer.issue.column.channel.label"), msg.T("issuer.issue.column.text.label")},
			Rows:    rows, Empty: msg.T("issuer.issue.channels.none"),
		}),
	})
	published := b.add("block", list)
	if b.err != nil {
		return b.err
	}
	return p.render(pg, components.Page{
		Title: msg.T("issuer.nav.issue.label"), Lead: msg.T("issuer.issue.lead"), Description: msg.T("issuer.issue.lead"),
		Content: components.Join(published, delivery),
	})
}

// offers reports whether the adapter lists a channel.
func offers(caps *backendv1.GetCapabilitiesResponse, c backendv1.Channel) bool {
	for _, got := range caps.GetChannels() {
		if got == c {
			return true
		}
	}
	return false
}

// schemaName is the display name of a schema in English, or its type.
func schemaName(s *schemav1.Schema) string {
	for _, d := range s.GetDisplay() {
		if d.GetName() != "" && (d.GetLocale() == "" || strings.HasPrefix(d.GetLocale(), "en")) {
			return d.GetName()
		}
	}
	return s.GetType()
}

// formats names the wire formats of a schema, joined with commas.
func formats(fs []commonv1.Format) string {
	names := make([]string, 0, len(fs))
	for _, f := range fs {
		names = append(names, strings.ToLower(strings.TrimPrefix(f.String(), "FORMAT_")))
	}
	return strings.Join(names, ", ")
}
