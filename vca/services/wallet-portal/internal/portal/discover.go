// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// discover renders board Holder-Discover: the credentials the issuers
// publish, with the trust of each issuer, the format, and how to claim
// (spec HO1, ADR-021 decision 1).
func (p *Portal) discover(w http.ResponseWriter, r *http.Request) error {
	b := p.pen(r)
	resp, err := p.opts.Service.ListDiscoverable(r.Context(),
		connect.NewRequest(&walletportalv1.ListDiscoverableRequest{}))
	var content template.HTML
	if err != nil {
		content = b.part("card", components.Card{
			ID: "problem", Title: msg.T("holder.discover.problem.title"), Text: msg.T("holder.problem.text"),
		})
	} else {
		content = p.offeringTable(b, resp.Msg.GetOfferings())
		if o, ok := chosen(r, resp.Msg.GetOfferings()); ok {
			content = components.Join(content, p.claimCard(b, o))
		}
	}
	return p.render(w, r, b, components.Page{
		Title:       msg.T("holder.discover.title.label"),
		Lead:        msg.T("holder.discover.lead"),
		Description: msg.T("holder.discover.lead"),
		Content:     content,
	})
}

// offeringTable renders one row per offering with its claim link.
func (p *Portal) offeringTable(b *pen, list []*walletportalv1.Offering) template.HTML {
	table := components.Table{
		ID: "offerings", Caption: msg.T("holder.discover.caption.label", strconv.Itoa(len(list))),
		Columns: []string{
			msg.T("holder.discover.column.issuer.label"), msg.T("holder.discover.column.credential.label"),
			msg.T("holder.discover.column.format.label"), msg.T("holder.discover.column.how.label"),
			msg.T("holder.discover.column.action.label"),
		},
		Empty: msg.T("holder.discover.empty"),
	}
	for i, o := range list {
		issuer := b.raw(template.HTMLEscapeString(issuerName(o)) +
			`<br><span class="hint">` + template.HTMLEscapeString(trustLine(o.GetTrust())) + `</span>`)
		claim := b.part("button", components.Button{
			Text: msg.T("holder.discover.claim.label"), Variant: "secondary",
			Href:      p.opts.Prefix + "/discover?claim=" + strconv.Itoa(i+1) + "#claim",
			AriaLabel: msg.T("holder.discover.claim.aria", title(o), issuerName(o)),
		})
		table.Rows = append(table.Rows, components.Row{
			{HTML: issuer}, {Text: title(o)}, {Text: formatLabel(o)}, {Text: howToClaim(o)}, {HTML: claim},
		})
	}
	return b.part("table", table)
}

// trustLine names the trust of an issuer under its name.
func trustLine(outcome trustv1.TrustLookupResponse_Outcome) string {
	switch outcome {
	case trustv1.TrustLookupResponse_OUTCOME_TRUSTED:
		return msg.T("holder.discover.trusted.label")
	case trustv1.TrustLookupResponse_OUTCOME_UNTRUSTED:
		return msg.T("holder.discover.untrusted.label")
	case trustv1.TrustLookupResponse_OUTCOME_UNKNOWN:
		return msg.T("holder.discover.unlisted.label")
	}
	return msg.T("holder.discover.unchecked.label")
}

// formatLabel names the format of an offering as the schema pages do.
func formatLabel(o *walletportalv1.Offering) string {
	formats := o.GetSchema().GetFormats()
	if len(formats) == 0 || formats[0] == commonv1.Format_FORMAT_UNSPECIFIED {
		return msg.T("holder.discover.format.none.label")
	}
	key := "schema.format." + strings.ToLower(strings.TrimPrefix(formats[0].String(), "FORMAT_")) + ".label"
	if text, ok := msg.Lookup(key); ok {
		return text
	}
	return formats[0].String()
}

// methodsOf returns the ways to claim an offering. An issuer that names
// no grant still sends offers, so the code is the way.
func methodsOf(o *walletportalv1.Offering) []walletportalv1.ClaimMethod {
	if len(o.GetClaimMethods()) == 0 {
		return []walletportalv1.ClaimMethod{walletportalv1.ClaimMethod_CLAIM_METHOD_PRE_AUTHORIZED_CODE}
	}
	return o.GetClaimMethods()
}

// howToClaim names the ways to claim an offering, sign in first.
func howToClaim(o *walletportalv1.Offering) string {
	var parts []string
	for _, m := range methodsOf(o) {
		switch m {
		case walletportalv1.ClaimMethod_CLAIM_METHOD_AUTHORIZATION_CODE:
			parts = append(parts, msg.T("holder.discover.how.signin.label"))
		case walletportalv1.ClaimMethod_CLAIM_METHOD_PRE_AUTHORIZED_CODE:
			parts = append(parts, msg.T("holder.discover.how.code.label"))
		}
	}
	return strings.Join(parts, " · ")
}
