// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"html/template"
	"net/http"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// liveStacks returns the live issuer pairs that run an adapter, in stack
// order. A pair that is starting or absent never shows (ADR-034
// decision 3).
func liveStacks(f staffshell.Frame) []topology.Status {
	var out []topology.Status
	for _, st := range f.Live(commonv1.Role_ROLE_ISSUER) {
		if st.Peer.Adapter() != "" {
			out = append(out, st)
		}
	}
	return out
}

// liveStack returns the live issuer pair of a name.
func (p *Pages) liveStack(f staffshell.Frame, pair string) (topology.Status, bool) {
	for _, st := range liveStacks(f) {
		if st.Peer.Pair == pair {
			return st, true
		}
	}
	return topology.Status{}, false
}

// chosenStack returns the stack the import page reads: the one the query
// names when it is live, else the own pair when it is live, else the
// first live stack.
func (p *Pages) chosenStack(f staffshell.Frame, pair string, stacks []topology.Status) topology.Status {
	if st, ok := p.liveStack(f, pair); ok {
		return st
	}
	if own, ok := f.Own(); ok {
		if st, ok := p.liveStack(f, own.Peer.Pair); ok {
			return st
		}
	}
	return stacks[0]
}

// stackCatalogCard renders the catalogue import of the live issuer
// stacks: a choice of the stack, then the credential types of the
// chosen stack. The choice is a GET form, so it works without script.
func (p *Pages) stackCatalogCard(err *error, r *http.Request, f staffshell.Frame, csrf template.HTML) template.HTML {
	title := msg.T("issuer.builder.import.stacks.label")
	stacks := liveStacks(f)
	if len(stacks) == 0 {
		return p.frag(err).card(components.Card{ID: "import-catalog", Title: title, Text: msg.T("issuer.builder.import.none")})
	}
	chosen := p.chosenStack(f, r.URL.Query().Get("stack"), stacks)
	snap := f.Snapshot()
	options := make([]components.ChoiceOption, 0, len(stacks))
	for _, st := range stacks {
		options = append(options, components.ChoiceOption{
			Value: st.Peer.Pair, Title: snap.StackName(st.Peer.Dpg), Meta: st.Capabilities.GetDpgInfo().GetVersion(),
			Checked: st.Peer.Pair == chosen.Peer.Pair,
		})
	}
	prefix := template.HTMLEscapeString(p.opts.Prefix)
	pick := p.frag(err)
	pick.raw(template.HTML(`<form method="get" action="` + prefix + `/import">`)) //nolint:gosec // the prefix is escaped
	pick.add("choice", components.Choice{ID: "stack", Legend: msg.T("issuer.builder.import.stack.label"), Options: options})
	pick.add("button", components.Button{Text: msg.T("issuer.builder.import.show.label"), Type: "submit"})
	pick.raw(`</form>`)
	name := snap.StackName(chosen.Peer.Dpg)
	entries, catalogErr := p.opts.Builder.WithCatalog(p.opts.Catalogs(chosen.Peer.Adapter())).Catalog(r.Context())
	body := p.frag(err)
	body.raw(pick.html())
	switch {
	case catalogErr != nil:
		body.raw(template.HTML(`<p>` + template.HTMLEscapeString(msg.T("issuer.builder.import.down", name)) + `</p>`)) //nolint:gosec // the text is escaped
	case len(entries) == 0:
		body.raw(template.HTML(`<p>` + template.HTMLEscapeString(msg.T("issuer.builder.import.empty", name)) + `</p>`)) //nolint:gosec // the text is escaped
	default:
		list := make([]components.Option, 0, len(entries))
		for _, e := range entries {
			text := e.GetId()
			if e.GetType() != "" {
				text = e.GetType() + " (" + e.GetId() + ")"
			}
			list = append(list, components.Option{Value: e.GetId(), Text: text})
		}
		body.raw(template.HTML(`<form method="post" action="` + prefix + `/import">`)) //nolint:gosec // the prefix is escaped
		body.raw(csrf)
		body.raw(template.HTML(`<input type="hidden" name="stack" value="` + template.HTMLEscapeString(chosen.Peer.Pair) + `">`)) //nolint:gosec // the value is escaped
		body.add("field", components.Field{ID: "catalog_entry_id", Label: msg.T("issuer.builder.import.type.label", name), Type: "select", Options: list})
		body.add("button", components.Button{Text: "Import the credential type", Type: "submit", Variant: "primary"})
		body.raw(`</form>`)
	}
	return p.frag(err).card(components.Card{
		ID: "import-catalog", Title: title, Text: msg.T("issuer.builder.import.stacks.text"), Body: body.html(),
	})
}
