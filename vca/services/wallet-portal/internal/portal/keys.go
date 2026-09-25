// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"html/template"
	"net/http"
	"slices"
	"strings"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// The page "Keys and identifiers" (P6-W4). It exists only when the
// wallet of the own stack manages keys (ADR-034 decision 5). Each part
// shows only when the adapter lists its feature: the keys with
// FEATURE_WALLET_KEYS, the DIDs with FEATURE_WALLET_DIDS, and the
// activity with FEATURE_WALLET_EVENTS. The choices of the forms are the
// key types and the DID methods the adapter lists.
//
//	GET  /keys           the page
//	POST /keys/key       make a key
//	POST /keys/did       make a DID
//	POST /keys/default   pick the default DID

// ownCaps returns the capability answer of the own stack.
func (b *pen) ownCaps() *backendv1.GetCapabilitiesResponse {
	own, _ := b.frame.Own()
	return own.Capabilities
}

// options lists the values of a select, with the first one picked.
func options(values []string) []components.Option {
	out := make([]components.Option, 0, len(values))
	for _, v := range values {
		out = append(out, components.Option{Value: v, Text: v})
	}
	return out
}

// keys renders the page.
func (p *Portal) keys(w http.ResponseWriter, r *http.Request) error {
	b := p.pen(r)
	if !b.frame.Has(backendv1.Feature_FEATURE_WALLET_KEYS) {
		http.NotFound(w, r)
		return nil
	}
	withDids, withEvents := b.frame.Has(backendv1.Feature_FEATURE_WALLET_DIDS), b.frame.Has(backendv1.Feature_FEATURE_WALLET_EVENTS)
	content := p.summary(b)
	wallet, err := p.opts.Service.ReadWalletKeys(r.Context(), withDids, withEvents)
	if err != nil {
		content += b.part("card", components.Card{ID: "keys-problem", Title: msg.T("holder.keys.problem.title"), Text: msg.T("holder.keys.problem.text") + " " + message(err)})
	} else {
		content += p.keyBlock(b, wallet.Keys)
		if withDids {
			content += p.didBlock(b, wallet.Dids, wallet.Keys)
		}
		if withEvents {
			content += p.eventBlock(b, wallet.Events)
		}
	}
	return p.render(w, r, b, components.Page{
		Title: msg.T("holder.nav.keys.label"), Lead: msg.T("holder.keys.lead"), Description: msg.T("holder.keys.lead"),
		Content: content,
	})
}

// summary is the identifier and the key of the session.
func (p *Portal) summary(b *pen) template.HTML {
	did := b.who.HolderDID
	if did == "" {
		did = msg.T("holder.keys.none")
	}
	key := msg.T("holder.keys.key.stack")
	if b.who.HasHolderKey {
		key = msg.T("holder.keys.key.browser")
	}
	return b.part("table", components.Table{
		ID: "holder-keys", Caption: msg.T("holder.keys.caption.label"),
		Columns: []string{msg.T("holder.keys.column.item.label"), msg.T("holder.keys.column.value.label")},
		Rows: []components.Row{
			{{Text: msg.T("holder.keys.did.label")}, {HTML: b.raw(`<span class="mono">` + template.HTMLEscapeString(did) + `</span>`)}},
			{{Text: msg.T("holder.keys.key.label")}, {Text: key}},
		},
	})
}

// mono renders a value in the monospace style.
func (b *pen) mono(v string) components.Cell {
	return components.Cell{HTML: b.raw(`<span class="mono">` + template.HTMLEscapeString(v) + `</span>`)}
}

// keyBlock lists the keys and offers a new one.
func (p *Portal) keyBlock(b *pen, keys []*backendv1.WalletKey) template.HTML {
	rows := make([]components.Row, 0, len(keys))
	for _, k := range keys {
		rows = append(rows, components.Row{b.mono(k.GetId()), {Text: k.GetType()}, {Text: k.GetBackend()}, {Text: k.GetName()}})
	}
	table := b.part("table", components.Table{
		ID: "wallet-keys", Caption: msg.T("holder.keys.keys.caption.label"),
		Columns: []string{msg.T("holder.keys.column.key.label"), msg.T("holder.keys.column.type.label"),
			msg.T("holder.keys.column.store.label"), msg.T("holder.keys.column.name.label")},
		Rows: rows, Empty: msg.T("holder.keys.keys.empty"),
	})
	field := b.part("field", components.Field{ID: "key_type", Label: msg.T("holder.keys.key_type.label"), Type: "select",
		Options: options(b.ownCaps().GetWalletKeyTypes()), Hint: msg.T("holder.keys.key_type.hint")})
	form := b.form(p.opts.Prefix+"/keys/key", nil, components.Button{Text: msg.T("holder.keys.key.create.label"), Type: "submit"}, field)
	return b.part("block", components.Block{ID: "keys", Title: msg.T("holder.keys.keys.label"), Lead: msg.T("holder.keys.keys.lead"),
		Body: components.Join(table, form)})
}

// didBlock lists the DIDs, marks the default one, and offers a new one.
func (p *Portal) didBlock(b *pen, dids []*backendv1.WalletDid, keys []*backendv1.WalletKey) template.HTML {
	rows := make([]components.Row, 0, len(dids))
	for _, d := range dids {
		state := components.Cell{HTML: b.part("badge", components.Badge{Status: "ok", Text: msg.T("holder.keys.default.label")})}
		if !d.GetDefault() {
			state = components.Cell{HTML: b.form(p.opts.Prefix+"/keys/default", map[string]string{"did": d.GetDid()},
				components.Button{Text: msg.T("holder.keys.default.make.label"), Type: "submit", Variant: "ghost"})}
		}
		rows = append(rows, components.Row{b.mono(d.GetDid()), {Text: d.GetAlias()}, b.mono(d.GetKeyId()), state})
	}
	table := b.part("table", components.Table{
		ID: "wallet-dids", Caption: msg.T("holder.keys.dids.caption.label"),
		Columns: []string{msg.T("holder.keys.column.did.label"), msg.T("holder.keys.column.name.label"),
			msg.T("holder.keys.column.key.label"), msg.T("holder.keys.column.default.label")},
		Rows: rows, Empty: msg.T("holder.keys.dids.empty"),
	})
	keyOptions := []components.Option{{Value: "", Text: msg.T("holder.keys.did.newkey.label")}}
	for _, k := range keys {
		text := k.GetType() + ", " + k.GetId()
		if k.GetName() != "" {
			text = k.GetName() + ", " + text
		}
		keyOptions = append(keyOptions, components.Option{Value: k.GetId(), Text: text})
	}
	fields := components.Join(
		b.part("field", components.Field{ID: "method", Label: msg.T("holder.keys.method.label"), Type: "select",
			Options: options(b.ownCaps().GetWalletDidMethods()), Hint: msg.T("holder.keys.method.hint")}),
		b.part("field", components.Field{ID: "key_id", Label: msg.T("holder.keys.did.key.label"), Type: "select", Options: keyOptions}),
		b.part("field", components.Field{ID: "alias", Label: msg.T("holder.keys.alias.label"), Hint: msg.T("holder.keys.alias.hint")}),
	)
	form := b.form(p.opts.Prefix+"/keys/did", nil, components.Button{Text: msg.T("holder.keys.did.create.label"), Type: "submit"}, fields)
	return b.part("block", components.Block{ID: "dids", Title: msg.T("holder.keys.dids.label"), Lead: msg.T("holder.keys.dids.lead"),
		Body: components.Join(table, form)})
}

// eventBlock lists the latest events of the wallet.
func (p *Portal) eventBlock(b *pen, events []*backendv1.WalletEvent) template.HTML {
	rows := make([]components.Row, 0, len(events))
	for _, e := range events {
		when := ""
		if e.GetAt() != nil {
			when = e.GetAt().AsTime().UTC().Format("2 Jan 2006, 15:04") + " UTC"
		}
		rows = append(rows, components.Row{{Text: when}, {Text: strings.TrimSpace(e.GetEvent() + " " + e.GetAction())}, {Text: e.GetCounterpart()}})
	}
	table := b.part("table", components.Table{
		ID: "wallet-events", Caption: msg.T("holder.keys.events.caption.label"),
		Columns: []string{msg.T("holder.keys.column.when.label"), msg.T("holder.keys.column.what.label"), msg.T("holder.keys.column.with.label")},
		Rows:    rows, Empty: msg.T("holder.keys.events.empty"),
	})
	return b.part("block", components.Block{ID: "events", Title: msg.T("holder.keys.events.label"), Lead: msg.T("holder.keys.events.lead"), Body: table})
}

// keyForm checks the feature and the form of a key page post. It
// answers the request itself and returns false when the post stops.
func (p *Portal) keyForm(w http.ResponseWriter, r *http.Request, feature backendv1.Feature) (*pen, bool) {
	b := p.pen(r)
	if !b.frame.Has(backendv1.Feature_FEATURE_WALLET_KEYS) || !b.frame.Has(feature) {
		http.NotFound(w, r)
		return nil, false
	}
	if _, ok := p.writer(w, r); !ok {
		return nil, false
	}
	return b, true
}

// refuse answers a post with a choice the stack does not list.
func (p *Portal) refuse(w http.ResponseWriter, r *http.Request, text string) error {
	w.WriteHeader(http.StatusBadRequest)
	return p.problem(w, r, msg.T("holder.nav.keys.label"), msg.T("holder.keys.refused.title"), text)
}

// after answers a post: back to the page, or a problem.
func (p *Portal) after(w http.ResponseWriter, r *http.Request, err error) error {
	if err != nil {
		return p.problem(w, r, msg.T("holder.nav.keys.label"), msg.T("holder.keys.problem.title"), message(err))
	}
	http.Redirect(w, r, p.opts.Prefix+"/keys", http.StatusSeeOther)
	return nil
}

// createKey makes a key of a listed type.
func (p *Portal) createKey(w http.ResponseWriter, r *http.Request) error {
	b, ok := p.keyForm(w, r, backendv1.Feature_FEATURE_WALLET_KEYS)
	if !ok {
		return nil
	}
	keyType := r.PostFormValue("key_type")
	if !slices.Contains(b.ownCaps().GetWalletKeyTypes(), keyType) {
		return p.refuse(w, r, msg.T("holder.keys.refused.key_type"))
	}
	return p.after(w, r, p.opts.Service.CreateWalletKey(r.Context(), keyType))
}

// createDid makes a DID of a listed method.
func (p *Portal) createDid(w http.ResponseWriter, r *http.Request) error {
	b, ok := p.keyForm(w, r, backendv1.Feature_FEATURE_WALLET_DIDS)
	if !ok {
		return nil
	}
	method := r.PostFormValue("method")
	if !slices.Contains(b.ownCaps().GetWalletDidMethods(), method) {
		return p.refuse(w, r, msg.T("holder.keys.refused.method"))
	}
	return p.after(w, r, p.opts.Service.CreateWalletDid(r.Context(), method, r.PostFormValue("key_id"), strings.TrimSpace(r.PostFormValue("alias"))))
}

// defaultDid picks the default DID.
func (p *Portal) defaultDid(w http.ResponseWriter, r *http.Request) error {
	if _, ok := p.keyForm(w, r, backendv1.Feature_FEATURE_WALLET_DIDS); !ok {
		return nil
	}
	did := strings.TrimSpace(r.PostFormValue("did"))
	if did == "" {
		return p.refuse(w, r, msg.T("holder.keys.refused.did"))
	}
	return p.after(w, r, p.opts.Service.SetWalletDefaultDid(r.Context(), did))
}
