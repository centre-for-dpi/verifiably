// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// errRefresh reports a refresh value the form does not offer.
var errRefresh = errors.New("portal: the refresh is not a duration")

// registryMethods are the list formats of the form, in form order.
var registryMethods = []struct {
	value string
	key   string
	proto trustv1.RegistryMethod
}{
	{"etsi-lote-json", "admin.registries.method.lote.label", trustv1.RegistryMethod_REGISTRY_METHOD_ETSI_LOTE_JSON},
	{"etsi-tsl-xml", "admin.registries.method.tsl.label", trustv1.RegistryMethod_REGISTRY_METHOD_ETSI_TSL_XML},
	{"dedi", "admin.registries.method.dedi.label", trustv1.RegistryMethod_REGISTRY_METHOD_DEDI},
}

// registerRegistries adds the registries tab of the trust pages (board
// Admin-Trust, owner spec AD2, ADR-011 decision 7).
func (p *Portal) registerRegistries(mux *http.ServeMux) {
	at := p.opts.Prefix
	mux.HandleFunc("GET "+at+"/trust/registries", p.guarded(p.registries))
	mux.HandleFunc("POST "+at+"/trust/registries", p.posted(p.addRegistry))
	mux.HandleFunc("POST "+at+"/trust/registries/{id}/sync", p.posted(p.syncRegistry))
	mux.HandleFunc("POST "+at+"/trust/registries/{id}/delete", p.posted(p.removeRegistry))
}

// trustTabs are the two views of the trust pages. current is list or
// registries.
func (p *Portal) trustTabs(b *blocks, current string) template.HTML {
	at := p.opts.Prefix
	return b.add("tabs", components.Tabs{Label: msg.T("admin.trust.tabs.label"), Links: []components.Link{
		{Href: at + "/trust", Text: msg.T("admin.trust.tab.list.label"), Current: current == "list"},
		{Href: at + "/trust/registries", Text: msg.T("admin.trust.tab.registries.label"), Current: current == "registries"},
	}})
}

// trustActions are the header buttons of both trust pages.
func (p *Portal) trustHeaderActions(b *blocks) template.HTML {
	at := p.opts.Prefix
	return components.Join(
		b.add("button", components.Button{Text: msg.T("admin.registries.add.label"), Href: at + "/trust/registries#add-registry", Variant: "secondary"}),
		b.add("button", components.Button{Text: msg.T("admin.trust.add.label"), Href: at + "/trust#add-entry", Variant: "primary"}),
	)
}

// registries renders the local registry with its published lists, the
// external registries with their last sync, and the add form.
func (p *Portal) registries(w http.ResponseWriter, r *http.Request, s session) error {
	b := p.blocks()
	res, err := p.opts.Client.ListTrustRegistries(r.Context(), call(s, &adminv1.ListTrustRegistriesRequest{}))
	var content template.HTML
	switch {
	case err != nil && connect.CodeOf(err) == connect.CodeFailedPrecondition:
		content = b.add("card", components.Card{
			ID: "no-registry", Title: msg.T("admin.trust.no_registry.label"), Text: msg.T("admin.trust.no_registry"),
		})
	case err != nil:
		return err
	default:
		content = components.Join(
			p.localRegistry(b, res.Msg),
			p.externalRegistries(b, res.Msg.GetRegistries(), s.CSRF),
			p.registryForm(b, s.CSRF),
		)
	}
	tabs := p.trustTabs(b, "registries")
	actions := p.trustHeaderActions(b)
	if b.err != nil {
		return b.err
	}
	return p.render(w, r, s, components.Page{
		Title:       msg.T("admin.nav.trust_registries.label"),
		Heading:     msg.T("admin.trust.heading.label"),
		Lead:        msg.T("admin.trust.lead"),
		Actions:     actions,
		Description: msg.T("admin.trust.lead"),
		Content:     components.Join(tabs, content),
		Toasts:      notice(r.URL.Query().Get("notice")),
	})
}

// localRegistry is the card of this registry: its published lists and
// the key set that signs them.
func (p *Portal) localRegistry(b *blocks, res *adminv1.ListTrustRegistriesResponse) template.HTML {
	rows := make([]components.Row, 0, len(res.GetLocal())+1)
	for _, pub := range res.GetLocal() {
		rows = append(rows, components.Row{
			{Text: publicationLabel(pub.GetMethod())},
			{HTML: link(pub.GetUrl())},
			{Text: strconv.Itoa(int(pub.GetEntryCount()))},
			{HTML: code(pub.GetKeyId())},
		})
	}
	if res.GetJwksUrl() != "" {
		rows = append(rows, components.Row{{Text: msg.T("admin.registries.jwks.label")}, {HTML: link(res.GetJwksUrl())}, {}, {}})
	}
	table := b.add("table", components.Table{
		ID: "local-lists", Caption: msg.T("admin.registries.local.caption.label"),
		Columns: []string{
			msg.T("admin.registries.column.list.label"), msg.T("admin.registries.column.url.label"),
			msg.T("admin.registries.column.entries.label"), msg.T("admin.registries.column.key.label"),
		},
		Rows: rows,
	})
	return b.add("card", components.Card{
		ID:    "local-registry",
		Title: msg.T("admin.registries.local.label"),
		Text:  msg.T("admin.registries.local.text"),
		Body:  components.Join(b.add("badge", components.Badge{Status: "ok", Text: msg.T("admin.registries.local.published.label")}), table),
	})
}

// externalRegistries is the table of the external registries, or the
// empty state with the add action.
func (p *Portal) externalRegistries(b *blocks, regs []*trustv1.Registry, csrf string) template.HTML {
	if len(regs) == 0 {
		return b.add("empty", components.Empty{
			Title: msg.T("admin.registries.empty.title"), Text: msg.T("admin.registries.empty.text"),
			Action: components.Button{Text: msg.T("admin.registries.add.label"), Href: "#add-registry", Variant: "primary"},
		})
	}
	at := p.opts.Prefix
	rows := make([]components.Row, 0, len(regs))
	for _, reg := range regs {
		base := at + "/trust/registries/" + reg.GetId()
		last := template.HTML(template.HTMLEscapeString(msg.T("admin.registries.never.label"))) //nolint:gosec // the text is escaped
		if reg.GetLastSync() != nil {
			at := reg.GetLastSync().AsTime().UTC()
			last = template.HTML(`<time datetime="` + at.Format(time.RFC3339) + `">` + at.Format(TimeFormat) + `</time>`) //nolint:gosec // a formatted time
		}
		rows = append(rows, components.Row{
			{HTML: components.Join(
				template.HTML(`<strong>`+template.HTMLEscapeString(reg.GetName())+`</strong><br>`), //nolint:gosec // the name is escaped
				link(reg.GetUrl()),
			)},
			{HTML: template.HTML(template.HTMLEscapeString(registryMethodLabel(reg.GetMethod())) + //nolint:gosec // both parts are escaped
				`<p class="hint">` + template.HTMLEscapeString(anchorLabel(reg.GetAnchor())) + `</p>`)},
			{HTML: last},
			{HTML: registryState(b, reg)},
			{HTML: components.Join(
				template.HTML(`<div class="row-actions">`), //nolint:gosec // a literal wrapper
				form(base+"/sync", csrf, b.add("button", components.Button{Text: msg.T("admin.registries.sync.label"), Type: "submit"})),
				form(base+"/delete", csrf, b.add("button", components.Button{Text: msg.T("admin.registries.remove.label"), Type: "submit", Variant: "danger"})),
				template.HTML(`</div>`),
			)},
		})
	}
	return b.add("table", components.Table{
		ID: "registries", Caption: msg.T("admin.registries.caption.label", strconv.Itoa(len(rows))),
		Columns: []string{
			msg.T("admin.registries.column.registry.label"), msg.T("admin.registries.column.format.label"),
			msg.T("admin.registries.column.sync.label"), msg.T("admin.registries.column.state.label"),
			msg.T("admin.registries.column.actions.label"),
		},
		Rows: rows,
	})
}

// registryState is the badge of the last read, with the entry count of
// a good read or the reason of a failed read under it.
func registryState(b *blocks, reg *trustv1.Registry) template.HTML {
	switch {
	case reg.GetLastError() != "":
		return components.Join(
			b.add("badge", components.Badge{Status: "bad", Text: msg.T("admin.registries.state.error.label")}),
			template.HTML(`<p class="hint">`+template.HTMLEscapeString(reg.GetLastError())+`</p>`), //nolint:gosec // the reason is escaped
		)
	case reg.GetLastSync() != nil:
		return components.Join(
			b.add("badge", components.Badge{Status: "ok", Text: msg.T("admin.registries.state.ok.label")}),
			template.HTML(`<p class="hint">`+template.HTMLEscapeString(msg.T("admin.registries.entries.label", strconv.Itoa(int(reg.GetEntryCount()))))+`</p>`), //nolint:gosec // the text is escaped
		)
	}
	return b.add("badge", components.Badge{Status: "info", Text: msg.T("admin.registries.state.never.label")})
}

// registryForm is the add form: name, format, URL, anchor and refresh.
func (p *Portal) registryForm(b *blocks, csrf string) template.HTML {
	methods := make([]components.Option, 0, len(registryMethods))
	for i, m := range registryMethods {
		methods = append(methods, components.Option{Value: m.value, Text: msg.T(m.key), Selected: i == 0})
	}
	fields := components.Join(
		b.add("field", components.Field{ID: "name", Label: msg.T("admin.registries.name.label"), Required: true}),
		b.add("field", components.Field{ID: "method", Label: msg.T("admin.registries.method.label"), Type: "select", Options: methods}),
		b.add("field", components.Field{ID: "url", Label: msg.T("admin.registries.url.label"), Type: "url", Required: true, Hint: msg.T("admin.registries.url.hint")}),
		b.add("choice", components.Choice{ID: "anchor_kind", Legend: msg.T("admin.registries.anchor.label"), Options: []components.ChoiceOption{
			{Value: "jwks", Title: msg.T("admin.registries.anchor.jwks.label"), Text: msg.T("admin.registries.anchor.jwks.text"), Checked: true},
			{Value: "x509", Title: msg.T("admin.registries.anchor.x509.label"), Text: msg.T("admin.registries.anchor.x509.text")},
		}}),
		b.add("field", components.Field{ID: "jwks_url", Label: msg.T("admin.registries.jwks_url.label"), Type: "url"}),
		b.add("field", components.Field{ID: "x509_certificate", Label: msg.T("admin.registries.certificate.label"), Type: "textarea",
			Hint: msg.T("admin.registries.certificate.hint")}),
		b.add("field", components.Field{ID: "refresh", Label: msg.T("admin.registries.refresh.label"), Type: "select", Options: []components.Option{
			{Value: "1h", Text: msg.T("admin.registries.refresh.1h.label")},
			{Value: "6h", Text: msg.T("admin.registries.refresh.6h.label")},
			{Value: "24h", Text: msg.T("admin.registries.refresh.24h.label"), Selected: true},
		}}),
		b.add("button", components.Button{Text: msg.T("admin.registries.add.label"), Type: "submit", Variant: "primary"}),
	)
	return b.add("card", components.Card{
		ID: "add-registry", Title: msg.T("admin.registries.new.label"), Text: msg.T("admin.registries.new.text"),
		Body: form(p.opts.Prefix+"/trust/registries", csrf, fields),
	})
}

// addRegistry sends the form to the trust registry, which reads the
// list once, and returns to the table that shows the result.
func (p *Portal) addRegistry(w http.ResponseWriter, r *http.Request, s session) error {
	reg := &trustv1.Registry{
		Name:   strings.TrimSpace(r.PostFormValue("name")),
		Url:    strings.TrimSpace(r.PostFormValue("url")),
		Anchor: &trustv1.Registry_Anchor{},
	}
	for _, m := range registryMethods {
		if m.value == r.PostFormValue("method") {
			reg.Method = m.proto
		}
	}
	if r.PostFormValue("anchor_kind") == "x509" {
		reg.Anchor.Anchor = &trustv1.Registry_Anchor_X509Certificate{X509Certificate: strings.TrimSpace(r.PostFormValue("x509_certificate"))}
	} else {
		reg.Anchor.Anchor = &trustv1.Registry_Anchor_JwksUrl{JwksUrl: strings.TrimSpace(r.PostFormValue("jwks_url"))}
	}
	if v := r.PostFormValue("refresh"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return connect.NewError(connect.CodeInvalidArgument, errRefresh)
		}
		reg.Refresh = durationpb.New(d)
	}
	if _, err := p.opts.Client.AddTrustRegistry(r.Context(), call(s, &adminv1.AddTrustRegistryRequest{Registry: reg})); err != nil {
		return err
	}
	p.redirect(w, r, "/trust/registries", "registry-added")
	return nil
}

// syncRegistry reads one registry now. A failed read shows a warning.
func (p *Portal) syncRegistry(w http.ResponseWriter, r *http.Request, s session) error {
	res, err := p.opts.Client.SyncTrustRegistry(r.Context(), call(s, &adminv1.SyncTrustRegistryRequest{Id: r.PathValue("id")}))
	if err != nil {
		return err
	}
	code := "registry-synced"
	if res.Msg.GetRegistry().GetLastError() != "" {
		code = "registry-sync-failed"
	}
	p.redirect(w, r, "/trust/registries", code)
	return nil
}

// removeRegistry stops the federation with one registry.
func (p *Portal) removeRegistry(w http.ResponseWriter, r *http.Request, s session) error {
	if _, err := p.opts.Client.RemoveTrustRegistry(r.Context(), call(s, &adminv1.RemoveTrustRegistryRequest{Id: r.PathValue("id")})); err != nil {
		return err
	}
	p.redirect(w, r, "/trust/registries", "registry-removed")
	return nil
}

// link is an escaped link to an address in the monospace face.
func link(href string) template.HTML {
	e := template.HTMLEscapeString(href)
	return template.HTML(`<a href="` + e + `" rel="noopener"><code>` + e + `</code></a>`) //nolint:gosec // the address is escaped
}

// code is an escaped value in the monospace face.
func code(v string) template.HTML {
	return template.HTML(`<code>` + template.HTMLEscapeString(v) + `</code>`) //nolint:gosec // the value is escaped
}

// publicationLabel names a local list by its method.
func publicationLabel(m trustv1.Method) string {
	if m == trustv1.Method_METHOD_DEDI {
		return msg.T("admin.registries.method.dedi.label")
	}
	return msg.T("admin.registries.method.lote.label")
}

// registryMethodLabel names the format of an external registry.
func registryMethodLabel(m trustv1.RegistryMethod) string {
	for _, rm := range registryMethods {
		if rm.proto == m {
			return msg.T(rm.key)
		}
	}
	return ""
}

// anchorLabel names the kind of anchor of an external registry.
func anchorLabel(a *trustv1.Registry_Anchor) string {
	if a.GetX509Certificate() != "" {
		return msg.T("admin.registries.anchor.x509.label")
	}
	return msg.T("admin.registries.anchor.jwks.label")
}
