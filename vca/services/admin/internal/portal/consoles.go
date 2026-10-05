// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"connectrpc.com/connect"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// Each auth service of a live pair keeps the providers that setup wrote
// for its role, such as the Keycloak realm of the holders (ADR-035
// decision 5). The admin reads them with its session, so the overview
// and the providers page list every provider in use. A record that
// names its management console gets a link that sends the browser
// there.

// pairHeld is what the auth service of one live pair holds.
type pairHeld struct {
	pair      string
	role      string
	auth      string
	providers []oidcflow.Provider
	// down says that the auth service did not answer.
	down bool
}

// authPeers lists the live pairs with an auth service, in snapshot
// order.
func authPeers(f frame) []topology.Peer {
	var out []topology.Peer
	for _, st := range f.snap.Live() {
		if st.Peer.Auth() != "" {
			out = append(out, st.Peer)
		}
	}
	return out
}

// pairProviders reads the providers of the auth service of every live
// pair. A service that does not answer gives a held record marked down.
func (p *Portal) pairProviders(ctx context.Context, f frame, s session) []pairHeld {
	peers := authPeers(f)
	out := make([]pairHeld, 0, len(peers))
	for _, peer := range peers {
		held := pairHeld{pair: peer.Pair, role: roleWord(peer.Role.String()), auth: peer.Auth()}
		res, err := p.signInClient(peer.Auth()).ListAuthProviders(ctx, call(s, &adminv1.ListAuthProvidersRequest{}))
		if err != nil {
			held.down = true
		} else {
			for _, m := range res.Msg.GetProviders() {
				held.providers = append(held.providers, oidcflow.FromAdminProto(m))
			}
		}
		out = append(out, held)
	}
	return out
}

// roleWord turns ROLE_HOLDER into holder.
func roleWord(enum string) string {
	return strings.ToLower(strings.TrimPrefix(enum, "ROLE_"))
}

// pairBlock lists the providers of each pair: the pair, the provider,
// its realm or issuer, and its state.
func (p *Portal) pairBlock(b *blocks, pairs []pairHeld) template.HTML {
	if len(pairs) == 0 {
		return ""
	}
	var rows []components.Row
	for _, held := range pairs {
		if held.down {
			rows = append(rows, components.Row{{Text: held.pair}, {Text: msg.T("admin.pairs.down")}, {Text: ""}, {Text: ""}})
			continue
		}
		for _, pr := range held.providers {
			state := components.Badge{Status: "warn", Text: msg.T("admin.providers.disabled.label")}
			if pr.Enabled {
				state = components.Badge{Status: "ok", Text: msg.T("admin.providers.enabled.label")}
			}
			rows = append(rows, components.Row{
				{Text: held.pair}, {Text: pr.DisplayName}, {Text: realmOrIssuer(pr)}, {HTML: b.add("badge", state)},
			})
		}
	}
	return b.add("card", components.Card{
		ID: "pair-providers", Title: msg.T("admin.pairs.title.label"), Text: msg.T("admin.pairs.lead"),
		Body: b.add("table", components.Table{
			ID: "pair-provider-rows", Caption: msg.T("admin.pairs.caption.label"),
			Columns: []string{
				msg.T("admin.pairs.column.pair.label"), msg.T("admin.providers.column.provider.label"),
				msg.T("admin.providers.column.realm.label"), msg.T("admin.providers.column.state.label"),
			},
			Rows: rows, Empty: msg.T("admin.pairs.empty"),
		}),
	})
}

// consolesCard lists every provider that names its management console,
// with a link through the console route of the admin.
func (p *Portal) consolesCard(b *blocks, own []oidcflow.Provider, pairs []pairHeld) template.HTML {
	at := p.opts.Prefix + "/providers/"
	var rows []components.Row
	row := func(pr oidcflow.Provider, where, href string) {
		if consoleOf(pr) == "" {
			return
		}
		link := template.HTML(`<a href="` + template.HTMLEscapeString(href) + `">` + //nolint:gosec // both parts are escaped
			template.HTMLEscapeString(msg.T("admin.consoles.open.label", realmOrIssuer(pr))) + `</a>`)
		rows = append(rows, components.Row{{Text: pr.DisplayName}, {Text: where}, {HTML: link}})
	}
	for _, pr := range own {
		row(pr, msg.T("admin.consoles.here.label"), at+url.PathEscape(pr.ID)+"/console")
	}
	for _, held := range pairs {
		for _, pr := range held.providers {
			row(pr, held.pair, at+"pairs/"+url.PathEscape(held.pair)+"/"+url.PathEscape(pr.ID)+"/console")
		}
	}
	if len(rows) == 0 {
		return ""
	}
	return b.add("card", components.Card{
		ID: "consoles", Title: msg.T("admin.consoles.title.label"), Text: msg.T("admin.consoles.lead"),
		Body: b.add("table", components.Table{
			ID: "console-rows", Caption: msg.T("admin.consoles.caption.label"),
			Columns: []string{
				msg.T("admin.providers.column.provider.label"), msg.T("admin.consoles.column.where.label"),
				msg.T("admin.consoles.column.console.label"),
			},
			Rows: rows,
		}),
	})
}

// consoleOf returns the console of a record when it is an http or https
// address, else "".
func consoleOf(pr oidcflow.Provider) string {
	return httpURL(pr.ConsoleURL)
}

// httpURL returns an absolute http or https address, else "".
func httpURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	return u.String()
}

// noConsole reports a provider without a console.
func noConsole() error {
	return connect.NewError(connect.CodeNotFound, errors.New("portal: the provider names no management console"))
}

// console sends the browser to the management console of a provider of
// this admin.
func (p *Portal) console(w http.ResponseWriter, r *http.Request, s session) error {
	got, err := p.opts.Client.GetAuthProvider(r.Context(), call(s, &adminv1.GetAuthProviderRequest{Id: r.PathValue("id")}))
	if err != nil {
		return err
	}
	target := consoleOf(oidcflow.FromAdminProto(got.Msg.GetProvider()))
	if target == "" {
		return noConsole()
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
	return nil
}

// pairConsole sends the browser to the management console of a provider
// that the auth service of a live pair holds.
func (p *Portal) pairConsole(w http.ResponseWriter, r *http.Request, s session) error {
	for _, held := range p.pairProviders(r.Context(), p.frame(r.Context()), s) {
		if held.pair != r.PathValue("pair") {
			continue
		}
		for _, pr := range held.providers {
			if pr.ID == r.PathValue("id") && consoleOf(pr) != "" {
				http.Redirect(w, r, consoleOf(pr), http.StatusSeeOther)
				return nil
			}
		}
	}
	return noConsole()
}

// defaultProvider makes one provider the default. The admin service
// takes the flag from every other record.
func (p *Portal) defaultProvider(w http.ResponseWriter, r *http.Request, s session) error {
	got, err := p.opts.Client.GetAuthProvider(r.Context(), call(s, &adminv1.GetAuthProviderRequest{Id: r.PathValue("id")}))
	if err != nil {
		return err
	}
	record := got.Msg.GetProvider()
	record.IsDefault = true
	if _, err := p.opts.Client.UpdateAuthProvider(r.Context(), call(s, &adminv1.UpdateAuthProviderRequest{Provider: record})); err != nil {
		return err
	}
	p.redirect(w, r, "/providers", "provider-default")
	return nil
}
