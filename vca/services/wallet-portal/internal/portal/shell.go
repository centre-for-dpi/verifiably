// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"context"
	"html/template"
	"net/http"
	"strconv"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/internal/rolenav"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/session"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// user draws the user menu of the wallet session: the name the IdP gave,
// and the sign out form with the synchronizer token of the wallet. A
// request with no session draws no menu.
func (p *Portal) user(r *http.Request) components.User {
	who, ok := session.From(r.Context())
	if !ok {
		return components.User{}
	}
	name := who.Name
	if name == "" {
		name = msg.T("holder.user.label")
	}
	return components.User{
		Name: name, SignOut: p.opts.Prefix + "/signout",
		CSRF: p.opts.Guard.Token(who), CSRFField: session.Field,
	}
}

// signOut ends the wallet session. The synchronizer token of the wallet
// guards the form. The wallet-auth service of the own pair ends the
// session, the cookie goes, and the browser follows the logout URL of
// the provider or goes to the login page.
func (p *Portal) signOut(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.writer(w, r); !ok {
		return
	}
	o := staffshell.SignOutOptions{
		Cookie: session.CookieName, Secure: p.opts.Topology.SecureCookie, After: p.opts.LoginPath,
	}
	if logout, auth := p.opts.Topology.Logout, p.shell.AuthURL(); logout != nil && auth != "" {
		o.Logout = func(ctx context.Context, token string) (string, error) { return logout(ctx, auth, token) }
	}
	staffshell.SignOut(o).ServeHTTP(w, r)
}

// helpPages names what each wallet page does, keyed by its path.
var helpPages = map[string]string{
	"/wallet/":         "holder.help.page.credentials",
	"/wallet/discover": "holder.help.page.discover",
	"/wallet/claim":    "holder.help.page.claim",
	"/wallet/present":  "holder.help.page.present",
	"/wallet/keys":     "holder.help.page.keys",
	"/wallet/help":     "holder.help.page.help",
}

// help renders what each page of the wallet does. It lists only the
// pages this deployment shows.
func (p *Portal) help(w http.ResponseWriter, r *http.Request) error {
	b := p.pen(r)
	var rows []components.Row
	for _, s := range rolenav.Visible(commonv1.Role_ROLE_HOLDER, b.frame.Has) {
		for _, page := range s.Pages {
			rows = append(rows, components.Row{
				{HTML: b.raw(`<a href="` + template.HTMLEscapeString(page.Path) + `">` +
					template.HTMLEscapeString(page.Label()) + `</a>`)},
				{Text: msg.T(helpPages[page.Path])},
			})
		}
	}
	table := b.part("table", components.Table{
		ID: "page-list", Caption: msg.T("holder.help.caption.label", strconv.Itoa(len(rows))),
		Columns: []string{msg.T("holder.help.column.page.label"), msg.T("holder.help.column.text.label")},
		Rows:    rows,
	})
	return p.render(w, r, b, components.Page{
		Title: msg.T("common.help.label"), Lead: msg.T("holder.help.lead"), Description: msg.T("holder.help.lead"),
		Content: table,
	})
}

// keys renders the holder identifier and the holder key of the wallet.
// The page exists only when the wallet of the own stack manages keys
// (ADR-034 decision 5).
func (p *Portal) keys(w http.ResponseWriter, r *http.Request) error {
	b := p.pen(r)
	if !b.frame.Has(backendv1.Feature_FEATURE_WALLET_KEYS) {
		http.NotFound(w, r)
		return nil
	}
	did := b.who.HolderDID
	if did == "" {
		did = msg.T("holder.keys.none")
	}
	key := msg.T("holder.keys.key.stack")
	if b.who.HasHolderKey {
		key = msg.T("holder.keys.key.browser")
	}
	table := b.part("table", components.Table{
		ID: "holder-keys", Caption: msg.T("holder.keys.caption.label"),
		Columns: []string{msg.T("holder.keys.column.item.label"), msg.T("holder.keys.column.value.label")},
		Rows: []components.Row{
			{{Text: msg.T("holder.keys.did.label")}, {HTML: b.raw(`<span class="mono">` + template.HTMLEscapeString(did) + `</span>`)}},
			{{Text: msg.T("holder.keys.key.label")}, {Text: key}},
		},
	})
	return p.render(w, r, b, components.Page{
		Title: msg.T("holder.nav.keys.label"), Lead: msg.T("holder.keys.lead"), Description: msg.T("holder.keys.lead"),
		Content: table,
	})
}
