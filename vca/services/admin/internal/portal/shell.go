// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"context"
	"net/http"
	"sort"
	"strings"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/internal/rolenav"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// SignOutPath is the action of the sign out form of the shell.
const SignOutPath = "/auth/logout"

// role is the shell role of the admin portal.
const role = "admin"

// frame is what one page knows about its shell: the snapshot of the
// peers and the provider records, read once per request.
type frame struct {
	snap      topology.Snapshot
	hasPeers  bool
	providers []oidcflow.Provider
}

// frame reads the peers and the providers for the shell of one page.
func (p *Portal) frame(ctx context.Context) frame {
	f := frame{providers: p.opts.Login.Providers().List()}
	if p.opts.Snapshot != nil {
		f.snap, f.hasPeers = p.opts.Snapshot(ctx), true
	}
	return f
}

// has reports whether any live pair of the deployment lists a feature.
// The admin portal gates on the deployment, not on one pair.
func (f frame) has(feature backendv1.Feature) bool {
	for _, st := range f.snap.Live() {
		if st.Has(feature) {
			return true
		}
	}
	return false
}

// shell builds the portal frame of one page: the role chip, the stack
// switcher over the admin pairs, the user menu, and the side navigation
// from the rolenav table plus one console link per identity realm.
func (p *Portal) shell(f frame, s session, current string) *components.Shell {
	sh := &components.Shell{
		Role:      role,
		RoleLabel: msg.T("role.admin.label"),
		Stacks:    p.stacks(f),
		Sections:  rolenav.Nav(commonv1.Role_ROLE_ADMIN, f.has, current),
	}
	if name := displayName(s.Claims); name != "" && s.Claims.Subject != "" {
		sh.User = components.User{Name: name, SignOut: SignOutPath, CSRF: s.CSRF, CSRFField: oidcflow.CSRFField}
	}
	if links := consoleLinks(f.providers); len(links) > 0 {
		sh.Sections = append(sh.Sections, components.NavSection{Label: msg.T("admin.nav.console.label"), Links: links})
	}
	return sh
}

// stacks lists the admin pairs of the deployment that are not absent,
// in stack order: one link per live pair to its admin portal, with this
// pair marked current, and a starting pair as text (ADR-034 decision 3).
func (p *Portal) stacks(f frame) []components.StackLink {
	if !f.hasPeers {
		return nil
	}
	var out []components.StackLink
	for _, st := range f.snap.ForRole(commonv1.Role_ROLE_ADMIN) {
		link := components.StackLink{
			Name:    stackName(f.snap, st.Peer.Dpg),
			Href:    strings.TrimRight(st.Peer.PublicURL, "/") + topology.HomePath(commonv1.Role_ROLE_ADMIN),
			Current: strings.TrimRight(st.Peer.PublicURL, "/") == p.opts.PublicURL,
		}
		if st.State != topology.Live {
			link.State = "starting"
			link.Href = ""
		}
		out = append(out, link)
	}
	return out
}

// stackName returns the display name of a stack: the name the first
// live adapter of the stack reports, or the short name of the enum
// value until an adapter answers (ADR-001 decision 4).
func stackName(snap topology.Snapshot, d configv1.Dpg) string {
	for _, st := range snap.Live() {
		if st.Peer.Dpg == d {
			if name := st.Capabilities.GetDpgInfo().GetDisplayName(); name != "" {
				return name
			}
		}
	}
	return shortName(d.String())
}

// shortName turns an enum name such as DPG_WALTID into waltid.
func shortName(name string) string {
	if i := strings.Index(name, "_"); i >= 0 {
		name = name[i+1:]
	}
	return strings.ToLower(name)
}

// consoleLinks returns one link per identity console the provider
// records name: a record of kind keycloak carries the console of its
// realm (ADR-035 decision 2). Two records of one realm give one link.
// The links sort by realm, so the list is stable.
func consoleLinks(providers []oidcflow.Provider) []components.Link {
	seen := map[string]bool{}
	var out []components.Link
	for _, pr := range providers {
		if pr.Kind != oidcflow.KindKeycloak || pr.ConsoleURL == "" || seen[pr.ConsoleURL] {
			continue
		}
		seen[pr.ConsoleURL] = true
		text := pr.Realm
		if text == "" {
			text = pr.DisplayName
		}
		out = append(out, components.Link{Href: pr.ConsoleURL, Text: text})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Text < out[j].Text })
	return out
}

// adminConsole returns the console of the realm the admins sign in
// through, or "" when no keycloak record lists the admin role.
func adminConsole(providers []oidcflow.Provider) string {
	for _, pr := range providers {
		if pr.Kind != oidcflow.KindKeycloak || pr.ConsoleURL == "" || !pr.Enabled {
			continue
		}
		for _, r := range pr.Roles {
			if r == role {
				return pr.ConsoleURL
			}
		}
	}
	return ""
}

// render writes a shell page. It reads the frame first.
func (p *Portal) render(w http.ResponseWriter, r *http.Request, s session, page components.Page) error {
	return p.renderWith(w, r, s, p.frame(r.Context()), page)
}

// renderWith writes a shell page from a frame the caller read. The
// wordmark leads to the overview.
func (p *Portal) renderWith(w http.ResponseWriter, r *http.Request, s session, f frame, page components.Page) error {
	page.Shell = p.shell(f, s, r.URL.Path)
	page.Nav = components.Nav{Label: msg.T("shell.main_nav.label"), Brand: components.Link{Href: p.opts.Prefix + "/"}}
	return p.opts.Kit.RenderPage(w, r, page)
}
