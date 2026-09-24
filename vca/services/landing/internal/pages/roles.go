// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"context"
	"html/template"
	"net/http"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/landing/internal/descriptor"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// roles serves the role picker (ADR-033 decision 5). It lists the live
// roles only. With one live role it sends the browser to that role.
func (p *Pages) roles(w http.ResponseWriter, r *http.Request) {
	view, _ := p.overview(r)
	live := view.LiveRoles()
	if len(live) == 1 {
		http.Redirect(w, r, "/roles/"+live[0].ID+"/", http.StatusFound)
		return
	}
	body, err := p.picker(view, live)
	if err != nil {
		http.Error(w, msg.T("common.render_failed"), http.StatusInternalServerError)
		return
	}
	page := p.page("/roles/", msg.T("roles.title"), body)
	page.Label = msg.T("landing.hero.label")
	page.Lead = msg.T("roles.lead")
	p.render(w, r, http.StatusOK, page)
}

// picker builds the tiles of the live roles and the admin band.
func (p *Pages) picker(view Overview, live []Role) (template.HTML, error) {
	if len(live) == 0 {
		return p.html("empty", components.Empty{
			Title: msg.T("roles.none.title"), Text: msg.T("roles.none.text"),
			Action: components.Button{Text: msg.T("common.back.label"), Href: "/", Variant: "primary"},
		})
	}
	var tiles []components.Tile
	var admin *Role
	for i := range live {
		role := live[i]
		if role.Role == commonv1.Role_ROLE_ADMIN {
			admin = &role
			continue
		}
		tiles = append(tiles, components.Tile{
			Num: role.Label(), Title: msg.T("roles." + role.ID + ".label"), Text: msg.T("roles." + role.ID + ".text"),
			Meta: msg.T("roles.available_on.label", joinNames(view.StackNames(role.Live()))), Href: "/roles/" + role.ID + "/",
		})
	}
	var parts []template.HTML
	if len(tiles) > 0 {
		grid, err := p.html("tiles", components.Tiles{Items: tiles, Columns: 3})
		if err != nil {
			return "", err
		}
		parts = append(parts, grid)
	}
	if admin != nil {
		band, err := p.html("cta", components.CTA{
			ID: "admin", Title: msg.T("roles.admin.title"), Text: msg.T("roles.admin.text"),
			Action: components.Button{Text: msg.T("roles.admin.label"), Href: "/roles/admin/", Variant: "primary"},
		})
		if err != nil {
			return "", err
		}
		parts = append(parts, band)
	}
	return components.Join(parts...), nil
}

// intro serves the intro page of one role (ADR-033 decision 6): the
// step cards of the live features, then the sign in action on the pair
// of the role.
func (p *Pages) intro(w http.ResponseWriter, r *http.Request) {
	role, ok := roleByID(r.PathValue("role"))
	if !ok {
		p.notFound(w, r)
		return
	}
	view, _ := p.overview(r)
	var live []topology.Status
	for _, candidate := range view.Roles {
		if candidate.Role == role {
			live = candidate.Live()
		}
	}
	id := descriptor.RoleID(role)
	page := p.page("/roles/"+id+"/", msg.T("intro."+id+".title"), "")
	page.Label = roleLabel(role)
	if len(live) == 0 {
		body, err := p.html("empty", components.Empty{
			Title:  msg.T("intro.not_live", id),
			Action: components.Button{Text: msg.T("intro.all_roles.label"), Href: "/roles/", Variant: "primary"},
		})
		if err != nil {
			http.Error(w, msg.T("common.render_failed"), http.StatusInternalServerError)
			return
		}
		page.Content = body
		p.render(w, r, http.StatusOK, page)
		return
	}
	items := stepsFor(role, live, view)
	steps, err := p.html("steps", components.Steps{Items: items})
	if err != nil {
		http.Error(w, msg.T("common.render_failed"), http.StatusInternalServerError)
		return
	}
	signin, err := p.signIn(r.Context(), role, view, live)
	if err != nil {
		http.Error(w, msg.T("common.render_failed"), http.StatusInternalServerError)
		return
	}
	back, err := p.html("button", components.Button{Text: msg.T("intro.all_roles.label"), Href: "/roles/", Variant: "ghost"})
	if err != nil {
		http.Error(w, msg.T("common.render_failed"), http.StatusInternalServerError)
		return
	}
	page.Lead = msg.T("intro.steps.lead", countWord(len(items)))
	page.Content = components.Join(steps, signin, back)
	p.render(w, r, http.StatusOK, page)
}

// roleByID reads a role from its short name.
func roleByID(id string) (commonv1.Role, bool) {
	for _, role := range roleOrder {
		if descriptor.RoleID(role) == id {
			return role, true
		}
	}
	return commonv1.Role_ROLE_UNSPECIFIED, false
}

// countWord returns the word of a small count, or the digits.
func countWord(n int) string {
	if n >= 1 && n <= 6 {
		return msg.T("number." + string(rune('0'+n)) + ".label")
	}
	return string(rune('0' + n))
}

// signIn builds the sign in block: one button on one live stack, one
// button per stack on several (ADR-033 decision 6). The first is the
// primary action. With one stack the sentence names the provider and
// the realm from the listing of its auth service (ADR-035).
func (p *Pages) signIn(ctx context.Context, role commonv1.Role, view Overview, live []topology.Status) (template.HTML, error) {
	label := func(pair topology.Status) string {
		if len(live) > 1 {
			return msg.T("intro.signin.stack.label", view.StackName(pair.Peer.Dpg))
		}
		return msg.T("intro.signin.continue.label")
	}
	text := msg.T("intro.signin.lead")
	if len(live) == 1 {
		if sentence, ok := p.realmSentence(ctx, role, live[0].Peer); ok {
			text = sentence
		}
	}
	var more []template.HTML
	for _, pair := range live[1:] {
		b, err := p.html("button", components.Button{Text: label(pair), Href: pair.Peer.SignInURL(), Variant: "secondary"})
		if err != nil {
			return "", err
		}
		more = append(more, b)
	}
	band := components.CTA{
		ID: "signin", Title: msg.T("intro.signin.label"), Text: text,
		Action: components.Button{Text: label(live[0]), Href: live[0].Peer.SignInURL(), Variant: "primary"},
	}
	if len(more) > 0 {
		band.More = components.Join(more...)
	}
	return p.html("cta", band)
}

// realmSentence reads the sign in listing of a pair and names its first
// provider and realm. A pair without an auth service, such as the admin,
// lists providers on its home service. An unreachable or empty listing
// gives false, and the band keeps its plain lead.
func (p *Pages) realmSentence(ctx context.Context, role commonv1.Role, peer topology.Peer) (string, bool) {
	base := peer.Auth()
	if base == "" {
		base = peer.Home()
	}
	listing, err := p.opts.Providers(ctx, base)
	if err != nil || len(listing.Providers) == 0 {
		return "", false
	}
	first := listing.Providers[0]
	who := msg.T("role." + descriptor.RoleID(role) + ".plural.label")
	sentence := msg.T("intro.signin.through", who, first.DisplayName)
	if first.Realm != "" {
		sentence = msg.T("intro.signin.realm", who, first.DisplayName, first.Realm)
	}
	if first.Register {
		sentence += " " + msg.T("intro.signin.register")
	}
	return sentence, true
}

// has reports whether one live pair lists the feature, protocol, or
// channel.
func has(live []topology.Status, want func(*backendv1.GetCapabilitiesResponse) bool) bool {
	for _, st := range live {
		if st.Capabilities != nil && want(st.Capabilities) {
			return true
		}
	}
	return false
}

func hasProtocol(live []topology.Status, p backendv1.Protocol) bool {
	return has(live, func(c *backendv1.GetCapabilitiesResponse) bool {
		for _, got := range c.GetProtocols() {
			if got == p {
				return true
			}
		}
		return false
	})
}

func hasChannel(live []topology.Status, ch backendv1.Channel) bool {
	return has(live, func(c *backendv1.GetCapabilitiesResponse) bool {
		for _, got := range c.GetChannels() {
			if got == ch {
				return true
			}
		}
		return false
	})
}

func hasFeature(live []topology.Status, f backendv1.Feature) bool {
	return has(live, func(c *backendv1.GetCapabilitiesResponse) bool {
		for _, got := range c.GetFeatures() {
			if got == f {
				return true
			}
		}
		return false
	})
}

// stepsFor returns the step cards of a role, filtered by what the live
// pairs can do (ADR-034 decision 5). Every step names a page the role
// gets after sign in.
func stepsFor(role commonv1.Role, live []topology.Status, view Overview) []components.Step {
	step := func(key string) components.Step {
		return components.Step{Title: msg.T("intro." + key + ".label"), Text: msg.T("intro." + key + ".text")}
	}
	switch role {
	case commonv1.Role_ROLE_ISSUER:
		issue := step("issuer.step3")
		if hasProtocol(live, backendv1.Protocol_PROTOCOL_OID4VCI) {
			issue.Text += " " + msg.T("intro.issuer.step3.oid4vci")
		}
		if hasChannel(live, backendv1.Channel_CHANNEL_PDF) {
			issue.Text += " " + msg.T("intro.issuer.step3.pdf")
		}
		return []components.Step{step("issuer.step1"), step("issuer.step2"), issue, step("issuer.step4")}
	case commonv1.Role_ROLE_HOLDER:
		var out []components.Step
		// Discovery needs an issuer to read, or a verifier whose
		// catalogue crawled one.
		for _, r := range view.LiveRoles() {
			if r.Role == commonv1.Role_ROLE_ISSUER || r.Role == commonv1.Role_ROLE_VERIFIER {
				out = append(out, step("holder.step1"))
				break
			}
		}
		return append(out, step("holder.step2"), step("holder.step3"), step("holder.step4"))
	case commonv1.Role_ROLE_VERIFIER:
		build := step("verifier.step2")
		build.Text += " " + msg.T("intro.verifier.step2.dcql")
		if hasProtocol(live, backendv1.Protocol_PROTOCOL_OID4VP_PEX) {
			build.Text += " " + msg.T("intro.verifier.step2.pe")
		}
		return []components.Step{step("verifier.step1"), build, step("verifier.step3"), step("verifier.step4")}
	default:
		out := []components.Step{step("admin.trust"), step("admin.registries"), step("admin.providers")}
		// Tenancy shows when one live stack of the deployment separates
		// tenants, whatever its role.
		if hasFeature(view.allLive(), backendv1.Feature_FEATURE_MULTI_TENANCY) {
			out = append(out, step("admin.tenants"))
		}
		return append(out, step("admin.keys"))
	}
}
