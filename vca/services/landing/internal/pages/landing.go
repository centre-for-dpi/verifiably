// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// landing serves the front page (ADR-033 decisions 3 and 4).
func (p *Pages) landing(w http.ResponseWriter, r *http.Request) {
	view, _ := p.overview(r)
	hero, err := p.hero(view)
	if err != nil {
		http.Error(w, msg.T("common.render_failed"), http.StatusInternalServerError)
		return
	}
	primer, err := p.primer()
	if err != nil {
		http.Error(w, msg.T("common.render_failed"), http.StatusInternalServerError)
		return
	}
	stacks, err := p.stacksBlock(view)
	if err != nil {
		http.Error(w, msg.T("common.render_failed"), http.StatusInternalServerError)
		return
	}
	cta, err := p.cta(view)
	if err != nil {
		http.Error(w, msg.T("common.render_failed"), http.StatusInternalServerError)
		return
	}
	page := p.page("/", msg.T("landing.hero.label"), components.Join(primer, stacks, cta))
	page.Hero = hero
	page.Description = msg.T("landing.hero.lead")
	p.render(w, r, http.StatusOK, page)
}

// stacks serves the stacks block alone, for the htmx refresh.
func (p *Pages) stacks(w http.ResponseWriter, r *http.Request) {
	view, _ := p.overview(r)
	block, err := p.stacksBlock(view)
	if err != nil {
		http.Error(w, msg.T("common.render_failed"), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	anyval.DiscardWrite(w.Write([]byte(block)))
}

// entry is the way in that the state of the deployment gives: the role
// picker with several live roles, the one live role alone, or nothing.
type entry struct {
	// Href is the target of the primary action. Empty means no action.
	Href string
	// Text is the label of the primary action.
	Text string
	// Role is the one live role, when there is one.
	Role *Role
}

// entryOf picks the way in.
func entryOf(view Overview) entry {
	live := view.LiveRoles()
	switch len(live) {
	case 0:
		return entry{}
	case 1:
		role := live[0]
		return entry{Href: "/roles/" + role.ID + "/", Text: msg.T("landing.one_role.continue.label", role.ID), Role: &role}
	default:
		return entry{Href: "/roles/", Text: msg.T("landing.hero.start.label")}
	}
}

// hero builds the opening block.
func (p *Pages) hero(view Overview) (*components.Hero, error) {
	way := entryOf(view)
	hero := &components.Hero{
		Label: msg.T("landing.hero.label"),
		Title: msg.T("landing.hero.title"),
		Lead:  msg.T("landing.hero.lead"),
	}
	if way.Href != "" {
		hero.Actions = []components.Button{
			{Text: way.Text, Href: way.Href, Variant: "primary"},
			{Text: msg.T("landing.hero.primer"), Href: "#how", Variant: "ghost"},
		}
	}
	note := components.Note{Label: msg.T("landing.none.label"), Text: msg.T("landing.stacks.none")}
	if way.Role != nil {
		stacks := view.StackNames(way.Role.Live())
		note = components.Note{Label: msg.T("landing.one_role.label"), Text: msg.T("landing.one_role.text", way.Role.ID, joinNames(stacks))}
	}
	if way.Role != nil || way.Href == "" {
		aside, err := p.html("note", note)
		if err != nil {
			return nil, err
		}
		hero.Aside = aside
	}
	return hero, nil
}

// lowerFirst lowers the first letter of a sentence that follows a comma.
func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// joinNames joins names with commas and a final "and".
func joinNames(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	default:
		return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
	}
}

// primer builds the "How it works" block with the three tiles.
func (p *Pages) primer() (template.HTML, error) {
	figure, err := p.html("figure", triangle())
	if err != nil {
		return "", err
	}
	tiles, err := p.html("tiles", components.Tiles{Columns: 3, Items: []components.Tile{
		{Num: "01", Title: msg.T("landing.how.dpg.label"), Text: msg.T("landing.how.dpg.text"), Meta: msg.T("landing.how.dpg.link.label"), Href: dpgStandardURL},
		{Num: "02", Title: msg.T("landing.how.vc.label"), Text: msg.T("landing.how.vc.text"), Meta: msg.T("landing.how.vc.link.label"), Href: vcDataModelURL},
		{Num: "03", Title: msg.T("landing.how.triangle.label"), Text: msg.T("landing.how.triangle.text"), Figure: figure, Meta: msg.T("landing.how.triangle.link.label"), Href: ecosystemURL},
	}})
	if err != nil {
		return "", err
	}
	return p.html("block", components.Block{ID: "how", Title: msg.T("landing.how.title"), Lead: msg.T("landing.how.lead"), Body: tiles})
}

// stacksBlock builds the "Stacks on this deployment" block. The block
// refreshes itself through htmx every 30 seconds.
func (p *Pages) stacksBlock(view Overview) (template.HTML, error) {
	block := components.Block{
		ID: "stacks", Title: msg.T("landing.stacks.label"), Lead: msg.T("landing.stacks.lead"),
		Meta:  msg.T("landing.stacks.meta.label", p.opts.Version) + ", " + lowerFirst(msg.T("common.updated.label", p.opts.Now().UTC().Format("15:04 MST"))),
		Attrs: map[string]string{"hx-get": "/stacks", "hx-trigger": refreshEvery, "hx-swap": "outerHTML"},
	}
	if len(view.Stacks) == 0 {
		block.Lead = msg.T("landing.stacks.none")
		return p.html("block", block)
	}
	cards := make([]components.StackCard, 0, len(view.Stacks))
	for _, s := range view.Stacks {
		cards = append(cards, stackCard(s))
	}
	body, err := p.html("stacks", components.Stacks{
		Items: cards, ComponentsLabel: msg.T("landing.stacks.components.label"), RolesLabel: msg.T("landing.stacks.roles.label"),
	})
	if err != nil {
		return "", err
	}
	block.Body = body
	return p.html("block", block)
}

// stackCard turns one stack into its card.
func stackCard(s Stack) components.StackCard {
	card := components.StackCard{ID: "stack-" + s.ID, Name: s.Name()}
	if v := s.Info.GetVersion(); v != "" {
		card.Version = msg.T("landing.stacks.pinned.label", v)
	}
	for _, c := range s.Info.GetComponents() {
		row := components.Component{Name: c.GetName()}
		if c.GetVersion() != "" {
			row.Version = msg.T("landing.stacks.component.label", c.GetVersion())
		}
		if c.GetRepositoryUrl() != "" {
			row.RepoHref, row.RepoText = c.GetRepositoryUrl(), msg.T("common.github.label")
		}
		if c.GetDocsUrl() != "" {
			row.DocsHref, row.DocsText = c.GetDocsUrl(), msg.T("common.documentation.label")
		}
		card.Components = append(card.Components, row)
	}
	for _, pair := range s.Pairs {
		row := components.RoleRow{Label: roleLabel(pair.Peer.Role), State: "starting", Text: msg.T("shell.starting.label")}
		if pair.State == topology.Live {
			row.State, row.Text = "live", msg.T("common.live.label")
		}
		card.Roles = append(card.Roles, row)
	}
	return card
}

// cta builds the call to action band, or nothing without a live role.
func (p *Pages) cta(view Overview) (template.HTML, error) {
	way := entryOf(view)
	if way.Href == "" {
		return "", nil
	}
	band := components.CTA{
		ID: "start", Title: msg.T("landing.cta.title"), Text: msg.T("landing.cta.lead"),
		Action: components.Button{Text: way.Text, Href: way.Href, Variant: "primary"},
	}
	if way.Role != nil {
		band.Title, band.Text = msg.T("landing.cta.one_role.title"), msg.T("landing.cta.one_role.lead")
	}
	return p.html("cta", band)
}
