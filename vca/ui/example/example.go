// SPDX-License-Identifier: Apache-2.0

// Package example builds the kit page: one page that uses every
// component of the kit. It shows how a service mounts the assets and
// composes a page. The content names the components, not a person, an
// issuer or a credential (ADR-050 decision 1). No service imports the
// package.
package example

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/centre-for-dpi/vc-adapters/ui"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// Handler returns the kit server: assets under /static/, the kit page
// at /, the sign in chooser at /signin, and a toast partial at /toast
// for the htmx button. The assets and the kit share one config, so the
// layout draws the brand the assets serve.
func Handler() (http.Handler, error) {
	cfg := ui.DefaultConfig()
	assets, err := ui.AssetsFor(cfg)
	if err != nil {
		return nil, err
	}
	kit, err := components.New(components.WithBrand(cfg.Brand))
	if err != nil {
		return nil, err
	}
	return Mux(assets, kit, KitPage), nil
}

// PageFunc builds the page a request shows.
type PageFunc func(kit *components.Kit) (components.Page, error)

// Mux wires the assets, the kit, and the page builder into one handler.
func Mux(assets http.Handler, kit *components.Kit, build PageFunc) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET "+ui.Prefix, assets)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		serve(w, func() error {
			page, err := build(kit)
			if err != nil {
				return err
			}
			return kit.RenderPage(w, r, page)
		})
	})
	mux.HandleFunc("GET /signin", func(w http.ResponseWriter, r *http.Request) {
		serve(w, func() error {
			page, err := SignInPage(kit)
			if err != nil {
				return err
			}
			return kit.RenderPage(w, r, page)
		})
	})
	mux.HandleFunc("GET /toast", func(w http.ResponseWriter, r *http.Request) {
		serve(w, func() error {
			toast := components.Toast{Level: "ok", Text: "Toast text " + r.URL.Query().Get("t"), OOB: true}
			return kit.Render(w, "toast", toast)
		})
	})
	return mux
}

// serve runs fn and answers 500 when it fails. The error text stays in the
// server log, not in the response.
func serve(w http.ResponseWriter, fn func() error) {
	if err := fn(); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
	}
}

// KitPage composes one page from every component. Each text names the
// part of the component it fills.
func KitPage(kit *components.Kit) (components.Page, error) {
	// The parts other components embed render first, in one pass.
	pre := map[string]template.HTML{}
	for name, data := range map[string]any{
		"badge": components.Badge{Status: "ok", Text: "Badge text"},
		"figure": components.Figure{ID: "triangle", Title: "Figure title", ViewBox: "0 0 320 200",
			Caption: "Figure caption.",
			SVG: `<path class="fig-edge" d="M60 160 L160 40 L260 160 Z"/><circle class="fig-node" cx="60" cy="160" r="26"/>` +
				`<circle class="fig-node" cx="160" cy="40" r="26"/><circle class="fig-node" cx="260" cy="160" r="26"/>` +
				`<text class="fig-text" x="60" y="164">Node 1</text><text class="fig-text" x="160" y="44">Node 2</text>` +
				`<text class="fig-text" x="260" y="164">Node 3</text><text class="fig-label" x="160" y="180" text-anchor="middle">Edge label</text>`},
		"stacks": components.Stacks{Items: []components.StackCard{{
			ID: "stack-card", Name: "Stack name", Version: "Version text",
			Components: []components.Component{{Name: "component-name", Version: "version text", RepoHref: "/", RepoText: "Repository link", DocsHref: "/", DocsText: "Documentation link"}},
			Roles:      []components.RoleRow{{Label: "Role 1", State: "live", Text: "Live"}, {Label: "Role 2", State: "starting", Text: "Starting"}},
		}}},
		"note": components.Note{Label: "Note", Text: "Every component renders on this page, in both themes."},
	} {
		h, err := kit.HTML(name, data)
		if err != nil {
			return components.Page{}, err
		}
		pre[name] = h
	}
	okBadge, figure, stacks, note := pre["badge"], pre["figure"], pre["stacks"], pre["note"]
	nested, err := kit.HTML("field", components.Field{ID: "group-field", Name: "group.field", Label: "Field in a group", Required: true})
	if err != nil {
		return components.Page{}, err
	}
	steps := []struct {
		name string
		data any
	}{
		{"tabs", components.Tabs{Label: "Kit views", Links: []components.Link{
			{Href: "/", Text: "Components", Current: true}, {Href: "/signin", Text: "Sign in"},
		}}},
		{"stepper", components.Stepper{Label: "Stepper label", Steps: []string{"Step 1", "Step 2", "Step 3"}, Current: 2}},
		{"steps", components.Steps{Items: []components.Step{
			{Title: "Step title 1", Text: "Step text of a done step.", State: "done"},
			{Title: "Step title 2", Text: "Step text of the current step.", State: "current", Href: "/", LinkText: "Step link"},
			{Title: "Step title 3", Text: "Step text of a locked step.", State: "locked"},
			{Title: "Step title 4", Text: "Step text of a step with no state."},
		}}},
		{"stat", components.Stat{Label: "Stat label", Value: "Stat value", Text: "Stat text.", Href: "/", LinkText: "Stat link"}},
		{"checklist", components.Checklist{ID: "checklist", Title: "Checklist title", Note: "Checklist note",
			Items: []components.Check{
				{Text: "Check text 1", Detail: "Check detail 1", Done: true},
				{Text: "Check text 2", Detail: "Check detail 2"},
			}}},
		{"choice", components.Choice{ID: "choice", Legend: "Choice legend", Hint: "Choice hint.",
			Options: []components.ChoiceOption{
				{Value: "one", Title: "Option title 1", Text: "Option text 1.", Checked: true},
				{Value: "two", Title: "Option title 2", Text: "Option text 2.", Meta: "Option meta"},
			}}},
		{"credentials", components.Credentials{Label: "Card list label", Items: []components.CredentialCard{
			{ID: "card-1", Issuer: "Card source 1", Title: "Card title 1", Status: "ok", StatusText: "Status text", Meta: "Card meta 1"},
			{ID: "card-2", Issuer: "Card source 2", Title: "Card title 2", Status: "warn", StatusText: "Status text", Meta: "Card meta 2"}},
			Add: components.Link{Href: "/", Text: "Add link"}}},
		{"dcapi", components.DCAPI{Text: "Device wallet button", Offer: "openid-credential-offer://?credential_offer_uri=%2Foffers%2F1",
			OK: "Success text.", Cancel: "Cancel text.", Fail: "Failure text."}},
		{"fieldset", components.Fieldset{ID: "group", Legend: "Group legend", Hint: "Group hint.",
			Body: nested}},
		{"code", components.Code{ID: "code", Label: "Code label", Text: "openid-credential-offer://?credential_offer_uri=/offers/1"}},
		{"empty", components.Empty{Title: "Empty title", Text: "Empty text.",
			Action: components.Button{Text: "Empty action", Href: "/", Variant: "primary"}}},
		{"tiles", components.Tiles{Items: []components.Tile{
			{Num: "Tile 1", Title: "Tile title 1", Text: "Tile text 1.", Meta: "Tile meta", Href: "/"},
			{Num: "Tile 2", Title: "Tile title 2", Text: "Tile text 2.", Href: "/"},
			{Num: "03", Title: "Tile title 3", Text: "Tile text with a figure.", Figure: figure, Meta: "Tile meta", Href: "/"},
		}}},
		{"block", components.Block{ID: "block", Title: "Block title", Lead: "Block lead.", Meta: "Block meta", Body: stacks}},
		{"cta", components.CTA{ID: "cta", Title: "Call to action title.", Text: "Call to action text.", Action: components.Button{Text: "Start", Href: "/", Variant: "primary"}}},
		{"card", components.Card{ID: "card", Title: "Card title", Text: "Card text.", Body: okBadge, Footer: "Card footer"}},
		{"table", components.Table{Caption: "Table caption", Columns: []string{"Column 1", "Column 2"}, Rows: []components.Row{
			{{Text: "Row 1"}, {HTML: okBadge}},
			{{Text: "Row 2"}, {HTML: okBadge}},
		}}},
		{"field", components.Field{ID: "text-field", Label: "Text field", Hint: "Field hint.", Required: true, Autocomplete: "off"}},
		{"field", components.Field{ID: "select-field", Label: "Select field", Type: "select", Options: []components.Option{{Value: "one", Text: "Option 1", Selected: true}}}},
		{"button", components.Button{Text: "Show a toast", Type: "submit", Variant: "primary", Attrs: map[string]string{"hx-get": "/toast?t=now", "hx-swap": "none"}}},
		{"button", components.Button{Text: "Toggle the JSON", Controls: "raw", Expanded: true}},
		{"json", components.JSON{ID: "raw", Summary: "JSON summary", Open: true, Data: map[string]any{"key": "value", "list": []string{"item"}}}},
		{"qr", components.QR{Src: "data:image/gif;base64,R0lGODlhAQABAAAAACw=", Alt: "QR code: the code text", Size: 160}},
		{"button", components.Button{Text: "Open the dialog", Variant: "danger", Opens: "confirm"}},
		{"dialog", components.Dialog{ID: "confirm", Title: "Dialog title", Text: "Dialog text.",
			Actions: []components.Button{{Text: "Dialog action", Type: "submit", Variant: "danger", Value: "confirm"}}}},
	}
	parts := make([]template.HTML, 0, len(steps)+4)
	parts = append(parts, template.HTML(`<form action="/" method="get">`)) //nolint:gosec // literal
	for _, s := range steps {
		h, err := kit.HTML(s.name, s.data)
		if err != nil {
			return components.Page{}, err
		}
		if s.name == "stat" {
			h = components.Join(template.HTML(`<div class="stats">`), h, h, template.HTML(`</div>`)) //nolint:gosec // literal
		}
		parts = append(parts, h)
	}
	parts = append(parts, template.HTML(`</form>`)) //nolint:gosec // literal
	hero := &components.Hero{
		Label: "UI kit", Title: "Every component,", Emphasis: "one page.",
		Lead:    "The kit in the light and the dark theme, with the portal shell around it.",
		Actions: []components.Button{{Text: "Stylesheet", Href: "/static/vca.css", Variant: "primary"}},
		Aside:   note,
	}
	return components.Page{
		Title:       "vca UI kit",
		Hero:        hero,
		Description: "Every component of the vca UI kit on one page.",
		Nav: components.Nav{Brand: components.Link{Href: "/", Text: "UI kit"},
			Links: []components.Link{{Href: "/", Text: "Components", Current: true}, {Href: "/signin", Text: "Sign in"}, {Href: "/static/vca.css", Text: "Stylesheet"}}},
		Shell:   kitShell(),
		Toasts:  []components.Toast{{Level: "info", Text: "Toast text"}},
		Footer:  fmt.Sprintf("vca UI kit, htmx %s", ui.HTMXVersion),
		Content: components.Join(parts...),
	}, nil
}

// SignInPage composes the sign in chooser of a role: the block carries
// the h1, so the page has no other header.
func SignInPage(kit *components.Kit) (components.Page, error) {
	extra, err := kit.HTML("card", components.Card{
		ID: "bootstrap", Title: "Card title", Text: "Card text under the providers.",
	})
	if err != nil {
		return components.Page{}, err
	}
	return components.Page{
		Title:       "Sign in",
		Description: "The sign in chooser of the vca UI kit.",
		Nav: components.Nav{Brand: components.Link{Href: "/", Text: "UI kit"},
			Links: []components.Link{{Href: "/", Text: "Components"}, {Href: "/signin", Text: "Sign in", Current: true}}},
		SignIn: &components.SignIn{
			Role: "Admin", Title: "Sign in as an admin.",
			Lead: "Lead text of the sign in chooser.",
			Back: components.Link{Href: "/", Text: "Choose another role"}, Label: "Continue with",
			Providers: []components.SignInProvider{
				{Text: "Provider 1", Href: "/", Meta: "Provider meta 1"},
				{Text: "Provider 2", Href: "/", Meta: "Provider meta 2"},
			},
			CalloutLabel: "Callout label", Callout: "Callout text.",
			Extra:    extra,
			Register: []components.Button{{Text: "Register a new account", Href: "/", Variant: "ghost"}},
			Note:     "Note text of the sign in chooser.",
		},
		Footer: fmt.Sprintf("vca UI kit, htmx %s", ui.HTMXVersion),
	}, nil
}

// kitShell frames the kit page with the portal shell: three stack
// links, one of them starting, the user of the kit page, and two
// navigation sections.
func kitShell() *components.Shell {
	return &components.Shell{
		Role: "issuer",
		Stacks: []components.StackLink{
			{Name: "Stack 1", Href: "/", Current: true},
			{Name: "Stack 2", Href: "/?stack=2"},
			{Name: "Stack 3", State: "starting"},
		},
		User: components.User{Name: "Kit page", SignOut: "/auth/logout", CSRF: "kit-page"},
		Sections: []components.NavSection{
			{Links: []components.Link{{Href: "/", Text: "Overview", Current: true}}},
			{Label: "Kit", Links: []components.Link{{Href: "/static/vca.css", Text: "Stylesheet"}, {Href: "/toast?t=nav", Text: "Toast"}}},
		},
	}
}
