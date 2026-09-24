// SPDX-License-Identifier: Apache-2.0

// Package example builds a demo page that uses every component of the kit.
// It shows how a service mounts the assets and composes a page.
package example

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/centre-for-dpi/vc-adapters/ui"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// Handler returns the demo server: assets under /static/, the demo page at
// /, and a toast partial at /toast for the htmx button. The assets and the
// kit share one config, so the layout draws the brand the assets serve.
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
	return Mux(assets, kit, DemoPage), nil
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
	mux.HandleFunc("GET /toast", func(w http.ResponseWriter, r *http.Request) {
		serve(w, func() error {
			toast := components.Toast{Level: "ok", Text: "Checked at " + r.URL.Query().Get("t"), OOB: true}
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

// DemoPage composes one page from every component.
func DemoPage(kit *components.Kit) (components.Page, error) {
	// The parts other components embed render first, in one pass.
	pre := map[string]template.HTML{}
	for name, data := range map[string]any{
		"badge": components.Badge{Status: "ok", Text: "Valid"},
		"figure": components.Figure{ID: "triangle", Title: "The triangle of trust", ViewBox: "0 0 320 200",
			Caption: "Issuer, holder and verifier, with the trust registry between them.",
			SVG: `<path class="fig-edge" d="M60 160 L160 40 L260 160 Z"/><circle class="fig-node" cx="60" cy="160" r="26"/>` +
				`<circle class="fig-node" cx="160" cy="40" r="26"/><circle class="fig-node" cx="260" cy="160" r="26"/>` +
				`<text class="fig-text" x="60" y="164">Issuer</text><text class="fig-text" x="160" y="44">Holder</text>` +
				`<text class="fig-text" x="260" y="164">Verifier</text><text class="fig-label" x="160" y="180" text-anchor="middle">trusts</text>`},
		"stacks": components.Stacks{Items: []components.StackCard{{
			ID: "stack-a", Name: "Alpha Stack", Version: "Pinned 1.2.3",
			Components: []components.Component{{Name: "issuer-api", Version: "pinned 1.2.3", RepoHref: "https://example.org/repo", RepoText: "GitHub", DocsHref: "https://example.org/docs", DocsText: "Documentation"}},
			Roles:      []components.RoleRow{{Label: "Issuer", State: "live", Text: "Live"}, {Label: "Holder", State: "starting", Text: "Starting"}},
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
	steps := []struct {
		name string
		data any
	}{
		{"stepper", components.Stepper{Label: "Demo progress", Steps: []string{"Source", "Claims", "Delivery"}, Current: 2}},
		{"steps", components.Steps{Items: []components.Step{
			{Title: "Identify your organisation", Text: "Register keys and metadata with the trust registry.", State: "done"},
			{Title: "Define what you issue", Text: "Publish a schema, or build one.", State: "current", Href: "/", LinkText: "Open schemas"},
			{Title: "Issue", Text: "One credential by hand, or many from a data source.", State: "locked"},
			{Title: "Manage what you issued", Text: "Search, review, suspend or revoke."},
		}}},
		{"stat", components.Stat{Label: "Trust list", Value: "12 trusted issuers", Text: "Issuers a verifier on this deployment accepts.", Href: "/", LinkText: "Open trust list"}},
		{"checklist", components.Checklist{ID: "first-run", Title: "First run checklist", Note: "Steps stay until done",
			Items: []components.Check{
				{Text: "Register the first admin account", Detail: "Done through the admin realm", Done: true},
				{Text: "Turn off self registration for admins", Detail: "Realm settings, Login, User registration"},
			}}},
		{"choice", components.Choice{ID: "source", Legend: "Source", Hint: "Options a stack cannot do are hidden for that stack.",
			Options: []components.ChoiceOption{
				{Value: "single", Title: "Single credential", Text: "Type the claims in a form built from the schema.", Checked: true},
				{Value: "bulk", Title: "Bulk from a data source", Text: "One credential per record.", Meta: "3 sources"},
			}}},
		{"code", components.Code{ID: "offer", Label: "Credential offer", Text: "openid-credential-offer://?credential_offer_uri=https://issuer.example/offers/1"}},
		{"empty", components.Empty{Title: "Nothing issued yet", Text: "The first credential you issue appears here.",
			Action: components.Button{Text: "Issue the first one", Href: "/", Variant: "primary"}}},
		{"tiles", components.Tiles{Items: []components.Tile{
			{Num: "Issuer", Title: "Proceed as issuer", Text: "Register your organisation, define what you issue, then issue credentials.", Meta: "On two stacks", Href: "/"},
			{Num: "Holder", Title: "Proceed as holder", Text: "Discover offers, claim credentials into a wallet and present them.", Href: "/"},
			{Num: "03", Title: "The triangle of trust", Text: "An issuer signs, a holder presents, a verifier checks.", Figure: figure, Meta: "Read more", Href: "https://www.w3.org/TR/vc-data-model-2.0/"},
		}}},
		{"block", components.Block{ID: "stacks", Title: "Stacks on this deployment", Lead: "Only running services appear.", Meta: "Updated now", Body: stacks}},
		{"cta", components.CTA{ID: "start", Title: "Pick a role.", Text: "Walk one flow end to end.", Action: components.Button{Text: "Start", Href: "/", Variant: "primary"}}},
		{"card", components.Card{ID: "verdict", Title: "Verification result", Text: "The credential is valid.", Body: okBadge, Footer: "Checked today"}},
		{"table", components.Table{Caption: "Checks", Columns: []string{"Check", "Result"}, Rows: []components.Row{
			{{Text: "Signature"}, {HTML: okBadge}},
			{{Text: "Status list"}, {HTML: okBadge}},
		}}},
		{"field", components.Field{ID: "issuer", Label: "Issuer DID", Hint: "Starts with did:", Required: true, Autocomplete: "off"}},
		{"field", components.Field{ID: "kind", Label: "Credential type", Type: "select", Options: []components.Option{{Value: "degree", Text: "Degree", Selected: true}}}},
		{"button", components.Button{Text: "Check now", Type: "submit", Variant: "primary", Attrs: map[string]string{"hx-get": "/toast?t=now", "hx-swap": "none"}}},
		{"button", components.Button{Text: "Raw credential", Controls: "raw", Expanded: true}},
		{"json", components.JSON{ID: "raw", Summary: "Raw credential JSON", Open: true, Data: map[string]any{"type": []string{"VerifiableCredential"}, "issuer": "did:example:123"}}},
		{"qr", components.QR{Src: "data:image/gif;base64,R0lGODlhAQABAAAAACw=", Alt: "QR code: open the credential offer in a wallet", Size: 160}},
		{"button", components.Button{Text: "Revoke", Variant: "danger", Opens: "confirm"}},
		{"dialog", components.Dialog{ID: "confirm", Title: "Revoke credential", Text: "This cannot be undone.",
			Actions: []components.Button{{Text: "Revoke", Type: "submit", Variant: "danger", Value: "revoke"}}}},
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
		Title:       "vca UI kit demo",
		Hero:        hero,
		Description: "Every component of the vca UI kit on one page.",
		Nav: components.Nav{Brand: components.Link{Href: "/", Text: "UI kit"},
			Links: []components.Link{{Href: "/", Text: "Demo", Current: true}, {Href: "/static/vca.css", Text: "Stylesheet"}}},
		Shell:   demoShell(),
		Toasts:  []components.Toast{{Level: "info", Text: "Demo page loaded"}},
		Footer:  fmt.Sprintf("vca UI kit, htmx %s", ui.HTMXVersion),
		Content: components.Join(parts...),
	}, nil
}

// demoShell frames the demo page as an issuer portal with two live stacks,
// one starting stack, a user, and two navigation sections.
func demoShell() *components.Shell {
	return &components.Shell{
		Role: "issuer",
		Stacks: []components.StackLink{
			{Name: "Stack A", Href: "/", Current: true},
			{Name: "Stack B", Href: "/?stack=b"},
			{Name: "Stack C", State: "starting"},
		},
		User: components.User{Name: "Demo user", SignOut: "/auth/logout", CSRF: "demo-token"},
		Sections: []components.NavSection{
			{Links: []components.Link{{Href: "/", Text: "Overview", Current: true}}},
			{Label: "Kit", Links: []components.Link{{Href: "/static/vca.css", Text: "Stylesheet"}, {Href: "/toast?t=nav", Text: "Toast"}}},
		},
	}
}
