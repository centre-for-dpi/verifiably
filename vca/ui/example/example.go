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
	okBadge, err := kit.HTML("badge", components.Badge{Status: "ok", Text: "Valid"})
	if err != nil {
		return components.Page{}, err
	}
	steps := []struct {
		name string
		data any
	}{
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
	parts := make([]template.HTML, 0, len(steps)+2)
	parts = append(parts, template.HTML(`<form action="/" method="get">`)) //nolint:gosec // literal
	for _, s := range steps {
		h, err := kit.HTML(s.name, s.data)
		if err != nil {
			return components.Page{}, err
		}
		parts = append(parts, h)
	}
	parts = append(parts, template.HTML(`</form>`)) //nolint:gosec // literal
	return components.Page{
		Title:       "vca UI kit demo",
		Label:       "UI kit",
		Lead:        "Every component of the kit on one page, in the light and the dark theme.",
		Description: "Every component of the vca UI kit on one page.",
		Nav: components.Nav{Brand: components.Link{Href: "/", Text: "UI kit"},
			Links: []components.Link{{Href: "/", Text: "Demo", Current: true}, {Href: "/static/vca.css", Text: "Stylesheet"}}},
		Toasts:  []components.Toast{{Level: "info", Text: "Demo page loaded"}},
		Footer:  fmt.Sprintf("vca UI kit, htmx %s", ui.HTMXVersion),
		Content: components.Join(parts...),
	}, nil
}
