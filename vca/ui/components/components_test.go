// SPDX-License-Identifier: Apache-2.0

package components

import (
	"bytes"
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

func newKit(t *testing.T) *Kit {
	t.Helper()
	k, err := New()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustHTML(t *testing.T, k *Kit, name string, data any) template.HTML {
	t.Helper()
	h, err := k.HTML(name, data)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return h
}

// samples returns one valid instance of every component.
func samples(t *testing.T, k *Kit) map[string]any {
	t.Helper()
	return map[string]any{
		"card": Card{ID: "c1", Title: "Card", Text: "Text", Body: mustHTML(t, k, "badge", Badge{Status: "ok", Text: "Valid"}), Footer: "Footer"},
		"field": Field{ID: "email", Label: "Email", Type: "email", Hint: "Work address", Error: "Enter an address",
			Required: true, Autocomplete: "email", Attrs: map[string]string{"placeholder": "you@example.org"}},
		"table": Table{ID: "t1", Caption: "Credentials", Columns: []string{"Name", "Status"},
			Rows: []Row{{{Text: "Degree"}, {HTML: mustHTML(t, k, "badge", Badge{Status: "ok", Text: "Valid"})}}}},
		"badge": Badge{Status: "warn", Text: "Expiring"},
		"toast": Toast{ID: "n1", Level: "info", Text: "Saved", OOB: true},
		"dialog": Dialog{ID: "d1", Title: "Confirm", Text: "Revoke this credential?",
			Actions: []Button{{Text: "Revoke", Type: "submit", Variant: "danger", Value: "revoke"}}},
		"qr":     QR{Src: "data:image/png;base64,iVBORw0KGgo=", Alt: "QR code: open the wallet offer"},
		"json":   JSON{ID: "j1", Summary: "Raw credential", Data: map[string]any{"a": 1, "b": []string{"x"}}, Open: true},
		"button": Button{Text: "Details", Controls: "j1", Expanded: false, Attrs: map[string]string{"hx-get": "/x?a=1&b=2"}},
	}
}

func TestEveryComponentRendersInsideLayout(t *testing.T) {
	k := newKit(t)
	var body strings.Builder
	for name, data := range samples(t, k) {
		h := mustHTML(t, k, name, data)
		a11ytest.AssertFragment(t, string(h))
		body.WriteString(string(h))
	}
	body.WriteString(string(mustHTML(t, k, "button", Button{Text: "Open", Opens: "d1", Variant: "primary"})))
	body.WriteString(string(mustHTML(t, k, "button", Button{Text: "Docs", Href: "/docs", Variant: "ghost"})))
	body.WriteString(string(mustHTML(t, k, "button", Button{AriaLabel: "Close", Disabled: true})))
	body.WriteString(string(mustHTML(t, k, "field", Field{ID: "notes", Label: "Notes", Type: "textarea", Value: "x"})))
	body.WriteString(string(mustHTML(t, k, "field", Field{ID: "kind", Label: "Kind", Type: "select",
		Options: []Option{{Value: "a", Text: "A", Selected: true}, {Value: "b", Text: "B"}}})))
	body.WriteString(string(mustHTML(t, k, "table", Table{Caption: "Empty", Columns: []string{"X"}})))

	page := Page{
		Title: "Demo", Description: "All components", Footer: "vca",
		Nav:     Nav{Brand: Link{Href: "/", Text: "vca"}, Links: []Link{{Href: "/", Text: "Home", Current: true}, {Href: "/verify", Text: "Verify"}}},
		Toasts:  []Toast{{Level: "ok", Text: "Ready"}},
		Content: template.HTML(body.String()), //nolint:gosec // composed from kit output
	}
	rec := httptest.NewRecorder()
	if err := k.RenderPage(rec, httptest.NewRequest(http.MethodGet, "/", nil), page); err != nil {
		t.Fatal(err)
	}
	doc := rec.Body.String()
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		`<html lang="en">`, `<title>Demo</title>`, `<h1>Demo</h1>`,
		`class="skip-link" href="#page"`, `<nav class="nav" aria-label="Main">`, `<main id="page"`,
		`<header class="site-header">`, `<a class="wordmark" href="/">vca</a>`, `<div class="pg-header">`,
		`aria-current="page"`, `data-theme-toggle aria-label="Theme"`, `aria-live="polite"`,
		`localStorage.getItem('theme')`, `try {`, `setAttribute('data-theme'`, `removeAttribute('data-theme')`,
		`name="viewport" content="width=device-width, initial-scale=1"`, `/static/vca.css`, `/static/htmx.min.js`,
		`aria-describedby="email-hint email-error"`, `aria-invalid="true"`, `autocomplete="email"`, `placeholder="you@example.org"`,
		`<caption>Credentials</caption>`, `<th scope="col">Name</th>`, `colspan="1">No rows</td>`,
		`class="badge badge-warn"`, `hx-swap-oob="beforeend:#toasts"`, `class="toast toast-ok"`,
		`<dialog id="d1" aria-labelledby="d1-title">`, `<form method="dialog"`, `>Close</button>`,
		`alt="QR code: open the wallet offer"`, `width="256"`, `<details class="json" open>`, `role="region" aria-label="Raw credential"`,
		`&#34;a&#34;: 1`, `aria-controls="j1" aria-expanded="false"`, `hx-get="/x?a=1&amp;b=2"`,
		`data-open-dialog="d1" aria-haspopup="dialog"`, `<a class="btn btn-ghost" href="/docs"`, `aria-label="Close" disabled`,
		`<textarea id="notes"`, `<option value="a" selected>A</option>`, `<footer class="site-footer">vca</footer>`,
		`Content-Type`,
	} {
		if want == "Content-Type" {
			if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
				t.Errorf("Content-Type = %q", ct)
			}
			continue
		}
		if !strings.Contains(doc, want) {
			t.Errorf("page missing %q", want)
		}
	}
	if strings.Contains(doc, "ZgotmplZ") {
		t.Error("page contains an escaped unsafe value")
	}
}

func TestRenderPageHTMX(t *testing.T) {
	k := newKit(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	if err := k.RenderPage(rec, req, Page{Title: "Partial", Heading: "Head", Content: "<p>x</p>"}); err != nil {
		t.Fatal(err)
	}
	doc := rec.Body.String()
	if strings.Contains(doc, "<html") || !strings.Contains(doc, "<h1>Head</h1>") || !strings.Contains(doc, "<p>x</p>") {
		t.Errorf("partial = %q", doc)
	}
	if rec.Header().Get("HX-Title") != "Partial" {
		t.Errorf("HX-Title = %q", rec.Header().Get("HX-Title"))
	}

	req.Header.Set("HX-History-Restore-Request", "true")
	rec = httptest.NewRecorder()
	if err := k.RenderPage(rec, req, Page{Title: "Full"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rec.Body.String(), "<html") || rec.Header().Get("HX-Title") != "" {
		t.Error("history restore must receive the full layout")
	}

	if err := k.RenderPage(httptest.NewRecorder(), req, Page{}); err == nil {
		t.Error("page without title should fail")
	}
	if err := k.RenderPage(httptest.NewRecorder(), req, Page{Title: "x", Toasts: []Toast{{Level: "loud"}}}); err == nil {
		t.Error("page with a bad toast should fail")
	}
}

func TestPageHeaderCarriesAccentLabel(t *testing.T) {
	k := newKit(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	if err := k.RenderPage(rec, req, Page{Title: "Schemas", Label: "Issuer", Lead: "Define what you issue."}); err != nil {
		t.Fatal(err)
	}
	want := `<div class="pg-header">` + "\n" + `<p class="pg-header-label">Issuer</p>` + "\n" +
		`<h1>Schemas</h1>` + "\n" + `<p class="pg-header-lead">Define what you issue.</p>` + "\n</div>"
	if doc := rec.Body.String(); !strings.HasPrefix(doc, want) {
		t.Errorf("page header = %q, want prefix %q", doc, want)
	}
	a11ytest.AssertFragment(t, rec.Body.String())
}

func TestPageTextAndLangCanBeTranslated(t *testing.T) {
	k := newKit(t)
	rec := httptest.NewRecorder()
	page := Page{Lang: "fr", Title: "Accueil", Nav: Nav{Label: "Principal"},
		Text: Text{SkipLink: "Aller au contenu", ThemeToggle: "Thème", ThemeSystem: "Système", ThemeLight: "Clair", ThemeDark: "Sombre"}}
	if err := k.RenderPage(rec, httptest.NewRequest(http.MethodGet, "/", nil), page); err != nil {
		t.Fatal(err)
	}
	doc := rec.Body.String()
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{`<html lang="fr">`, `aria-label="Principal"`, `>Aller au contenu<`, `data-label-dark="Sombre"`} {
		if !strings.Contains(doc, want) {
			t.Errorf("page missing %q", want)
		}
	}
}

func TestInvalidDataIsRejected(t *testing.T) {
	k := newKit(t)
	cases := map[string]any{
		"card no id":          Card{},
		"card bad id":         Card{ID: "1 bad"},
		"field no label":      Field{ID: "x"},
		"field bad id":        Field{Label: "x"},
		"field bad attr":      Field{ID: "x", Label: "x", Attrs: map[string]string{"onclick": "alert(1)"}},
		"table no caption":    Table{Columns: []string{"a"}},
		"table no columns":    Table{Caption: "x"},
		"badge bad status":    Badge{Status: "purple", Text: "x"},
		"badge no text":       Badge{Status: "ok"},
		"toast bad level":     Toast{Level: "x", Text: "x"},
		"toast no text":       Toast{Level: "ok"},
		"dialog no id":        Dialog{Title: "x"},
		"dialog no title":     Dialog{ID: "d"},
		"dialog bad action":   Dialog{ID: "d", Title: "x", Actions: []Button{{}}},
		"qr no alt":           QR{Src: "/qr.png", Alt: "  "},
		"qr bad src":          QR{Src: "javascript:alert(1)", Alt: "x"},
		"json no id":          JSON{Summary: "x"},
		"json no summary":     JSON{ID: "j"},
		"json unmarshallable": JSON{ID: "j", Summary: "x", Data: make(chan int)},
		"button no text":      Button{},
		"button bad type":     Button{Text: "x", Type: "reset"},
		"button bad variant":  Button{Text: "x", Variant: "loud"},
		"button bad attr":     Button{Text: "x", Attrs: map[string]string{"onclick": "x", "style": "y"}},
	}
	for name, data := range cases {
		var buf bytes.Buffer
		if err := k.Render(&buf, "card", data); err == nil {
			t.Errorf("%s: expected an error", name)
		}
		if buf.Len() != 0 {
			t.Errorf("%s: nothing must be written on error", name)
		}
	}
	if err := k.Render(&bytes.Buffer{}, "missing", nil); err == nil {
		t.Error("unknown template should fail")
	}
	if _, err := k.HTML("missing", nil); err == nil {
		t.Error("HTML with unknown template should fail")
	}
}

func TestSafeAttr(t *testing.T) {
	if got := SafeAttr("hx-get", `/a?b="c"&d`); got != `hx-get="/a?b=&#34;c&#34;&amp;d"` {
		t.Errorf("SafeAttr = %q", got)
	}
	if got := SafeAttr("onclick", "x"); got != "" {
		t.Errorf("SafeAttr must drop unknown names, got %q", got)
	}
	f := Field{ID: "a", Hint: "h", Error: "e"}
	if f.DescribedBy() != "a-hint a-error" {
		t.Errorf("DescribedBy = %q", f.DescribedBy())
	}
	if (Field{ID: "a"}).DescribedBy() != "" {
		t.Error("DescribedBy should be empty without hint or error")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

func TestWriteErrors(t *testing.T) {
	k := newKit(t)
	if err := k.Render(failWriter{}, "badge", Badge{Status: "ok", Text: "x"}); err == nil {
		t.Error("write error must be returned")
	}
	var empty *Kit
	if err := empty.Render(io.Discard, "badge", Badge{Status: "ok", Text: "x"}); !errors.Is(err, ErrNoTemplates) {
		t.Errorf("empty kit Render err = %v", err)
	}
	if err := (&Kit{}).RenderPage(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), Page{Title: "t"}); !errors.Is(err, ErrNoTemplates) {
		t.Errorf("empty kit RenderPage err = %v", err)
	}
	if got := Join("<a>", "<b>"); got != "<a>\n<b>\n" {
		t.Errorf("Join = %q", got)
	}
	if len(Names) != 11 {
		t.Errorf("Names = %v", Names)
	}
	for _, n := range Names {
		if k.tpl.Lookup(n) == nil {
			t.Errorf("template %q is not defined", n)
		}
	}
}
