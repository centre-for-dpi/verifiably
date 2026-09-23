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
	"github.com/centre-for-dpi/vc-adapters/ui/brand"
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
		`<header class="site-header">`, `<a class="wordmark" href="/"><span class="wordmark-text">VCA</span><span class="wordmark-context">vca</span></a>`,
		`<div class="pg-header">`,
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
		`<textarea id="notes"`, `<option value="a" selected>A</option>`, `<footer class="site-footer">` + "\n" + `<span class="ft-monogram"><span class="ft-name">VCA</span></span>` + "\n" + `<span class="ft-note">vca</span>`,
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

func TestLayoutRendersWordmarkAndLogo(t *testing.T) {
	b := brand.Default()
	b.Wordmark, b.Emphasis = "Republic", "Credentials"
	b.Logo = brand.Logo{DataURI: "data:image/png;base64,iVBORw==", Alt: "Republic crest"}
	k, err := New(WithBrand(b))
	if err != nil {
		t.Fatal(err)
	}
	if got := k.Mark(); got != (Mark{Text: "Republic", Emphasis: "Credentials", LogoSrc: "/static/logo.png", LogoAlt: "Republic crest"}) {
		t.Errorf("Mark() = %+v", got)
	}
	rec := httptest.NewRecorder()
	page := Page{Title: "Issue", Nav: Nav{Brand: Link{Href: "/issuer/", Text: "Issuer"}}}
	if err := k.RenderPage(rec, httptest.NewRequest(http.MethodGet, "/", nil), page); err != nil {
		t.Fatal(err)
	}
	doc := rec.Body.String()
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		`<a class="wordmark" href="/issuer/"><img src="/static/logo.png" alt="Republic crest"><span class="wordmark-text">Republic&nbsp;<em>Credentials</em></span><span class="wordmark-context">Issuer</span></a>`,
		`<span class="ft-monogram"><span class="ft-name">Republic Credentials</span></span>`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("page missing %q\n%s", want, doc)
		}
	}
	if strings.Contains(doc, "ft-note") {
		t.Error("a page with no footer text has no note")
	}

	// The default kit draws the default wordmark and no logo.
	rec = httptest.NewRecorder()
	if err := newKit(t).RenderPage(rec, httptest.NewRequest(http.MethodGet, "/", nil), Page{Title: "Home"}); err != nil {
		t.Fatal(err)
	}
	if doc := rec.Body.String(); !strings.Contains(doc, `<a class="wordmark" href="/"><span class="wordmark-text">VCA</span></a>`) || strings.Contains(doc, "<img") {
		t.Errorf("default wordmark wrong:\n%s", doc)
	}

	// A logo the kit cannot serve stops New.
	b.Logo.DataURI = "data:image/gif;base64,R0lG"
	if _, err := New(WithBrand(b)); err == nil || !strings.Contains(err.Error(), "logo") {
		t.Errorf("bad logo should fail New, got %v", err)
	}
}

// issuerShell returns a shell with two stacks, a user, and two nav sections.
func issuerShell() *Shell {
	return &Shell{
		Role: "issuer",
		Stacks: []StackLink{
			{Name: "Stack A", Href: "https://issuer-a.example/issuer/", Current: true},
			{Name: "Stack B", Href: "https://issuer-b.example/issuer/"},
		},
		User: User{Name: "Amina", SignOut: "/auth/logout", CSRF: "tok&en"},
		Sections: []NavSection{
			{Links: []Link{{Href: "/issuer/", Text: "Overview", Current: true}, {Href: "/issuer/identity", Text: "Identity"}}},
			{Label: "Credentials", Links: []Link{{Href: "/issuer/schemas", Text: "Schemas"}, {Href: "/issuer/issue", Text: "Issue"}}},
		},
	}
}

func renderShellPage(t *testing.T, k *Kit, page Page) string {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := k.RenderPage(rec, httptest.NewRequest(http.MethodGet, "/", nil), page); err != nil {
		t.Fatal(err)
	}
	doc := rec.Body.String()
	a11ytest.AssertPage(t, doc)
	return doc
}

func TestShellRendersRoleChipStacksAndUser(t *testing.T) {
	k := newKit(t)
	doc := renderShellPage(t, k, Page{Title: "Overview", Shell: issuerShell(), Nav: Nav{Brand: Link{Href: "/issuer/", Text: "Issuer"}}})
	for _, want := range []string{
		`<body data-role="issuer" class="has-shell">`,
		`<span class="role-chip">Issuer</span>`,
		`<nav class="stack-nav" aria-label="Stack">`,
		`<a href="https://issuer-a.example/issuer/" aria-current="true">Stack A</a>`,
		`<a href="https://issuer-b.example/issuer/">Stack B</a>`,
		`<details class="user-menu">`, `<summary>Amina</summary>`,
		`<form method="post" action="/auth/logout">`,
		`<input type="hidden" name="csrf_token" value="tok&amp;en">`,
		`>Sign out</button>`,
		`<details class="side-nav" open>`, `<summary class="side-nav-toggle">Menu</summary>`,
		`<nav aria-label="Portal">`,
		`<p class="side-label" id="side-2-label">Credentials</p>`, `<ul class="side-links" aria-labelledby="side-2-label">`,
		`<a href="/issuer/" aria-current="page" hx-get="/issuer/" hx-target="#page" hx-push-url="true">Overview</a>`,
		`<div class="shell">`, `<main id="page" tabindex="-1">`, `<h1>Overview</h1>`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("shell page missing %q\n%s", want, doc)
		}
	}
	// The top nav has no links, so the shell page has no empty Main landmark.
	if strings.Contains(doc, `aria-label="Main"`) {
		t.Error("a shell page without top links must not render an empty main nav")
	}
	// A plain page has no shell markup and no role.
	plain := renderShellPage(t, k, Page{Title: "Home"})
	for _, gone := range []string{"data-role", "has-shell", `<div class="shell">`, "role-chip", "user-menu", `<details class="side-nav"`, "stack-nav"} {
		if strings.Contains(plain, gone) {
			t.Errorf("plain page must not contain %q", gone)
		}
	}
	if !strings.Contains(plain, `<nav class="nav" aria-label="Main">`) {
		t.Error("plain page keeps the main nav")
	}
}

func TestShellHidesStackNavWithOneStack(t *testing.T) {
	k := newKit(t)
	sh := issuerShell()
	sh.Stacks = sh.Stacks[:1]
	doc := renderShellPage(t, k, Page{Title: "Overview", Shell: sh})
	if strings.Contains(doc, `aria-label="Stack"`) || strings.Contains(doc, "stack-nav") {
		t.Error("one stack needs no switcher")
	}
	sh.Stacks = nil
	doc = renderShellPage(t, k, Page{Title: "Overview", Shell: sh})
	if strings.Contains(doc, "stack-nav") {
		t.Error("no stack needs no switcher")
	}
}

func TestShellSideNavMarksCurrent(t *testing.T) {
	k := newKit(t)
	doc := renderShellPage(t, k, Page{Title: "Identity", Shell: issuerShell()})
	if strings.Count(doc, `aria-current="page"`) != 1 {
		t.Errorf("want one current side link, got %d", strings.Count(doc, `aria-current="page"`))
	}
	if !strings.Contains(doc, `<a href="/issuer/" aria-current="page"`) {
		t.Error("the current side link is Overview")
	}
	if !strings.Contains(doc, `<a href="/issuer/identity" hx-get="/issuer/identity"`) {
		t.Error("other side links carry no aria-current")
	}
	// A section without a label is a plain list.
	if !strings.Contains(doc, `<ul class="side-links">`) {
		t.Error("the first section has no label and no aria-labelledby")
	}
}

func TestShellStartingStackHasNoLink(t *testing.T) {
	k := newKit(t)
	sh := issuerShell()
	sh.Stacks = append(sh.Stacks, StackLink{Name: "Stack C", State: "starting"})
	doc := renderShellPage(t, k, Page{Title: "Overview", Shell: sh})
	want := `<li><span class="stack-starting">Stack C <span class="badge badge-warn">Starting</span></span></li>`
	if !strings.Contains(doc, want) {
		t.Errorf("starting stack should render as text with a badge, want %q in\n%s", want, doc)
	}
	if strings.Contains(doc, `href="">`) || strings.Contains(doc, `>Stack C</a>`) {
		t.Error("a starting stack must not be a link")
	}
}

func TestShellTextCanBeTranslated(t *testing.T) {
	k := newKit(t)
	sh := issuerShell()
	sh.RoleLabel = "Émetteur"
	sh.Stacks = append(sh.Stacks, StackLink{Name: "C", State: "starting"})
	page := Page{Lang: "fr", Title: "Vue", Shell: sh,
		Text: Text{SignOut: "Se déconnecter", Menu: "Menu du portail", StackNav: "Pile", SideNav: "Portail", Starting: "Démarrage"}}
	doc := renderShellPage(t, k, page)
	for _, want := range []string{`<span class="role-chip">Émetteur</span>`, `>Se déconnecter</button>`, `<summary class="side-nav-toggle">Menu du portail</summary>`,
		`aria-label="Pile"`, `<nav aria-label="Portail">`, `<span class="badge badge-warn">Démarrage</span>`} {
		if !strings.Contains(doc, want) {
			t.Errorf("shell page missing %q", want)
		}
	}
}

func TestShellRejectsBadData(t *testing.T) {
	k := newKit(t)
	cases := map[string]func(*Shell){
		"unknown role":        func(s *Shell) { s.Role = "root" },
		"no role":             func(s *Shell) { s.Role = "" },
		"stack no name":       func(s *Shell) { s.Stacks[0].Name = "" },
		"live stack no href":  func(s *Shell) { s.Stacks[1].Href = "" },
		"unknown stack state": func(s *Shell) { s.Stacks[1].State = "down" },
		"two current stacks":  func(s *Shell) { s.Stacks[1].Current = true },
		"user no sign out":    func(s *Shell) { s.User.SignOut = "" },
		"user no csrf":        func(s *Shell) { s.User.CSRF = "" },
		"section no links":    func(s *Shell) { s.Sections = append(s.Sections, NavSection{Label: "Empty"}) },
		"link no href":        func(s *Shell) { s.Sections[0].Links[0].Href = "" },
		"link no text":        func(s *Shell) { s.Sections[0].Links[0].Text = "" },
	}
	for name, mutate := range cases {
		sh := issuerShell()
		mutate(sh)
		rec := httptest.NewRecorder()
		if err := k.RenderPage(rec, httptest.NewRequest(http.MethodGet, "/", nil), Page{Title: "x", Shell: sh}); err == nil {
			t.Errorf("%s: expected an error", name)
		} else if rec.Body.Len() != 0 {
			t.Errorf("%s: nothing must be written on error", name)
		}
	}
	// A shell without a user renders no user menu; the CSRF field name can change.
	sh := issuerShell()
	sh.User = User{}
	if doc := renderShellPage(t, k, Page{Title: "x", Shell: sh}); strings.Contains(doc, "user-menu") {
		t.Error("no user, no menu")
	}
	sh = issuerShell()
	sh.User.CSRFField = "_token"
	if doc := renderShellPage(t, k, Page{Title: "x", Shell: sh}); !strings.Contains(doc, `name="_token"`) {
		t.Error("CSRFField should rename the hidden field")
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
