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
		"tiles": Tiles{Items: []Tile{{Num: "01", Title: "Proceed as issuer", Text: "Define what you issue.", Meta: "On two stacks", Href: "/roles/issuer/"},
			{Num: "02", Title: "Proceed as holder", Href: "/roles/holder/"}}},
		"steps": Steps{Items: []Step{{Title: "Identify", Text: "Register keys.", State: "done"}, {Title: "Define", State: "current", Href: "/schemas", LinkText: "Open schemas"},
			{Title: "Issue", State: "locked"}, {Title: "Manage"}}},
		"checklist": Checklist{ID: "first-run", Title: "First run checklist", Note: "Steps stay until done",
			Items: []Check{{Text: "Register the first admin", Detail: "Done in the admin realm", Done: true}, {Text: "Turn off self registration"}}},
		"stat":    Stat{Label: "Trust list", Value: "12 trusted issuers", Text: "Issuers a verifier accepts.", Href: "/trust", LinkText: "Open trust list"},
		"stepper": Stepper{Label: "Issue progress", Steps: []string{"Source", "Claims", "Delivery"}, Current: 2},
		"tabs":    Tabs{Label: "Views", Links: []Link{{Href: "/a", Text: "A", Current: true}, {Href: "/b", Text: "B"}}},
		"choice": Choice{ID: "source", Legend: "Source", Hint: "Pick one", Options: []ChoiceOption{
			{Value: "single", Title: "Single credential", Text: "Type the claims.", Checked: true},
			{Value: "bulk", Title: "Bulk", Text: "One credential per record.", Meta: "3 sources", Disabled: true}}},
		"code":  Code{ID: "offer", Label: "Credential offer", Text: "openid-credential-offer://?a=<b>"},
		"empty": Empty{Title: "Nothing issued yet", Text: "The first credential appears here.", Action: Button{Text: "Issue one", Href: "/issue", Variant: "primary"}},
		"block": Block{ID: "how", Title: "How it works", Lead: "Three ideas.", Meta: "Two minutes", Body: "<p>Body</p>",
			Attrs: map[string]string{"hx-get": "/how", "hx-trigger": "every 30s", "hx-swap": "outerHTML"}},
		"figure": Figure{ID: "triangle", Title: "The triangle of trust", Caption: "Issuer, holder and verifier.", ViewBox: "0 0 320 200",
			SVG: `<circle class="fig-node" cx="10" cy="10" r="5"/><text class="fig-text" x="1" y="1">Issuer</text>`},
		"stacks": Stacks{Items: []StackCard{{ID: "stack-a", Name: "Alpha Stack", Version: "Pinned 1.0",
			Components: []Component{{Name: "issuer-api", Version: "pinned 1.0", RepoHref: "https://example.org/r", RepoText: "GitHub", DocsHref: "https://example.org/d", DocsText: "Documentation"}},
			Roles:      []RoleRow{{Label: "Issuer", State: "live", Text: "Live"}, {Label: "Holder", State: "starting", Text: "Starting"}}}}},
		"cta":  CTA{ID: "start", Title: "Pick a role.", Text: "Walk one flow.", Action: Button{Text: "Start", Href: "/roles/", Variant: "primary"}},
		"note": Note{Label: "One role", Text: "This deployment runs one role."},
	}
}

func TestHeroReplacesPageHeader(t *testing.T) {
	k := newKit(t)
	hero := &Hero{Label: "Verifiable Credentials Adapter", Title: "One front door to", Emphasis: "open credentials.",
		Lead:    "Issue, hold and check credentials on open source stacks.",
		Actions: []Button{{Text: "Start", Href: "/roles/", Variant: "primary"}, {Text: "Read the primer", Href: "/#how", Variant: "ghost"}},
		Aside:   `<p class="ethos-note">Only running services appear.</p>`}
	doc := renderShellPage(t, k, Page{Title: "VCA", Hero: hero, Nav: Nav{Links: []Link{{Href: "/", Text: "Home"}}}})
	for _, want := range []string{
		`<section class="hero">`, `<div class="hero-left">`, `<span class="role">Verifiable Credentials Adapter</span>`,
		`<h1>One front door to<em>open credentials.</em></h1>`, `<div class="hero-right">`,
		`<p class="desc">Issue, hold and check credentials on open source stacks.</p>`,
		`<div class="hero-actions">`, `<a class="btn btn-primary" href="/roles/">Start</a>`,
		`<div class="hero-rule" aria-hidden="true"></div>`, `<p class="ethos-note">Only running services appear.</p>`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("hero page missing %q\n%s", want, doc)
		}
	}
	if strings.Contains(doc, "pg-header") {
		t.Error("a hero replaces the page header")
	}
	if strings.Count(doc, "<h1>") != 1 {
		t.Error("the hero carries the one h1")
	}
	// The hero also renders alone, and rejects a missing title.
	frag := mustHTML(t, k, "hero", Hero{Title: "Plain"})
	a11ytest.AssertFragment(t, string(frag))
	if strings.Contains(string(frag), "hero-actions") || strings.Contains(string(frag), "hero-rule") || strings.Contains(string(frag), "role-row") {
		t.Errorf("a bare hero has no optional parts:\n%s", frag)
	}
	if err := k.RenderPage(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), Page{Title: "x", Hero: &Hero{}}); err == nil {
		t.Error("a hero without a title should fail")
	}
	if err := k.RenderPage(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), Page{Title: "x", Hero: &Hero{Title: "t", Actions: []Button{{}}}}); err == nil {
		t.Error("a hero with a bad action should fail")
	}
}

func TestTilesRequireTitleAndHref(t *testing.T) {
	k := newKit(t)
	doc := string(mustHTML(t, k, "tiles", sampleTiles()))
	a11ytest.AssertFragment(t, doc)
	for _, want := range []string{
		`<ul class="tiles">`, `<li><a class="tile" href="/roles/issuer/">`, `<span class="tile-num">01</span>`,
		`<svg class="tile-arrow"`, `aria-hidden="true"`, `<h2>Proceed as issuer</h2>`, `<p>Define what you issue.</p>`,
		`<span class="tile-meta">On two stacks</span>`, `<div class="tile-line" aria-hidden="true"></div>`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("tiles missing %q\n%s", want, doc)
		}
	}
	for name, data := range map[string]any{
		"no items": Tiles{},
		"no title": Tiles{Items: []Tile{{Href: "/x"}}},
		"no href":  Tiles{Items: []Tile{{Title: "x"}}},
	} {
		if _, err := k.HTML("tiles", data); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func sampleTiles() Tiles {
	return Tiles{Items: []Tile{{Num: "01", Title: "Proceed as issuer", Text: "Define what you issue.", Meta: "On two stacks", Href: "/roles/issuer/"}}}
}

func TestStepsStateHasText(t *testing.T) {
	k := newKit(t)
	doc := string(mustHTML(t, k, "steps", samples(t, k)["steps"]))
	a11ytest.AssertFragment(t, doc)
	for _, want := range []string{
		`<ol class="steps">`,
		`<li class="step step-done">`, `<span class="step-num" aria-hidden="true">1</span>`, `<span class="step-state">Done</span>`,
		`<li class="step step-current" aria-current="step">`, `<span class="step-state">Current</span>`,
		`<li class="step step-locked">`, `<span class="step-state">Locked</span>`,
		`<span class="step-title">Identify</span>`, `<p class="step-text">Register keys.</p>`,
		`<a class="step-link" href="/schemas">Open schemas</a>`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("steps missing %q\n%s", want, doc)
		}
	}
	// A step without a state has no state text; a link without text says Open.
	plain := string(mustHTML(t, k, "steps", Steps{Items: []Step{{Title: "Manage", Href: "/issued"}}}))
	if strings.Contains(plain, "step-state") || !strings.Contains(plain, `<li class="step">`) || !strings.Contains(plain, `>Open</a>`) {
		t.Errorf("plain step wrong:\n%s", plain)
	}
	// State words can be translated.
	fr := string(mustHTML(t, k, "steps", Steps{Items: []Step{{Title: "x", State: "done"}}, Text: StepText{Done: "Fait"}}))
	if !strings.Contains(fr, `<span class="step-state">Fait</span>`) {
		t.Errorf("translated state missing:\n%s", fr)
	}
	for name, data := range map[string]any{
		"no items":    Steps{},
		"no title":    Steps{Items: []Step{{State: "done"}}},
		"bad state":   Steps{Items: []Step{{Title: "x", State: "soon"}}},
		"two current": Steps{Items: []Step{{Title: "x", State: "current"}, {Title: "y", State: "current"}}},
	} {
		if _, err := k.HTML("steps", data); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestChecklistMarksDoneInWords(t *testing.T) {
	k := newKit(t)
	doc := string(mustHTML(t, k, "checklist", samples(t, k)["checklist"]))
	a11ytest.AssertFragment(t, doc)
	for _, want := range []string{
		`<section class="checklist" id="first-run" aria-labelledby="first-run-title">`, `<h2 id="first-run-title">First run checklist</h2>`,
		`<p class="checklist-note">Steps stay until done</p>`,
		`<li class="check check-done">`, `<span class="check-mark" aria-hidden="true"></span>`, `<span class="check-state">Done</span>`,
		`<span class="check-text">Register the first admin</span>`, `<span class="check-detail">Done in the admin realm</span>`,
		`<li class="check">`, `<span class="check-state">To do</span>`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("checklist missing %q\n%s", want, doc)
		}
	}
	fr := string(mustHTML(t, k, "checklist", Checklist{ID: "c", Title: "T", Items: []Check{{Text: "x"}}, Text: CheckText{Todo: "À faire"}}))
	if !strings.Contains(fr, `<span class="check-state">À faire</span>`) {
		t.Errorf("translated state missing:\n%s", fr)
	}
	for name, data := range map[string]any{
		"no id":    Checklist{Title: "x", Items: []Check{{Text: "x"}}},
		"no title": Checklist{ID: "c", Items: []Check{{Text: "x"}}},
		"no items": Checklist{ID: "c", Title: "x"},
		"no text":  Checklist{ID: "c", Title: "x", Items: []Check{{Detail: "d"}}},
	} {
		if _, err := k.HTML("checklist", data); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestStatCardLinksOut(t *testing.T) {
	k := newKit(t)
	doc := string(mustHTML(t, k, "stat", samples(t, k)["stat"]))
	a11ytest.AssertFragment(t, doc)
	for _, want := range []string{
		`<div class="stat">`, `<span class="stat-label">Trust list</span>`, `<span class="stat-value">12 trusted issuers</span>`,
		`<p class="stat-text">Issuers a verifier accepts.</p>`, `<a class="stat-link" href="/trust">Open trust list</a>`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("stat missing %q\n%s", want, doc)
		}
	}
	bare := string(mustHTML(t, k, "stat", Stat{Label: "Keys", Value: "None yet", Href: "/keys"}))
	if strings.Contains(bare, "stat-text") || !strings.Contains(bare, `>Open</a>`) {
		t.Errorf("bare stat wrong:\n%s", bare)
	}
	if s := string(mustHTML(t, k, "stat", Stat{Label: "Keys", Value: "None"})); strings.Contains(s, "stat-link") {
		t.Error("no href, no link")
	}
	for name, data := range map[string]any{"no label": Stat{Value: "1"}, "no value": Stat{Label: "x"}} {
		if _, err := k.HTML("stat", data); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestStepperMarksCurrentStep(t *testing.T) {
	k := newKit(t)
	doc := string(mustHTML(t, k, "stepper", samples(t, k)["stepper"]))
	a11ytest.AssertFragment(t, doc)
	for _, want := range []string{
		`<ol class="stepper" aria-label="Issue progress">`,
		`<li class="stepper-step stepper-done"><span class="stepper-num" aria-hidden="true">1</span><span class="stepper-name">Source</span><span class="visually-hidden">Done</span></li>`,
		`<li class="stepper-step stepper-current" aria-current="step"><span class="stepper-num" aria-hidden="true">2</span><span class="stepper-name">Claims</span></li>`,
		`<li class="stepper-step"><span class="stepper-num" aria-hidden="true">3</span><span class="stepper-name">Delivery</span></li>`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("stepper missing %q\n%s", want, doc)
		}
	}
	if strings.Count(doc, `aria-current="step"`) != 1 {
		t.Error("exactly one current step")
	}
	fr := string(mustHTML(t, k, "stepper", Stepper{Label: "P", Steps: []string{"a", "b"}, Current: 2, Text: StepText{Done: "Fait"}}))
	if !strings.Contains(fr, `<span class="visually-hidden">Fait</span>`) {
		t.Errorf("translated done missing:\n%s", fr)
	}
	for name, data := range map[string]any{
		"no label":     Stepper{Steps: []string{"a", "b"}, Current: 1},
		"one step":     Stepper{Label: "P", Steps: []string{"a"}, Current: 1},
		"empty step":   Stepper{Label: "P", Steps: []string{"a", ""}, Current: 1},
		"current zero": Stepper{Label: "P", Steps: []string{"a", "b"}},
		"current high": Stepper{Label: "P", Steps: []string{"a", "b"}, Current: 3},
	} {
		if _, err := k.HTML("stepper", data); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestChoiceIsAFieldsetWithLegend(t *testing.T) {
	k := newKit(t)
	doc := string(mustHTML(t, k, "choice", samples(t, k)["choice"]))
	a11ytest.AssertFragment(t, doc)
	for _, want := range []string{
		`<fieldset class="choice" id="source">`, `<legend>Source</legend>`, `<p class="hint" id="source-hint">Pick one</p>`,
		`<label class="choice-card" for="source-1">`, `<input type="radio" id="source-1" name="source" value="single" aria-describedby="source-hint" checked>`,
		`<span class="choice-title">Single credential</span>`, `<span class="choice-text">Type the claims.</span>`,
		`<input type="radio" id="source-2" name="source" value="bulk" aria-describedby="source-hint" disabled>`, `<span class="choice-meta">3 sources</span>`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("choice missing %q\n%s", want, doc)
		}
	}
	multi := string(mustHTML(t, k, "choice", Choice{ID: "ch", Name: "channels", Legend: "Channels", Multiple: true, Options: []ChoiceOption{{Value: "qr", Title: "QR"}}}))
	if !strings.Contains(multi, `<input type="checkbox" id="ch-1" name="channels" value="qr">`) || strings.Contains(multi, "hint") {
		t.Errorf("multiple choice wrong:\n%s", multi)
	}
	for name, data := range map[string]any{
		"no id":      Choice{Legend: "x", Options: []ChoiceOption{{Value: "a", Title: "A"}}},
		"no legend":  Choice{ID: "c", Options: []ChoiceOption{{Value: "a", Title: "A"}}},
		"no options": Choice{ID: "c", Legend: "x"},
		"no value":   Choice{ID: "c", Legend: "x", Options: []ChoiceOption{{Title: "A"}}},
		"no title":   Choice{ID: "c", Legend: "x", Options: []ChoiceOption{{Value: "a"}}},
	} {
		if _, err := k.HTML("choice", data); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestCodeBlockIsLabelled(t *testing.T) {
	k := newKit(t)
	doc := string(mustHTML(t, k, "code", samples(t, k)["code"]))
	a11ytest.AssertFragment(t, doc)
	want := `<figure class="code" id="offer">` + "\n" + `<figcaption id="offer-label">Credential offer</figcaption>` + "\n" +
		`<pre tabindex="0" role="region" aria-labelledby="offer-label"><code>openid-credential-offer://?a=&lt;b&gt;</code></pre>` + "\n</figure>\n"
	if doc != want {
		t.Errorf("code = %q, want %q", doc, want)
	}
	for name, data := range map[string]any{
		"no id":    Code{Label: "x", Text: "y"},
		"no label": Code{ID: "c", Text: "y"},
		"no text":  Code{ID: "c", Label: "x"},
	} {
		if _, err := k.HTML("code", data); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestEmptyStateHasAction(t *testing.T) {
	k := newKit(t)
	doc := string(mustHTML(t, k, "empty", samples(t, k)["empty"]))
	a11ytest.AssertFragment(t, doc)
	for _, want := range []string{
		`<div class="empty">`, `<p class="empty-title">Nothing issued yet</p>`, `<p class="empty-text">The first credential appears here.</p>`,
		`<a class="btn btn-primary" href="/issue">Issue one</a>`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("empty state missing %q\n%s", want, doc)
		}
	}
	for name, data := range map[string]any{
		"no title":  Empty{Action: Button{Text: "x"}},
		"no action": Empty{Title: "x"},
	} {
		if _, err := k.HTML("empty", data); err == nil {
			t.Errorf("%s: expected an error", name)
		}
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

func TestPageHeaderActions(t *testing.T) {
	k := newKit(t)
	btn, err := k.HTML("button", Button{Text: "Identity console", Href: "https://kc.example/admin/x/console/"})
	if err != nil {
		t.Fatal(err)
	}
	doc := renderShellPage(t, k, Page{Title: "Overview", Lead: "A lead.", Actions: btn, Shell: issuerShell()})
	want := `<p class="pg-header-lead">A lead.</p>
<div class="pg-header-actions"><a class="btn btn-secondary" href="https://kc.example/admin/x/console/">Identity console</a></div>
</div>`
	if !strings.Contains(doc, want) {
		t.Errorf("want %q in\n%s", want, doc)
	}
	// Without actions the header has no empty row.
	plain := renderShellPage(t, k, Page{Title: "Overview", Shell: issuerShell()})
	if strings.Contains(plain, "pg-header-actions") {
		t.Error("an empty actions slot renders a row")
	}
	a11ytest.AssertPage(t, doc)
}

func TestShellSideNavExternalLinkIsPlain(t *testing.T) {
	k := newKit(t)
	sh := issuerShell()
	sh.Sections = append(sh.Sections, NavSection{Label: "Console", Links: []Link{
		{Href: "https://kc.example/admin/vca-issuer-realm/console/", Text: "vca-issuer-realm"},
	}})
	doc := renderShellPage(t, k, Page{Title: "Overview", Shell: sh})
	// An external side link opens as a plain link: no htmx swap into the
	// main region, and rel="noopener".
	want := `<li><a href="https://kc.example/admin/vca-issuer-realm/console/" rel="noopener">vca-issuer-realm</a></li>`
	if !strings.Contains(doc, want) {
		t.Errorf("want %q in\n%s", want, doc)
	}
	if strings.Contains(doc, `hx-get="https://kc.example`) {
		t.Error("an external side link must not swap through htmx")
	}
	a11ytest.AssertPage(t, doc)
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
	if len(Names) != 27 {
		t.Errorf("Names = %v", Names)
	}
	for _, n := range Names {
		if k.tpl.Lookup(n) == nil {
			t.Errorf("template %q is not defined", n)
		}
	}
}

// TestNavLinksBoostOnlyLocalPaths keeps htmx off a nav link that leaves
// the page: an anchor and an external address open as plain links, a
// local path swaps the main region.
func TestNavLinksBoostOnlyLocalPaths(t *testing.T) {
	k := newKit(t)
	doc := renderShellPage(t, k, Page{Title: "VCA", Nav: Nav{Links: []Link{
		{Href: "/roles/", Text: "Start"}, {Href: "#how", Text: "How it works"},
		{Href: "https://example.org/docs", Text: "Docs"}, {Href: "//cdn.example/x", Text: "Odd"},
	}}})
	for _, want := range []string{
		`<a href="/roles/" hx-get="/roles/" hx-target="#page" hx-push-url="true">Start</a>`,
		`<a href="#how">How it works</a>`,
		`<a href="https://example.org/docs" rel="noopener">Docs</a>`,
		`<a href="//cdn.example/x" rel="noopener">Odd</a>`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("nav missing %q\n%s", want, doc)
		}
	}
	for href, local := range map[string]bool{"/": true, "/a/b": true, "#x": false, "https://a": false, "//a": false, "": false} {
		if (Link{Href: href}).Local() != local {
			t.Errorf("Local(%q) = %v", href, !local)
		}
	}
}

// TestBlockCarriesHeadingLeadMetaAndAttrs checks the page section: a
// section labelled by its h2, a lead, a meta line, a body, and the
// whitelisted htmx attributes that let it refresh itself.
func TestBlockCarriesHeadingLeadMetaAndAttrs(t *testing.T) {
	k := newKit(t)
	doc := string(mustHTML(t, k, "block", Block{ID: "stacks", Title: "Stacks on this deployment", Lead: "Only running services appear.",
		Meta: "VCA 1.0, updated 09:41", Body: `<p>body</p>`,
		Attrs: map[string]string{"hx-get": "/stacks", "hx-trigger": "every 30s", "hx-swap": "outerHTML"}}))
	a11ytest.AssertFragment(t, doc)
	for _, want := range []string{
		`<section class="block" id="stacks" aria-labelledby="stacks-title" hx-get="/stacks" hx-swap="outerHTML" hx-trigger="every 30s">`,
		`<div class="block-head">`, `<h2 id="stacks-title">Stacks on this deployment</h2>`,
		`<p class="block-lead">Only running services appear.</p>`, `<span class="block-meta">VCA 1.0, updated 09:41</span>`,
		`<p>body</p>`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("block missing %q\n%s", want, doc)
		}
	}
	bare := string(mustHTML(t, k, "block", Block{ID: "how", Title: "How"}))
	if strings.Contains(bare, "block-lead") || strings.Contains(bare, "block-meta") || strings.Contains(bare, "hx-") {
		t.Errorf("a bare block has no optional parts:\n%s", bare)
	}
	for name, data := range map[string]any{
		"no id":       Block{Title: "x"},
		"no title":    Block{ID: "a"},
		"bad attr":    Block{ID: "a", Title: "x", Attrs: map[string]string{"onclick": "x"}},
		"bad id":      Block{ID: "1a", Title: "x"},
		"space in id": Block{ID: "a b", Title: "x"},
	} {
		if _, err := k.HTML("block", data); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// TestFigureHasATextEquivalent checks the diagram figure: the SVG is an
// image named by its title, and the caption carries the words a screen
// reader gets instead of the drawing.
func TestFigureHasATextEquivalent(t *testing.T) {
	k := newKit(t)
	svg := template.HTML(`<circle class="fig-node" cx="1" cy="1" r="1"/><text class="fig-text" x="0" y="0">Issuer</text>`) //nolint:gosec // literal
	doc := string(mustHTML(t, k, "figure", Figure{ID: "triangle", Title: "The triangle of trust",
		Caption: "Issuer, holder and verifier, with the trust registry between them.", ViewBox: "0 0 320 200", SVG: svg}))
	a11ytest.AssertFragment(t, doc)
	for _, want := range []string{
		`<figure class="figure" id="triangle">`, `<svg viewBox="0 0 320 200" role="img" aria-labelledby="triangle-title triangle-caption">`,
		`<title id="triangle-title">The triangle of trust</title>`, `<circle class="fig-node"`, `<text class="fig-text"`,
		`<figcaption id="triangle-caption" class="visually-hidden">Issuer, holder and verifier, with the trust registry between them.</figcaption>`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("figure missing %q\n%s", want, doc)
		}
	}
	for name, data := range map[string]any{
		"no id":      Figure{Title: "t", Caption: "c", ViewBox: "0 0 1 1", SVG: svg},
		"no title":   Figure{ID: "f", Caption: "c", ViewBox: "0 0 1 1", SVG: svg},
		"no caption": Figure{ID: "f", Title: "t", ViewBox: "0 0 1 1", SVG: svg},
		"no svg":     Figure{ID: "f", Title: "t", Caption: "c", ViewBox: "0 0 1 1"},
		"bad box":    Figure{ID: "f", Title: "t", Caption: "c", ViewBox: "wide", SVG: svg},
		"script":     Figure{ID: "f", Title: "t", Caption: "c", ViewBox: "0 0 1 1", SVG: `<script>x</script>`},
		"handler":    Figure{ID: "f", Title: "t", Caption: "c", ViewBox: "0 0 1 1", SVG: `<a onclick="x">y</a>`},
	} {
		if _, err := k.HTML("figure", data); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// TestStacksShowTheStateInWords checks the stack cards of the landing:
// one article per stack, its version, its components with links, and
// one row per role whose state is a word, never only a colour.
func TestStacksShowTheStateInWords(t *testing.T) {
	k := newKit(t)
	doc := string(mustHTML(t, k, "stacks", Stacks{
		ComponentsLabel: "Components", RolesLabel: "Roles",
		Items: []StackCard{{
			ID: "stack-a", Name: "Alpha Stack", Version: "Pinned 1.2.3",
			Components: []Component{{Name: "issuer-api", Version: "pinned 1.2.3", RepoHref: "https://example.org/repo", RepoText: "GitHub",
				DocsHref: "https://example.org/docs", DocsText: "Documentation"}},
			Roles: []RoleRow{{Label: "Issuer", State: "live", Text: "Live"}, {Label: "Holder", State: "starting", Text: "Starting"}},
		}, {ID: "stack-b", Name: "Beta Stack", Roles: []RoleRow{{Label: "Admin", State: "live", Text: "Live"}}}},
	}))
	a11ytest.AssertFragment(t, doc)
	for _, want := range []string{
		`<ul class="stacks">`, `<article class="stack" id="stack-a" aria-labelledby="stack-a-title">`,
		`<h3 id="stack-a-title">Alpha Stack</h3>`, `<span class="stack-version">Pinned 1.2.3</span>`,
		`<h4 class="stack-label">Components</h4>`, `<span class="stack-component-name">issuer-api</span>`,
		`<span class="stack-component-version">pinned 1.2.3</span>`,
		`<a href="https://example.org/repo" rel="noopener">GitHub</a>`, `<a href="https://example.org/docs" rel="noopener">Documentation</a>`,
		`<h4 class="stack-label">Roles</h4>`, `<li class="stack-role stack-role-live"><span>Issuer</span><span class="badge badge-ok">Live</span></li>`,
		`<li class="stack-role stack-role-starting"><span>Holder</span><span class="badge badge-warn">Starting</span></li>`,
		`<article class="stack" id="stack-b"`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("stacks missing %q\n%s", want, doc)
		}
	}
	if strings.Count(doc, `class="stack-label">Components`) != 1 {
		t.Error("a stack with no component has no components heading")
	}
	for name, data := range map[string]any{
		"no item":      Stacks{},
		"no id":        Stacks{Items: []StackCard{{Name: "x", Roles: []RoleRow{{Label: "a", State: "live", Text: "Live"}}}}},
		"no name":      Stacks{Items: []StackCard{{ID: "s", Roles: []RoleRow{{Label: "a", State: "live", Text: "Live"}}}}},
		"no role":      Stacks{Items: []StackCard{{ID: "s", Name: "x"}}},
		"bad state":    Stacks{Items: []StackCard{{ID: "s", Name: "x", Roles: []RoleRow{{Label: "a", State: "down", Text: "Down"}}}}},
		"no text":      Stacks{Items: []StackCard{{ID: "s", Name: "x", Roles: []RoleRow{{Label: "a", State: "live"}}}}},
		"no comp name": Stacks{Items: []StackCard{{ID: "s", Name: "x", Roles: []RoleRow{{Label: "a", State: "live", Text: "Live"}}, Components: []Component{{Version: "1"}}}}},
		"link no text": Stacks{Items: []StackCard{{ID: "s", Name: "x", Roles: []RoleRow{{Label: "a", State: "live", Text: "Live"}}, Components: []Component{{Name: "c", RepoHref: "https://x"}}}}},
	} {
		if _, err := k.HTML("stacks", data); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// The default labels are English.
	plain := string(mustHTML(t, k, "stacks", Stacks{Items: []StackCard{{ID: "s", Name: "x",
		Components: []Component{{Name: "c"}}, Roles: []RoleRow{{Label: "a", State: "live", Text: "Live"}}}}}))
	if !strings.Contains(plain, ">Components</h4>") || !strings.Contains(plain, ">Roles</h4>") {
		t.Errorf("default labels:\n%s", plain)
	}
}

// TestCTABandHasOneAction checks the call to action band: a section
// labelled by its heading, a sentence, and one button.
func TestCTABandHasOneAction(t *testing.T) {
	k := newKit(t)
	doc := string(mustHTML(t, k, "cta", CTA{ID: "start", Title: "Pick a role.", Text: "Walk one flow end to end.",
		Action: Button{Text: "Start with VCA", Href: "/roles/", Variant: "primary"}}))
	a11ytest.AssertFragment(t, doc)
	for _, want := range []string{
		`<section class="cta" id="start" aria-labelledby="start-title">`, `<h2 id="start-title">Pick a role.</h2>`,
		`<p class="cta-text">Walk one flow end to end.</p>`, `<div class="cta-actions">`, `<a class="btn btn-primary" href="/roles/">Start with VCA</a>`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("cta missing %q\n%s", want, doc)
		}
	}
	more := mustHTML(t, k, "button", Button{Text: "Continue on Beta", Href: "/b", Variant: "secondary"})
	choice := string(mustHTML(t, k, "cta", CTA{ID: "s", Title: "Sign in", Action: Button{Text: "Continue on Alpha", Href: "/a", Variant: "primary"}, More: more}))
	if !strings.Contains(choice, `href="/a">Continue on Alpha</a>`) || !strings.Contains(choice, `href="/b">Continue on Beta</a>`) {
		t.Errorf("cta with more buttons:\n%s", choice)
	}
	for name, data := range map[string]any{
		"no id":      CTA{Title: "t", Action: Button{Text: "x"}},
		"no title":   CTA{ID: "c", Action: Button{Text: "x"}},
		"bad action": CTA{ID: "c", Title: "t"},
	} {
		if _, err := k.HTML("cta", data); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// TestNoteRendersLabelAndText checks the small aside of a hero: a tracked
// label, a sentence, and the accent line.
func TestNoteRendersLabelAndText(t *testing.T) {
	k := newKit(t)
	doc := string(mustHTML(t, k, "note", Note{Label: "One role", Text: "This deployment runs one role."}))
	a11ytest.AssertFragment(t, doc)
	for _, want := range []string{
		`<div class="ethos note">`, `<span class="ethos-label">One role</span>`, `<p>This deployment runs one role.</p>`,
		`<div class="ethos-line" aria-hidden="true"></div>`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("note missing %q\n%s", want, doc)
		}
	}
	bare := string(mustHTML(t, k, "note", Note{Text: "Only text."}))
	if strings.Contains(bare, "ethos-label") {
		t.Errorf("a note without a label has no label element:\n%s", bare)
	}
	if _, err := k.HTML("note", Note{}); err == nil {
		t.Error("a note without text passed")
	}
}

// TestTileCarriesAFigure lets a tile hold a diagram between its text and
// its meta line, and keeps an external tile a plain link.
func TestTileCarriesAFigure(t *testing.T) {
	k := newKit(t)
	fig := mustHTML(t, k, "figure", Figure{ID: "f", Title: "t", Caption: "c", ViewBox: "0 0 1 1", SVG: `<circle class="fig-node" r="1"/>`})
	doc := string(mustHTML(t, k, "tiles", Tiles{Items: []Tile{{Num: "03", Title: "Triangle", Text: "Text.", Figure: fig, Meta: "Read more", Href: "https://example.org/x"}}}))
	a11ytest.AssertFragment(t, doc)
	if !strings.Contains(doc, `<a class="tile" href="https://example.org/x" rel="noopener">`) {
		t.Errorf("an external tile needs rel=noopener:\n%s", doc)
	}
	text := strings.Index(doc, "<p>Text.</p>")
	figure := strings.Index(doc, `<figure class="figure"`)
	meta := strings.Index(doc, `<span class="tile-meta">`)
	if text >= figure || figure >= meta {
		t.Errorf("the figure sits between the text and the meta line:\n%s", doc)
	}
	local := string(mustHTML(t, k, "tiles", Tiles{Items: []Tile{{Title: "Local", Href: "/roles/"}}}))
	if strings.Contains(local, "noopener") || !strings.Contains(local, `<ul class="tiles">`) {
		t.Errorf("a local tile needs no rel, and four columns is the default:\n%s", local)
	}
	three := string(mustHTML(t, k, "tiles", Tiles{Columns: 3, Items: []Tile{{Title: "Local", Href: "/roles/"}}}))
	if !strings.Contains(three, `<ul class="tiles tiles-3">`) {
		t.Errorf("three columns carry the modifier:\n%s", three)
	}
	if _, err := k.HTML("tiles", Tiles{Columns: 5, Items: []Tile{{Title: "x", Href: "/"}}}); err == nil {
		t.Error("five columns passed")
	}
}

// TestSignInRendersProvidersAndRegister checks the sign in chooser
// (ADR-035): the role and the title on the left with the lead and the
// back link, one button per provider with its realm in the monospace
// stack on the right, the callout, the extra block, the rule with the
// word "or", the register actions, and the note. The block carries the
// one h1 of the page.
func TestSignInRendersProvidersAndRegister(t *testing.T) {
	k := newKit(t)
	block := &SignIn{
		Role: "Issuer", Title: "Sign in as an issuer.", Lead: "You return to the issuer portal after sign in.",
		Back: Link{Href: "https://vca.example/roles/", Text: "Choose another role"}, Label: "Continue with",
		Providers: []SignInProvider{
			{Text: "Keycloak", Href: "/auth/login?provider=default", Meta: "vca-issuer-realm"},
			{Text: "Second", Href: "/auth/login?provider=b"},
		},
		Callout: "Paste the bootstrap token, then register.", CalloutLabel: "First admin?",
		Extra: `<p id="extra">Extra</p>`,
		Or:    "or", Register: []Button{{Text: "Register a new account", Href: "/auth/register?provider=default", Variant: "ghost"}},
		Note: "VCA is not tied to Keycloak.",
	}
	doc := renderShellPage(t, k, Page{Title: "Sign in", SignIn: block, Nav: Nav{Links: []Link{{Href: "/", Text: "Home"}}}})
	for _, want := range []string{
		`<section class="signin">`, `<div class="signin-left">`, `<span class="role">Issuer</span>`,
		`<h1>Sign in as an issuer.</h1>`, `<p class="desc">You return to the issuer portal after sign in.</p>`,
		`<a class="signin-back" href="https://vca.example/roles/" rel="noopener">Choose another role</a>`,
		`<div class="signin-panel">`, `<p class="signin-label">Continue with</p>`, `<ul class="signin-providers">`,
		`<a class="btn btn-primary signin-provider" href="/auth/login?provider=default"><span>Keycloak</span><span class="signin-meta">vca-issuer-realm</span></a>`,
		`<a class="btn btn-secondary signin-provider" href="/auth/login?provider=b"><span>Second</span></a>`,
		`<div class="signin-callout"><strong>First admin?</strong> Paste the bootstrap token, then register.</div>`,
		`<p id="extra">Extra</p>`, `<div class="signin-or"><span>or</span></div>`, `<div class="signin-register">`,
		`<a class="btn btn-ghost" href="/auth/register?provider=default">Register a new account</a>`,
		`<p class="signin-note">VCA is not tied to Keycloak.</p>`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("sign in page missing %q\n%s", want, doc)
		}
	}
	if strings.Contains(doc, "pg-header") {
		t.Error("a sign in block replaces the page header")
	}
	if strings.Count(doc, "<h1>") != 1 {
		t.Error("the sign in block carries the one h1")
	}
	// Without providers the panel says so, and every optional part is
	// absent when its field is empty.
	bare := string(mustHTML(t, k, "signin", SignIn{Title: "Plain", Empty: "No provider yet."}))
	a11ytest.AssertFragment(t, bare)
	if !strings.Contains(bare, `<p class="signin-empty">No provider yet.</p>`) {
		t.Errorf("an empty chooser names the gap:\n%s", bare)
	}
	for _, absent := range []string{"role-row", "desc", "signin-back", "signin-label", "signin-providers", "signin-callout", "signin-or", "signin-register", "signin-note"} {
		if strings.Contains(bare, absent) {
			t.Errorf("a bare sign in block has no %s:\n%s", absent, bare)
		}
	}
	// The word on the rule defaults to "or", and a local back link
	// carries no rel.
	local := string(mustHTML(t, k, "signin", SignIn{Title: "T", Back: Link{Href: "/roles/", Text: "Back"}, Register: []Button{{Text: "Register", Href: "/r"}}}))
	if !strings.Contains(local, `<a class="signin-back" href="/roles/">Back</a>`) || !strings.Contains(local, `<span>or</span>`) {
		t.Errorf("local back link and default rule word:\n%s", local)
	}
	// A missing title, a provider without a link, and a bad register
	// button fail.
	for name, bad := range map[string]SignIn{
		"no title":         {},
		"provider no href": {Title: "T", Providers: []SignInProvider{{Text: "X"}}},
		"provider no text": {Title: "T", Providers: []SignInProvider{{Href: "/x"}}},
		"bad register":     {Title: "T", Register: []Button{{}}},
	} {
		if _, err := k.HTML("signin", bad); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if err := k.RenderPage(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), Page{Title: "x", SignIn: &SignIn{}}); err == nil {
		t.Error("a page with a bad sign in block should fail")
	}
}

func TestTabsMarkTheCurrentView(t *testing.T) {
	k := newKit(t)
	doc := string(mustHTML(t, k, "tabs", Tabs{Label: "Trust views", Links: []Link{
		{Href: "/admin/trust", Text: "Trust list", Current: true},
		{Href: "/admin/trust/registries", Text: "Registries"},
	}}))
	a11ytest.AssertFragment(t, doc)
	for _, want := range []string{
		`<nav class="tabs" aria-label="Trust views">`,
		`<a href="/admin/trust" aria-current="page">Trust list</a>`,
		`<a href="/admin/trust/registries">Registries</a>`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("tabs missing %q\n%s", want, doc)
		}
	}
	for name, data := range map[string]any{
		"no label":  Tabs{Links: []Link{{Href: "/a", Text: "A"}, {Href: "/b", Text: "B"}}},
		"one link":  Tabs{Label: "Views", Links: []Link{{Href: "/a", Text: "A"}}},
		"no text":   Tabs{Label: "Views", Links: []Link{{Href: "/a", Text: "A"}, {Href: "/b"}}},
		"no href":   Tabs{Label: "Views", Links: []Link{{Href: "/a", Text: "A"}, {Text: "B"}}},
		"two marks": Tabs{Label: "Views", Links: []Link{{Href: "/a", Text: "A", Current: true}, {Href: "/b", Text: "B", Current: true}}},
	} {
		if _, err := k.HTML("tabs", data); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
