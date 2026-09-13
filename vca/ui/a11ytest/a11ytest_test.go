// SPDX-License-Identifier: Apache-2.0

package a11ytest

import (
	"strings"
	"testing"
)

const good = `<!DOCTYPE html><html lang="en"><body>
<a class="skip-link" href="#page">Skip</a>
<nav aria-label="Main"><a href="/">Home</a></nav>
<main id="page"><h1>Title</h1>
<img src="/qr.png" alt="QR code">
<button type="button">OK</button>
<button type="button" aria-label="Close"><svg aria-hidden="true"></svg></button>
<button type="button" aria-controls="r" aria-expanded="false">More</button>
<label for="name">Name</label><input id="name" type="text">
<input type="hidden" name="csrf"><input type="submit" value="Go">
<select id="s" aria-label="Pick"></select>
<textarea aria-labelledby="name"></textarea>
</main></body></html>`

func TestGoodDocumentPasses(t *testing.T) {
	if p := Check(good); len(p) != 0 {
		t.Errorf("unexpected problems: %v", p)
	}
	AssertPage(t, good)
	AssertFragment(t, `<button type="button">OK</button>`)
}

// fakeT records failures so the assert helpers can be tested.
type fakeT struct {
	testing.TB
	msgs []string
}

func (f *fakeT) Helper()                        {}
func (f *fakeT) Errorf(format string, a ...any) { f.msgs = append(f.msgs, format) }

func TestAssertHelpersReportProblems(t *testing.T) {
	ft := &fakeT{}
	AssertPage(ft, "<html></html>")
	if len(ft.msgs) == 0 {
		t.Error("AssertPage should report problems for an empty document")
	}
	ft = &fakeT{}
	AssertFragment(ft, `<img src="x.png"><button></button>`)
	if len(ft.msgs) != 2 {
		t.Errorf("AssertFragment should report 2 problems, got %d", len(ft.msgs))
	}
	ft = &fakeT{}
	AssertFragment(ft, `<span>fragment</span>`)
	if len(ft.msgs) != 0 {
		t.Errorf("AssertFragment should ignore page-level rules, got %v", ft.msgs)
	}
}

func TestEachRule(t *testing.T) {
	cases := map[string]struct {
		mutate func(string) string
		want   string
	}{
		"two h1":            {func(s string) string { return strings.Replace(s, "<h1>", "<h1>A</h1><h1>", 1) }, "exactly one h1"},
		"no lang":           {func(s string) string { return strings.Replace(s, ` lang="en"`, "", 1) }, "no lang"},
		"no skip":           {func(s string) string { return strings.Replace(s, "skip-link", "x", 1) }, "no skip link"},
		"bad skip target":   {func(s string) string { return strings.Replace(s, `href="#page"`, `href="#nope"`, 1) }, "does not exist"},
		"unlabelled nav":    {func(s string) string { return strings.Replace(s, ` aria-label="Main"`, "", 1) }, "nav landmark has no"},
		"no nav":            {func(s string) string { return strings.Replace(s, "nav", "div", 2) }, "no nav landmark"},
		"no main":           {func(s string) string { return strings.Replace(s, "main", "div", 2) }, "exactly one main"},
		"img no alt":        {func(s string) string { return strings.Replace(s, ` alt="QR code"`, "", 1) }, "img without alt"},
		"empty button":      {func(s string) string { return strings.Replace(s, ">OK<", "><", 1) }, "button without text"},
		"no aria-expanded":  {func(s string) string { return strings.Replace(s, ` aria-expanded="false"`, "", 1) }, "no aria-expanded"},
		"href hash":         {func(s string) string { return strings.Replace(s, `href="/"`, `href="#"`, 1) }, "placeholder link"},
		"unlabelled input":  {func(s string) string { return strings.Replace(s, `for="name"`, `for="other"`, 1) }, "input \"name\" has no label"},
		"unlabelled select": {func(s string) string { return strings.Replace(s, ` aria-label="Pick"`, "", 1) }, "select \"s\" has no label"},
	}
	for name, c := range cases {
		problems := Check(c.mutate(good))
		if !strings.Contains(strings.Join(problems, "\n"), c.want) {
			t.Errorf("%s: want a problem containing %q, got %v", name, c.want, problems)
		}
	}
}

func TestParseHandlesUnclosedAndCase(t *testing.T) {
	tags := parse(`<BUTTON aria-label="x"><INPUT type="text" ID="q">`)
	if len(tags) != 2 || tags[0].name != "button" || tags[1].attrs["id"] != "q" {
		t.Errorf("parse = %+v", tags)
	}
	if tags[0].inner != "" {
		t.Errorf("unclosed button should have empty inner, got %q", tags[0].inner)
	}
}
