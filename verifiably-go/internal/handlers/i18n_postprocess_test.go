package handlers

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// i18nUpperTranslator is a stub Translator: it uppercases text, returns "" for
// the sentinel "drop me", and records every call so tests can assert exactly
// which strings reached the translator.
type i18nUpperTranslator struct{ calls []string }

func (u *i18nUpperTranslator) Translate(_ context.Context, text, _ string) string {
	u.calls = append(u.calls, text)
	if text == "drop me" {
		return ""
	}
	return strings.ToUpper(text)
}

func TestTranslateHTML_PassThroughCases(t *testing.T) {
	body := []byte("<p>hello world</p>")
	tr := &i18nUpperTranslator{}
	cases := []struct {
		name string
		body []byte
		lang string
		tr   Translator
	}{
		{"nil translator", body, "fr", nil},
		{"empty lang", body, "", tr},
		{"english", body, "en", tr},
		{"empty body", nil, "fr", tr},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := translateHTML(context.Background(), c.body, c.lang, c.tr)
			if string(got) != string(c.body) {
				t.Errorf("body changed: %q", got)
			}
		})
	}
	if len(tr.calls) != 0 {
		t.Errorf("translator must not be called on pass-through, got %v", tr.calls)
	}
}

func TestTranslateHTML_TranslatesTextAndAttrsSkipsOptOuts(t *testing.T) {
	in := `<div title="tool tip" data-x="keep me" placeholder="type here">` +
		`<p>hello world</p>` +
		`<span class="pill mono">did:web:issuer.example</span>` +
		`<em translate="no">verbatim text</em>` +
		`<code>some code</code>` +
		`<script>var greeting = "script text";</script>` +
		`<b>--&gt;</b><i>x</i><u>drop me</u><s>SAME</s>` +
		`</div>`
	tr := &i18nUpperTranslator{}
	out := string(translateHTML(context.Background(), []byte(in), "fr", tr))

	want := []string{`title="TOOL TIP"`, `placeholder="TYPE HERE"`, `data-x="keep me"`,
		`<p>HELLO WORLD</p>`, `did:web:issuer.example`, `>verbatim text<`, `<code>some code</code>`,
		`var greeting = "script text";`, `<b>--&gt;</b>`, `<i>x</i>`, `<u>drop me</u>`, `<s>SAME</s>`}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("output missing %q:\n%s", w, out)
		}
	}
	for _, bad := range []string{"DID:WEB", "VERBATIM", "SOME CODE", "SCRIPT TEXT", "KEEP ME"} {
		if strings.Contains(out, bad) {
			t.Errorf("opted-out content was translated (%q):\n%s", bad, out)
		}
	}
	// Exactly the worthwhile strings reached the translator.
	wantCalls := []string{"tool tip", "type here", "hello world", "drop me", "SAME"}
	if strings.Join(tr.calls, "|") != strings.Join(wantCalls, "|") {
		t.Errorf("translator calls = %v, want %v", tr.calls, wantCalls)
	}
}

func TestWalkAndTranslate_NilNodeIsNoop(t *testing.T) {
	tr := &i18nUpperTranslator{}
	walkAndTranslate(context.Background(), nil, "fr", tr, false)
	if len(tr.calls) != 0 {
		t.Errorf("nil node must not translate anything, got %v", tr.calls)
	}
}

func TestElementIsNoTranslate(t *testing.T) {
	mk := func(attrs ...string) *html.Node {
		n := &html.Node{Type: html.ElementNode, Data: "span"}
		for i := 0; i+1 < len(attrs); i += 2 {
			n.Attr = append(n.Attr, html.Attribute{Key: attrs[i], Val: attrs[i+1]})
		}
		return n
	}
	cases := []struct {
		name string
		n    *html.Node
		want bool
	}{
		{"no attrs", mk(), false},
		{"translate=no", mk("translate", "no"), true},
		{"translate=yes", mk("translate", "yes"), false},
		{"class mono", mk("class", "pill mono"), true},
		{"class notr", mk("class", "notr"), true},
		{"class other", mk("class", "pill monospace"), false},
		{"unrelated attr", mk("id", "mono"), false},
	}
	for _, c := range cases {
		if got := elementIsNoTranslate(c.n); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestAttrIsUserFacing(t *testing.T) {
	for _, k := range []string{"title", "placeholder", "alt", "aria-label"} {
		if !attrIsUserFacing(k) {
			t.Errorf("%s should be user-facing", k)
		}
	}
	for _, k := range []string{"href", "class", "data-x", ""} {
		if attrIsUserFacing(k) {
			t.Errorf("%s should not be user-facing", k)
		}
	}
}

func TestTranslateIfWorth(t *testing.T) {
	tr := &i18nUpperTranslator{}
	ctx := context.Background()
	cases := []struct{ in, want string }{
		{"", ""},
		{"   \n", ""},
		{"-->", ""},
		{"a", ""},          // one letter only
		{"a1", ""},         // still one letter
		{"12345", ""},      // digits only
		{"hello", "HELLO"}, // plain
		{"  hi there\n", "  HI THERE\n"},
		{"SAME", ""},    // translator returned the input unchanged
		{"drop me", ""}, // translator returned empty
	}
	for _, c := range cases {
		if got := translateIfWorth(ctx, c.in, "fr", tr); got != c.want {
			t.Errorf("translateIfWorth(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSplitWhitespaceAndIsSpace(t *testing.T) {
	cases := []struct{ in, lead, core, trail string }{
		{"", "", "", ""},
		{"abc", "", "abc", ""},
		{" \t abc\r\n", " \t ", "abc", "\r\n"},
		{"   ", "   ", "", ""},
	}
	for _, c := range cases {
		l, m, r := splitWhitespace(c.in)
		if l != c.lead || m != c.core || r != c.trail {
			t.Errorf("splitWhitespace(%q) = %q,%q,%q", c.in, l, m, r)
		}
	}
	for _, b := range []byte{' ', '\t', '\n', '\r'} {
		if !isSpace(b) {
			t.Errorf("isSpace(%q) = false", b)
		}
	}
	for _, b := range []byte{'a', '\v', 0} {
		if isSpace(b) {
			t.Errorf("isSpace(%q) = true", b)
		}
	}
}
