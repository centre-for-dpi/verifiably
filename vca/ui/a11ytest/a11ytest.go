// SPDX-License-Identifier: Apache-2.0

// Package a11ytest checks rendered HTML for the structural WCAG 2.2 rules
// the vca UI kit guarantees. Use AssertPage in the tests of every page.
//
// The checks work on markup produced by html/template, where every "<" in
// text and every quote in an attribute value is escaped.
package a11ytest

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

var (
	tagRE   = regexp.MustCompile(`(?s)<([a-zA-Z][a-zA-Z0-9-]*)([^>]*)>`)
	attrRE  = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9:-]*)(?:\s*=\s*"([^"]*)")?`)
	stripRE = regexp.MustCompile(`(?s)<[^>]*>`)
)

// tag is one opening tag with its attributes and its inner text.
type tag struct {
	name  string
	attrs map[string]string
	has   map[string]bool
	inner string
}

func parse(doc string) []tag {
	var tags []tag
	for _, m := range tagRE.FindAllStringSubmatchIndex(doc, -1) {
		name := strings.ToLower(doc[m[2]:m[3]])
		t := tag{name: name, attrs: map[string]string{}, has: map[string]bool{}}
		for _, a := range attrRE.FindAllStringSubmatch(doc[m[4]:m[5]], -1) {
			k := strings.ToLower(a[1])
			t.has[k] = true
			t.attrs[k] = a[2]
		}
		if end := strings.Index(strings.ToLower(doc[m[1]:]), "</"+name); end >= 0 {
			t.inner = doc[m[1] : m[1]+end]
		}
		tags = append(tags, t)
	}
	return tags
}

func textOf(t tag) string {
	return strings.TrimSpace(stripRE.ReplaceAllString(t.inner, ""))
}

func count(tags []tag, name string) int {
	n := 0
	for _, t := range tags {
		if t.name == name {
			n++
		}
	}
	return n
}

func ids(tags []tag) map[string]bool {
	out := map[string]bool{}
	for _, t := range tags {
		if id := t.attrs["id"]; id != "" {
			out[id] = true
		}
	}
	return out
}

func labelled(t tag) bool {
	return t.attrs["aria-label"] != "" || t.attrs["aria-labelledby"] != ""
}

// Check returns every rule the document breaks. An empty result is a pass.
func Check(doc string) []string {
	tags := parse(doc)
	known := ids(tags)
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	if n := count(tags, "h1"); n != 1 {
		add("want exactly one h1, found %d", n)
	}
	if n := count(tags, "html"); n != 1 {
		add("want exactly one html element, found %d", n)
	}
	if n := count(tags, "main"); n != 1 {
		add("want exactly one main landmark, found %d", n)
	}
	if strings.Contains(doc, `href="#"`) {
		add(`placeholder link href="#" found`)
	}
	skip, nav := false, false
	labels := map[string]bool{}
	for _, t := range tags {
		if t.name == "label" {
			labels[t.attrs["for"]] = true
		}
	}
	for _, t := range tags {
		switch t.name {
		case "html":
			if t.attrs["lang"] == "" {
				add("html element has no lang attribute")
			}
		case "a":
			href := t.attrs["href"]
			if strings.Contains(t.attrs["class"], "skip-link") {
				skip = true
				if !strings.HasPrefix(href, "#") || !known[href[1:]] {
					add("skip link target %q does not exist", href)
				}
			}
		case "nav":
			nav = true
			if !labelled(t) {
				add("nav landmark has no aria-label or aria-labelledby")
			}
		case "img":
			if !t.has["alt"] {
				add("img without alt: src=%q", t.attrs["src"])
			}
		case "button":
			if textOf(t) == "" && !labelled(t) {
				add("button without text or aria-label: %q", t.inner)
			}
			if t.has["aria-controls"] && !t.has["aria-expanded"] {
				add("disclosure button controlling %q has no aria-expanded", t.attrs["aria-controls"])
			}
		case "input", "select", "textarea":
			typ := t.attrs["type"]
			if t.name == "input" && (typ == "hidden" || typ == "submit" || typ == "button" || typ == "reset") {
				continue
			}
			if !labels[t.attrs["id"]] && !labelled(t) {
				add("%s %q has no label", t.name, t.attrs["id"])
			}
		}
	}
	if !skip {
		add("no skip link")
	}
	if !nav {
		add("no nav landmark")
	}
	return problems
}

// AssertPage fails the test for every rule the document breaks.
func AssertPage(t testing.TB, doc string) {
	t.Helper()
	for _, p := range Check(doc) {
		t.Errorf("a11y: %s", p)
	}
}

// AssertFragment checks the rules that apply to a partial: images have alt,
// buttons are named, disclosures carry aria-expanded, inputs have labels,
// and there is no placeholder link.
func AssertFragment(t testing.TB, doc string) {
	t.Helper()
	for _, p := range Check(doc) {
		if strings.HasPrefix(p, "want exactly") || strings.HasPrefix(p, "no ") || strings.HasPrefix(p, "html element") {
			continue
		}
		t.Errorf("a11y: %s", p)
	}
}
