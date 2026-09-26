// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"regexp"
	"strings"
	"testing"
)

// A POST form of the admin pages that carries a field puts one field
// under the other. The one row layout of the class filters suits a
// search form and a form with only a button, such as the actions of a
// table row. Fields with hints of different lengths break that row.

var (
	formRE    = regexp.MustCompile(`(?s)<form\b([^>]*)>(.*?)</form>`)
	methodRE  = regexp.MustCompile(`method="([^"]*)"`)
	classRE   = regexp.MustCompile(`class="([^"]*)"`)
	actionRE  = regexp.MustCompile(`action="([^"]*)"`)
	controlRE = regexp.MustCompile(`<(input|select|textarea)\b([^>]*)>`)
	typeRE    = regexp.MustCompile(`type="([^"]*)"`)
)

// oneRowPostForms returns the action of every POST form of the page that
// has the class filters and at least one field a person fills in.
func oneRowPostForms(page string) []string {
	var out []string
	for _, m := range formRE.FindAllStringSubmatch(page, -1) {
		attrs, body := m[1], m[2]
		method := methodRE.FindStringSubmatch(attrs)
		class := classRE.FindStringSubmatch(attrs)
		if method == nil || !strings.EqualFold(method[1], "post") || class == nil || !hasClass(class[1], "filters") {
			continue
		}
		for _, c := range controlRE.FindAllStringSubmatch(body, -1) {
			if c[1] == "input" {
				kind := typeRE.FindStringSubmatch(c[2])
				if kind != nil && (kind[1] == "hidden" || kind[1] == "submit" || kind[1] == "button") {
					continue
				}
			}
			action := ""
			if a := actionRE.FindStringSubmatch(attrs); a != nil {
				action = a[1]
			}
			out = append(out, action)
			break
		}
	}
	return out
}

func hasClass(list, name string) bool {
	for _, c := range strings.Fields(list) {
		if c == name {
			return true
		}
	}
	return false
}

// assertNoOneRowPostForm fails on a POST form with fields in one row.
func assertNoOneRowPostForm(t *testing.T, path, page string) {
	t.Helper()
	for _, action := range oneRowPostForms(page) {
		t.Errorf("%s: the POST form %s puts its fields in one row; use the stacked form", path, action)
	}
}

func TestOneRowPostFormsFindsTheRow(t *testing.T) {
	page := `<form class="filters" action="/a" method="post"><input type="hidden" name="t"><button type="submit">Go</button></form>
<form class="filters" action="/b" method="post"><input type="hidden" name="t"><input id="x" name="x"></form>
<form class="filters" action="/c" method="get"><input id="q" name="q"></form>
<form action="/d" method="post"><select id="s" name="s"></select></form>
<form class="filters wide" action="/e" method="POST"><textarea id="n" name="n"></textarea></form>`
	got := oneRowPostForms(page)
	if strings.Join(got, ",") != "/b,/e" {
		t.Errorf("found %v, want /b and /e", got)
	}
}

// TestNoAdminPostFormIsOneRow renders every admin page with a POST form
// and fails on a form whose fields share one row.
func TestNoAdminPostFormIsOneRow(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	h.seedRegistries()
	for _, path := range []string{
		"/admin/", "/admin/providers", "/admin/providers/new", "/admin/trust", "/admin/trust/registries",
		"/admin/keys", "/admin/tenants", "/admin/audit", "/admin/notifications",
	} {
		status, body := h.get(t, path)
		if status != 200 {
			t.Errorf("%s status = %d", path, status)
			continue
		}
		if !strings.Contains(body, `method="post"`) {
			continue
		}
		assertNoOneRowPostForm(t, path, body)
	}
}
