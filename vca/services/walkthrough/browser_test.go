// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package walkthrough_test

import (
	"bytes"
	"context"
	"html"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// localJar keeps cookies as a browser does. A browser treats
// http://localhost as a secure context, so it keeps and sends a Secure
// cookie there. The jar of the standard library does not, so the jar
// sees localhost as https.
type localJar struct{ jar *cookiejar.Jar }

func secureLocal(u *url.URL) *url.URL {
	if u.Scheme != "http" || u.Hostname() != "localhost" {
		return u
	}
	c := *u
	c.Scheme = "https"
	return &c
}

func (j localJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.jar.SetCookies(secureLocal(u), cookies)
}

func (j localJar) Cookies(u *url.URL) []*http.Cookie { return j.jar.Cookies(secureLocal(u)) }

// browser is one person at one browser. It follows redirects and keeps
// cookies. Every full HTML page it reads must pass the accessibility
// rules of the kit.
type browser struct {
	t      *testing.T
	ctx    context.Context
	client *http.Client
	// pages counts the pages that passed the accessibility check.
	pages int
}

func newBrowser(ctx context.Context, t *testing.T) *browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &browser{t: t, ctx: ctx, client: &http.Client{Jar: localJar{jar: jar}, Timeout: 20 * time.Second}}
}

// page is one answer the browser shows.
type page struct {
	url    *url.URL
	status int
	ctype  string
	body   string
}

// get opens an address.
func (b *browser) get(target string) page {
	b.t.Helper()
	req, err := http.NewRequestWithContext(b.ctx, http.MethodGet, target, nil)
	if err != nil {
		b.t.Fatal(err)
	}
	return b.do(req)
}

// post sends a form.
func (b *browser) post(target string, form url.Values) page {
	b.t.Helper()
	req, err := http.NewRequestWithContext(b.ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		b.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return b.do(req)
}

func (b *browser) do(req *http.Request) page {
	b.t.Helper()
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	res, err := b.client.Do(req)
	if err != nil {
		b.t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	raw, err := io.ReadAll(res.Body)
	if cerr := res.Body.Close(); cerr != nil {
		b.t.Log(cerr)
	}
	if err != nil {
		b.t.Fatal(err)
	}
	p := page{url: res.Request.URL, status: res.StatusCode, ctype: res.Header.Get("Content-Type"), body: string(raw)}
	if strings.HasPrefix(p.ctype, "text/html") && strings.HasPrefix(strings.ToLower(strings.TrimSpace(p.body)), "<!doctype html") {
		before := len(a11ytest.Check(p.body))
		a11ytest.AssertPage(b.t, p.body)
		if before == 0 {
			b.pages++
		} else {
			b.t.Logf("the page %s breaks the accessibility rules", p.url)
		}
	}
	return p
}

// must fails the test unless the page answered 200 with HTML.
func (p page) must(t *testing.T) page {
	t.Helper()
	if p.status != http.StatusOK {
		t.Fatalf("%s answered %d\n%s", p.url, p.status, tail(p.body, 60))
	}
	return p
}

// has fails the test unless the page shows every text, in its markup
// or in its visible words.
func (p page) has(t *testing.T, texts ...string) page {
	t.Helper()
	words := text(p.body)
	for _, s := range texts {
		if !strings.Contains(p.body, s) && !strings.Contains(words, s) {
			t.Fatalf("%s does not show %q\n%s", p.url, s, words)
		}
	}
	return p
}

// text returns the visible words of a page, for failure messages.
func text(doc string) string {
	doc = regexp.MustCompile(`(?s)<(script|style|svg)\b.*?</(script|style|svg)>`).ReplaceAllString(doc, " ")
	doc = regexp.MustCompile(`(?s)<[^>]*>`).ReplaceAllString(doc, " ")
	doc = html.UnescapeString(doc)
	return strings.Join(strings.Fields(doc), " ")
}

// form is one HTML form of a page, with the values a browser sends
// when the person changes nothing.
type form struct {
	action string
	method string
	values url.Values
	// files names the file inputs.
	files []string
}

var (
	formRe     = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	inputRe    = regexp.MustCompile(`(?is)<input\b([^>]*)>`)
	textareaRe = regexp.MustCompile(`(?is)<textarea\b([^>]*)>(.*?)</textarea>`)
	selectRe   = regexp.MustCompile(`(?is)<select\b([^>]*)>(.*?)</select>`)
	optionRe   = regexp.MustCompile(`(?is)<option\b([^>]*)>`)
	attrRe     = regexp.MustCompile(`(?is)([a-z_:-]+)(?:\s*=\s*"([^"]*)")?`)
)

// attrs reads the attributes of a tag.
func attrs(raw string) map[string]string {
	out := map[string]string{}
	for _, m := range attrRe.FindAllStringSubmatch(raw, -1) {
		out[strings.ToLower(m[1])] = html.UnescapeString(m[2])
	}
	return out
}

// forms returns every form of a page, relative to the page address.
func (p page) forms() []form {
	var out []form
	for _, m := range formRe.FindAllStringSubmatch(p.body, -1) {
		a := attrs(m[1])
		f := form{action: a["action"], method: strings.ToLower(a["method"]), values: url.Values{}}
		if f.method == "" {
			f.method = "get"
		}
		if u, err := p.url.Parse(f.action); err == nil {
			f.action = u.String()
		}
		for _, in := range inputRe.FindAllStringSubmatch(m[2], -1) {
			ia := attrs(in[1])
			name := ia["name"]
			if name == "" {
				continue
			}
			switch strings.ToLower(ia["type"]) {
			case "file":
				f.files = append(f.files, name)
				continue
			case "submit", "button", "image", "reset":
				continue
			case "checkbox", "radio":
				if _, on := ia["checked"]; !on {
					continue
				}
				if _, ok := ia["value"]; !ok {
					ia["value"] = "on"
				}
			}
			f.values.Add(name, ia["value"])
		}
		for _, ta := range textareaRe.FindAllStringSubmatch(m[2], -1) {
			if name := attrs(ta[1])["name"]; name != "" {
				f.values.Add(name, html.UnescapeString(strings.TrimPrefix(ta[2], "\n")))
			}
		}
		for _, sel := range selectRe.FindAllStringSubmatch(m[2], -1) {
			name := attrs(sel[1])["name"]
			if name == "" {
				continue
			}
			first, chosen := "", ""
			for i, opt := range optionRe.FindAllStringSubmatch(sel[2], -1) {
				oa := attrs(opt[1])
				if i == 0 {
					first = oa["value"]
				}
				if _, on := oa["selected"]; on && chosen == "" {
					chosen = oa["value"]
				}
			}
			if chosen == "" {
				chosen = first
			}
			f.values.Set(name, chosen)
		}
		out = append(out, f)
	}
	return out
}

// form returns the form whose action ends with the path. A form that
// posts wins over one that gets the same path.
func (p page) form(t *testing.T, action string) form {
	t.Helper()
	var found []form
	for _, f := range p.forms() {
		u, err := url.Parse(f.action)
		if err == nil && strings.HasSuffix(u.Path, action) {
			found = append(found, f)
		}
	}
	for _, f := range found {
		if f.method == "post" {
			return f
		}
	}
	if len(found) > 0 {
		return found[0]
	}
	t.Fatalf("%s has no form that posts to %s\n%s", p.url, action, text(p.body))
	return form{}
}

// submit sends a form with the changes the person makes.
func (b *browser) submit(f form, changes ...string) page {
	b.t.Helper()
	values := url.Values{}
	for k, v := range f.values {
		values[k] = append([]string(nil), v...)
	}
	for i := 0; i+1 < len(changes); i += 2 {
		values.Set(changes[i], changes[i+1])
	}
	if f.method == "get" {
		u, err := url.Parse(f.action)
		if err != nil {
			b.t.Fatal(err)
		}
		u.RawQuery = values.Encode()
		return b.get(u.String())
	}
	return b.post(f.action, values)
}

// link returns the address of the first link whose text holds the words.
func (p page) link(t *testing.T, words string) string {
	t.Helper()
	for _, m := range regexp.MustCompile(`(?is)<a\b([^>]*)>(.*?)</a>`).FindAllStringSubmatch(p.body, -1) {
		if strings.Contains(text(m[2]), words) {
			u, err := p.url.Parse(attrs(m[1])["href"])
			if err != nil {
				t.Fatal(err)
			}
			return u.String()
		}
	}
	t.Fatalf("%s has no link %q\n%s", p.url, words, text(p.body))
	return ""
}

// upload sends a form with one file, as multipart/form-data.
func (b *browser) upload(f form, name, content string, changes ...string) page {
	b.t.Helper()
	values := url.Values{}
	for k, v := range f.values {
		values[k] = append([]string(nil), v...)
	}
	for i := 0; i+1 < len(changes); i += 2 {
		values.Set(changes[i], changes[i+1])
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, vs := range values {
		for _, v := range vs {
			if err := mw.WriteField(k, v); err != nil {
				b.t.Fatal(err)
			}
		}
	}
	if len(f.files) == 0 {
		b.t.Fatalf("the form of %s has no file input", f.action)
	}
	part, err := mw.CreateFormFile(f.files[0], name)
	if err != nil {
		b.t.Fatal(err)
	}
	if _, werr := io.WriteString(part, content); werr != nil {
		b.t.Fatal(werr)
	}
	if cerr := mw.Close(); cerr != nil {
		b.t.Fatal(cerr)
	}
	req, err := http.NewRequestWithContext(b.ctx, http.MethodPost, f.action, &buf)
	if err != nil {
		b.t.Fatal(err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return b.do(req)
}

// option returns the value of the option of a select whose text holds
// the words.
func (p page) option(t *testing.T, name, words string) string {
	t.Helper()
	for _, sel := range selectRe.FindAllStringSubmatch(p.body, -1) {
		if attrs(sel[1])["name"] != name {
			continue
		}
		for _, m := range regexp.MustCompile(`(?is)<option\b([^>]*)>(.*?)</option>`).FindAllStringSubmatch(sel[2], -1) {
			if strings.Contains(text(m[2]), words) {
				return attrs(m[1])["value"]
			}
		}
	}
	t.Fatalf("%s has no option %q in %s\n%s", p.url, words, name, text(p.body))
	return ""
}
