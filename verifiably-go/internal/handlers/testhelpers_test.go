package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/verifiably/verifiably-go/vctypes"
)

// Shared test helpers for the internal/handlers package. Keep every helper
// that more than one *_test.go file needs HERE (plan §4.4) — per-file test
// files may add private fixtures but must not duplicate these.

// testFuncMap mirrors cmd/server/main.go funcMap with `t` as identity. It is
// the production-compatible FuncMap subset every page template needs.
func testFuncMap() template.FuncMap {
	return template.FuncMap{
		"titleIf": func(cond bool, s string) string {
			if cond {
				return s
			}
			return ""
		},
		"daysUntil": func(t time.Time) int {
			if t.IsZero() {
				return 99999
			}
			return int(time.Until(t).Hours() / 24)
		},
		"hasPrefix":         strings.HasPrefix,
		"replaceUnderscore": func(s string) string { return strings.ReplaceAll(s, "_", " ") },
		"trimPrefix":        strings.TrimPrefix,
		"list":              func(args ...any) []any { return args },
		"jsonRows": func(v any) template.JS {
			b, err := json.Marshal(v)
			if err != nil {
				return template.JS("[]")
			}
			return template.JS(b)
		},
		"t": func(s string, _ ...any) string { return s },
		"hasCapability": func(dpg vctypes.DPG, kind, key string) bool {
			for _, c := range dpg.Capabilities {
				if c.Kind == kind && c.Key == key {
					return true
				}
			}
			return false
		},
		"dict": func(pairs ...any) (map[string]any, error) {
			if len(pairs)%2 != 0 {
				return nil, fmt.Errorf("dict requires even number of args, got %d", len(pairs))
			}
			m := make(map[string]any, len(pairs)/2)
			for i := 0; i < len(pairs); i += 2 {
				key, ok := pairs[i].(string)
				if !ok {
					return nil, fmt.Errorf("dict key at position %d is not a string", i)
				}
				m[key] = pairs[i+1]
			}
			return m, nil
		},
		"deref": func(p *vctypes.OID4VPTemplate) vctypes.OID4VPTemplate {
			if p == nil {
				return vctypes.OID4VPTemplate{}
			}
			return *p
		},
		"indexSchemas": func(schemas []vctypes.Schema, id string) vctypes.Schema {
			for _, s := range schemas {
				if s.HasVariantID(id) {
					return s.ApplyVariant(id)
				}
			}
			return vctypes.Schema{}
		},
		"fieldSet": func(xs []string) map[string]bool {
			out := make(map[string]bool, len(xs))
			for _, x := range xs {
				out[x] = true
			}
			return out
		},
		"schemaStdList": func(schemas []vctypes.Schema) []string {
			seen := map[string]struct{}{}
			for _, s := range schemas {
				if s.Std != "" {
					seen[s.Std] = struct{}{}
				}
			}
			out := make([]string, 0, len(seen))
			for k := range seen {
				out = append(out, k)
			}
			sort.Strings(out)
			return out
		},
		"lowerStr": strings.ToLower,
		"uniqueTitles": func(creds []vctypes.Credential) []string {
			seen := map[string]bool{}
			out := []string{}
			for _, c := range creds {
				if c.Title != "" && !seen[c.Title] {
					seen[c.Title] = true
					out = append(out, c.Title)
				}
			}
			sort.Strings(out)
			return out
		},
		"uniqueFormats": func(creds []vctypes.Credential) []string {
			seen := map[string]bool{}
			out := []string{}
			for _, c := range creds {
				if c.Format != "" && !seen[c.Format] {
					seen[c.Format] = true
					out = append(out, c.Format)
				}
			}
			sort.Strings(out)
			return out
		},
	}
}

// loadPageTemplates parses templates/layouts/base.html plus every named
// templates/pages/<page>.html with the production-compatible FuncMap, so
// both the HTMX (content_<page>) and full-page ("layout") render paths work.
func loadPageTemplates(t *testing.T, pages ...string) *template.Template {
	t.Helper()
	tmpl := newTestTemplate()
	files := []string{"../../templates/layouts/base.html"}
	for _, p := range pages {
		files = append(files, "../../templates/pages/"+p+".html")
	}
	if _, err := tmpl.ParseFiles(files...); err != nil {
		t.Fatalf("parse templates %v: %v", pages, err)
	}
	return tmpl
}

// loadPublicTemplates parses templates/public/*.html (layout_public + the
// public verify page and its fragments) with the same FuncMap.
func loadPublicTemplates(t *testing.T) *template.Template {
	t.Helper()
	tmpl := newTestTemplate()
	if _, err := tmpl.ParseGlob("../../templates/public/*.html"); err != nil {
		t.Fatalf("parse public templates: %v", err)
	}
	return tmpl
}

// newTestTemplate returns an empty template set carrying testFuncMap plus the
// production `render` helper bound to the set itself.
func newTestTemplate() *template.Template {
	var tmpl *template.Template
	fns := testFuncMap()
	fns["render"] = func(name string, data any) (template.HTML, error) {
		var buf bytes.Buffer
		if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
			return "", err
		}
		return template.HTML(buf.String()), nil
	}
	tmpl = template.New("").Funcs(fns)
	return tmpl
}

// seedSession creates a session through h.Sessions.MustGet, applies mutate,
// and returns the cookies to attach to subsequent requests.
func seedSession(t *testing.T, h *H, mutate func(*Session)) []*http.Cookie {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sess := h.Sessions.MustGet(rr, req)
	if mutate != nil {
		mutate(sess)
	}
	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("seedSession: MustGet set no cookie")
	}
	return cookies
}

// dpgWithBulk returns a DPG declaring the given bulk_source capability keys.
func dpgWithBulk(keys ...string) vctypes.DPG {
	d := vctypes.DPG{Vendor: "Example DPG"}
	for _, k := range keys {
		d.Capabilities = append(d.Capabilities, vctypes.Capability{Kind: "bulk_source", Key: k, Title: k, Body: k})
	}
	return d
}

// formPost builds an HTMX form POST carrying the given session cookies.
func formPost(path string, v url.Values, cookies ...*http.Cookie) *http.Request {
	req := postFormReq(http.MethodPost, path, v)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

// multipartCSV builds a multipart POST with one file part and returns the
// request plus its Content-Type (boundary included).
func multipartCSV(t *testing.T, fieldName, filename, body string) (*http.Request, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile(fieldName, filename)
	if err != nil {
		t.Fatalf("multipart part: %v", err)
	}
	if _, err := io.WriteString(fw, body); err != nil {
		t.Fatalf("multipart body: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("multipart close: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/issuer/issue/bulk/preview", &buf)
	ct := mw.FormDataContentType()
	req.Header.Set("Content-Type", ct)
	req.Header.Set("HX-Request", "true")
	return req, ct
}
