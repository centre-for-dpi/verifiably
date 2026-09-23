// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"bytes"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/centre-for-dpi/vc-adapters/ui/fonts"
	"github.com/centre-for-dpi/vc-adapters/ui/theme"
)

func newAssets(t *testing.T) http.Handler {
	t.Helper()
	h, err := Assets(theme.DefaultLight(), theme.DefaultDark(), fonts.Default())
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func get(h http.Handler, method, path string, etag string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

var fontPx = regexp.MustCompile(`font-size:\s*[0-9.]+px`)

func TestStylesheetCarriesThemeFontsAndA11y(t *testing.T) {
	css, err := StylesheetCSS(theme.DefaultLight(), theme.DefaultDark(), fonts.Default())
	if err != nil {
		t.Fatal(err)
	}
	for name, hex := range theme.DefaultLight().Tokens {
		if !strings.Contains(css, "--"+name+":"+hex+";") {
			t.Errorf("stylesheet missing light token %s", name)
		}
	}
	dark := css[strings.Index(css, `[data-theme="dark"]{`):]
	for name, hex := range theme.DefaultDark().Tokens {
		if !strings.Contains(dark, "--"+name+":"+hex+";") {
			t.Errorf("stylesheet missing dark token %s", name)
		}
	}
	for _, want := range []string{
		"@font-face", "font-display:swap", ".skip-link", ":focus-visible", "prefers-reduced-motion",
		"min-width:24px;min-height:24px", ".visually-hidden", "var(--font-body)", "prefers-color-scheme: dark",
		".card", ".field", ".badge", ".toast", "dialog", ".qr", ".json", ".btn", "th,td",
		"outline-offset:2px", ".table-wrap{overflow-x:auto", "flex-wrap:wrap",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("stylesheet missing %q", want)
		}
	}
	// Headings use Cinzel and code uses the generic monospace stack. The
	// removed display and meta roles leave no trace.
	for _, want := range []string{
		"h1{font-family:var(--font-heading)", "code,pre,kbd{font-family:var(--font-mono)}",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("stylesheet missing %q", want)
		}
	}
	for _, gone := range []string{"var(--font-display)", "--font-meta"} {
		if strings.Contains(css, gone) {
			t.Errorf("stylesheet still uses %q", gone)
		}
	}
	if strings.Contains(css, "outline:none") || strings.Contains(css, "outline: none") {
		t.Error("stylesheet must not remove focus outlines")
	}
	// Font sizes scale with the user setting (WCAG 2.2 SC 1.4.4), so no px.
	if fontPx.MatchString(css) {
		t.Error("stylesheet sets a font-size in px")
	}
	// The base stylesheet must only use tokens, never literal theme colours.
	base := css[strings.Index(css, "/* vca UI kit base stylesheet"):]
	for _, hex := range theme.DefaultLight().Tokens {
		if strings.Contains(base, hex) {
			t.Errorf("base.css hard-codes colour %s", hex)
		}
	}
}

func TestServeAssets(t *testing.T) {
	h := newAssets(t)
	cases := map[string]string{
		"/static/vca.css":                            "text/css; charset=utf-8",
		"/static/htmx.min.js":                        "text/javascript; charset=utf-8",
		"/static/fonts/" + fonts.Default().Body.File: "font/woff2",
	}
	for path, ct := range cases {
		rec := get(h, http.MethodGet, path, "")
		if rec.Code != 200 || rec.Header().Get("Content-Type") != ct {
			t.Errorf("%s: status %d, type %q", path, rec.Code, rec.Header().Get("Content-Type"))
		}
		if rec.Header().Get("Cache-Control") != cacheControl || rec.Header().Get("ETag") == "" {
			t.Errorf("%s: missing cache headers", path)
		}
		if rec.Body.Len() == 0 {
			t.Errorf("%s: empty body", path)
		}
		etag := rec.Header().Get("ETag")
		if rec := get(h, http.MethodGet, path, etag); rec.Code != http.StatusNotModified || rec.Body.Len() != 0 {
			t.Errorf("%s: If-None-Match should give 304, got %d", path, rec.Code)
		}
		if rec := get(h, http.MethodHead, path, ""); rec.Code != 200 || rec.Body.Len() != 0 || rec.Header().Get("Content-Length") == "" {
			t.Errorf("%s: HEAD should give headers only", path)
		}
	}
	if rec := get(h, http.MethodGet, "/static/htmx.min.js", ""); !strings.Contains(rec.Body.String(), HTMXVersion) {
		t.Errorf("vendored htmx is not version %s", HTMXVersion)
	}
	if rec := get(h, http.MethodGet, "/static/base.css", ""); rec.Code != 404 {
		t.Errorf("base.css must not be served on its own, got %d", rec.Code)
	}
	if rec := get(h, http.MethodGet, "/static/../go.mod", ""); rec.Code != 404 {
		t.Errorf("path traversal should give 404, got %d", rec.Code)
	}
	if rec := get(h, http.MethodPost, "/static/vca.css", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST should give 405, got %d", rec.Code)
	}
}

func TestAssetsRejectsBadInput(t *testing.T) {
	light, dark, pack := theme.DefaultLight(), theme.DefaultDark(), fonts.Default()
	if _, err := Assets(dark, light, pack); err == nil {
		t.Error("swapped themes should fail")
	}
	bad := light
	bad.Tokens = map[string]string{}
	if _, err := Assets(bad, dark, pack); err == nil {
		t.Error("invalid theme should fail")
	}
	badPack := pack
	badPack.Name = ""
	if _, err := Assets(light, dark, badPack); err == nil {
		t.Error("invalid pack should fail")
	}
	missing := pack
	missing.Body.File = "nope.woff2"
	if _, err := Assets(light, dark, missing); err == nil {
		t.Error("missing font file should fail")
	}
	if _, err := StylesheetCSS(light, dark, missing); err == nil {
		t.Error("StylesheetCSS should report the missing font file")
	}

	// A file system without base.css or htmx fails at startup, not at request time.
	fsys := fstest.MapFS{}
	for _, f := range fonts.Files(pack) {
		fsys["static/fonts/"+f] = &fstest.MapFile{Data: []byte("wOF2")}
	}
	if _, err := build(fsys, light, dark, pack); err == nil || !strings.Contains(err.Error(), "base.css") {
		t.Errorf("missing base.css should fail, got %v", err)
	}
	fsys["static/base.css"] = &fstest.MapFile{Data: []byte("body{}")}
	if _, err := build(fsys, light, dark, pack); err == nil || !strings.Contains(err.Error(), "htmx") {
		t.Errorf("missing htmx should fail, got %v", err)
	}
}

// removedFamilies are the font families the owner removed from the pack.
// The strings are split so this file does not match itself.
var removedFamilies = []string{
	"big" + " shoulders", "big" + "-shoulders", "google sans" + " code", "google-sans" + "-code",
}

func hasRemovedFamily(b []byte) string {
	low := bytes.ToLower(b)
	for _, f := range removedFamilies {
		if bytes.Contains(low, []byte(f)) {
			return f
		}
	}
	return ""
}

// TestNoRemovedFamilyAnywhere checks every file name and file under ui/,
// and every line of docs/ui.md, for a removed font family.
func TestNoRemovedFamilyAnywhere(t *testing.T) {
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if f := hasRemovedFamily([]byte(path)); f != "" {
			t.Errorf("%s: the name holds %q", path, f)
		}
		if d.IsDir() {
			return nil
		}
		b, readErr := os.ReadFile(filepath.Clean(path))
		if readErr != nil {
			return readErr
		}
		if f := hasRemovedFamily(b); f != "" {
			t.Errorf("%s: the file holds %q", path, f)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk ui: %v", err)
	}
	doc, err := os.ReadFile(filepath.Join("..", "docs", "ui.md"))
	if err != nil {
		t.Fatalf("read docs/ui.md: %v", err)
	}
	for i, line := range bytes.Split(doc, []byte("\n")) {
		if f := hasRemovedFamily(line); f != "" {
			t.Errorf("docs/ui.md:%d holds %q", i+1, f)
		}
	}
}
