// SPDX-License-Identifier: Apache-2.0

// Package ui is the vca UI kit: themes, fonts, static assets, and
// html/template components that meet WCAG 2.2 AA.
//
// The kit uses the Go standard library only. Services import the kit,
// mount Assets under /static/, and render pages with the components package.
package ui

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/ui/fonts"
	"github.com/centre-for-dpi/vc-adapters/ui/theme"
)

// Static holds the vendored assets: base.css, htmx.min.js, and fonts/.
//
//go:embed static
var Static embed.FS

// Templates holds the component partials and the layout.
//
//go:embed templates
var Templates embed.FS

// HTMXVersion is the vendored htmx release.
const HTMXVersion = "2.0.10"

// Prefix is the URL path prefix the assets handler serves.
const Prefix = "/static/"

// cacheControl marks every asset immutable for one year.
const cacheControl = "public, max-age=31536000, immutable"

type asset struct {
	body        []byte
	contentType string
	etag        string
}

// Assets validates the themes and the font pack, generates /static/vca.css,
// and returns a handler for every file under /static/.
// Every response carries an ETag and a long Cache-Control.
func Assets(light, dark theme.Theme, pack fonts.Pack) (http.Handler, error) {
	return build(Static, light, dark, pack)
}

// build is Assets over any file system, so tests can inject a broken one.
func build(static fs.FS, light, dark theme.Theme, pack fonts.Pack) (http.Handler, error) {
	if light.Dark || !dark.Dark {
		return nil, fmt.Errorf("ui: light theme %q and dark theme %q have wrong Dark flags", light.Name, dark.Name)
	}
	for _, t := range []theme.Theme{light, dark} {
		if err := theme.Validate(t); err != nil {
			return nil, fmt.Errorf("ui: %w", err)
		}
	}
	if err := fonts.Validate(pack); err != nil {
		return nil, fmt.Errorf("ui: %w", err)
	}
	files := map[string]asset{}
	for _, name := range fonts.Files(pack) {
		b, err := fs.ReadFile(static, "static/fonts/"+name)
		if err != nil {
			return nil, fmt.Errorf("ui: font pack %q: %w", pack.Name, err)
		}
		files["fonts/"+name] = newAsset(b, "font/woff2")
	}
	base, err := fs.ReadFile(static, "static/base.css")
	if err != nil {
		return nil, fmt.Errorf("ui: %w", err)
	}
	css := fonts.CSS(pack) + theme.CSS(light) + theme.CSS(dark) + string(base)
	files["vca.css"] = newAsset([]byte(css), "text/css; charset=utf-8")
	htmx, err := fs.ReadFile(static, "static/htmx.min.js")
	if err != nil {
		return nil, fmt.Errorf("ui: %w", err)
	}
	files["htmx.min.js"] = newAsset(htmx, "text/javascript; charset=utf-8")
	return &handler{files: files}, nil
}

// StylesheetCSS returns the generated stylesheet text without serving it.
// Tests and build tools use it.
func StylesheetCSS(light, dark theme.Theme, pack fonts.Pack) (string, error) {
	h, err := Assets(light, dark, pack)
	if err != nil {
		return "", err
	}
	return string(h.(*handler).files["vca.css"].body), nil
}

func newAsset(body []byte, contentType string) asset {
	sum := sha256.Sum256(body)
	return asset{body: body, contentType: contentType, etag: `"` + hex.EncodeToString(sum[:16]) + `"`}
}

type handler struct {
	files map[string]asset
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(path.Clean(r.URL.Path), Prefix)
	a, ok := h.files[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", a.contentType)
	w.Header().Set("ETag", a.etag)
	w.Header().Set("Cache-Control", cacheControl)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if strings.Contains(r.Header.Get("If-None-Match"), a.etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Length", fmt.Sprint(len(a.body)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(a.body)
}
