// SPDX-License-Identifier: Apache-2.0

package uikit

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/internal/themefile"
	"github.com/centre-for-dpi/vc-adapters/ui"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
	"github.com/centre-for-dpi/vc-adapters/ui/brand"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// lookup returns a getenv over one map.
func lookup(values map[string]string) func(string) string {
	return func(k string) string { return values[k] }
}

// writeTheme writes one theme file under a temporary directory and
// returns its path. edit rewrites the embedded default.
func writeTheme(t *testing.T, edit func(string) string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "theme.yaml")
	if err := os.WriteFile(path, []byte(edit(string(themefile.Default()))), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// get serves one GET through the assets handler.
func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestLoadDefaultWhenUnset(t *testing.T) {
	assets, kit, cfg, err := Load(lookup(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if assets == nil || kit == nil {
		t.Fatal("nil handler or kit")
	}
	if cfg.Brand.Wordmark != ui.DefaultConfig().Brand.Wordmark || cfg.Light.Tokens["primary"] != "#21663F" {
		t.Errorf("config is not the default look: %+v", cfg.Brand)
	}
	if kit.Mark().Text != "VCA" || kit.Mark().LogoSrc != "" {
		t.Errorf("mark = %+v", kit.Mark())
	}
	rec := get(t, assets, "/static/vca.css")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "--primary:#21663F;") {
		t.Errorf("vca.css: %d %q", rec.Code, rec.Body.String()[:80])
	}
	if rec := get(t, assets, "/static/logo.svg"); rec.Code != http.StatusNotFound {
		t.Errorf("logo with no brand logo: %d", rec.Code)
	}
}

func TestLoadFileOverrides(t *testing.T) {
	svg := "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMCAxMCI+PGNpcmNsZSBjeD0iNSIgY3k9IjUiIHI9IjQiLz48L3N2Zz4="
	path := writeTheme(t, func(s string) string {
		s = strings.Replace(s, `text: "VCA"`, `text: "Ministry"`, 1)
		s = strings.Replace(s, `emphasis: ""`, `emphasis: "ID"`, 1)
		s = strings.Replace(s, `data_uri: ""`, `data_uri: "data:image/svg+xml;base64,`+svg+`"`, 1)
		s = strings.Replace(s, `alt: ""`, `alt: "The crest"`, 1)
		s = strings.Replace(s, `primary: "#21663F"      # pine: links, primary buttons, emphasis`, `primary: "#1B4D8C"`, 1)
		return strings.Replace(s, `invert-bg: "#21663F"    # tile and card hover surface`, `invert-bg: "#1B4D8C"`, 1)
	})
	assets, kit, cfg, err := Load(lookup(map[string]string{ThemeFileEnv: path}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Brand.Wordmark != "Ministry" || cfg.Brand.Emphasis != "ID" || cfg.Light.Tokens["primary"] != "#1B4D8C" {
		t.Errorf("config = %+v %v", cfg.Brand, cfg.Light.Tokens["primary"])
	}
	if kit.Mark().Text != "Ministry" || kit.Mark().Emphasis != "ID" || kit.Mark().LogoSrc != "/static/logo.svg" || kit.Mark().LogoAlt != "The crest" {
		t.Errorf("mark = %+v", kit.Mark())
	}
	if rec := get(t, assets, "/static/vca.css"); !strings.Contains(rec.Body.String(), "--primary:#1B4D8C;") {
		t.Error("vca.css lacks the new primary")
	}
	rec := get(t, assets, "/static/logo.svg")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "image/svg+xml" || rec.Header().Get("Content-Security-Policy") == "" {
		t.Errorf("logo: %d %v", rec.Code, rec.Header())
	}
	// The kit and the assets agree: a page shows the logo the handler serves.
	var out strings.Builder
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	if err := kit.RenderPage(rr, req, components.Page{Title: "Home", Content: "<p>Hello.</p>"}); err != nil {
		t.Fatal(err)
	}
	out.WriteString(rr.Body.String())
	if !strings.Contains(out.String(), `src="/static/logo.svg"`) || !strings.Contains(out.String(), `alt="The crest"`) {
		t.Error("the page does not show the logo")
	}
	a11ytest.AssertPage(t, out.String())
}

func TestLoadFailsWithClearMessage(t *testing.T) {
	low := writeTheme(t, func(s string) string {
		return strings.Replace(s, `primary: "#21663F"      # pine: links, primary buttons, emphasis`, `primary: "#5B9E73"`, 1)
	})
	for name, path := range map[string]string{
		"low contrast": low,
		"missing":      filepath.Join(t.TempDir(), "none.yaml"),
	} {
		_, _, _, err := Load(lookup(map[string]string{ThemeFileEnv: path}))
		if err == nil {
			t.Errorf("%s: loaded", name)
			continue
		}
		if !strings.HasPrefix(err.Error(), "theme file "+path+": ") {
			t.Errorf("%s: error = %q", name, err)
		}
		if name == "low contrast" && !strings.Contains(err.Error(), `pairing "primary button label"`) {
			t.Errorf("error names no pairing: %v", err)
		}
	}
}

func TestLoadFileIsLoadWithAPath(t *testing.T) {
	_, kit, _, err := LoadFile("")
	if err != nil || kit.Mark().Text != "VCA" {
		t.Fatalf("LoadFile: %v %+v", err, kit)
	}
}

// TestBuildRejectsAKitConfigTheFileNeverMakes covers the guard behind the
// file reader: a config the kit refuses stops the start.
func TestBuildRejectsAKitConfigTheFileNeverMakes(t *testing.T) {
	cfg := ui.DefaultConfig()
	cfg.Brand.Logo = brand.Logo{DataURI: "data:image/gif;base64,R0lG", Alt: "x"}
	_, _, err := build(cfg)
	if err == nil || !strings.Contains(err.Error(), "logo") {
		t.Errorf("error = %v", err)
	}
}
