// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"bytes"
	"encoding/base64"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/centre-for-dpi/vc-adapters/ui/brand"
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
		"h1{font-family:var(--font-heading)", "code,pre,kbd,.num{font-family:var(--font-mono)}",
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
		"/static/dcapi.js":                           "text/javascript; charset=utf-8",
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
	if _, err := build(fsys, Config{Light: light, Dark: dark, Fonts: pack, Brand: brand.Default()}); err == nil || !strings.Contains(err.Error(), "base.css") {
		t.Errorf("missing base.css should fail, got %v", err)
	}
	fsys["static/base.css"] = &fstest.MapFile{Data: []byte("body{}")}
	if _, err := build(fsys, Config{Light: light, Dark: dark, Fonts: pack, Brand: brand.Default()}); err == nil || !strings.Contains(err.Error(), "htmx") {
		t.Errorf("missing htmx should fail, got %v", err)
	}
}

var (
	varUse  = regexp.MustCompile(`var\(--([a-z0-9-]+)`)
	varDecl = regexp.MustCompile(`--([a-z0-9-]+):`)
	hexLit  = regexp.MustCompile(`#[0-9A-Fa-f]{3,8}\b`)
)

// baseCSS returns the embedded base stylesheet.
func baseCSS(t *testing.T) string {
	t.Helper()
	b, err := fs.ReadFile(Static, "static/base.css")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestBaseCSSUsesOnlyDeclaredTokens proves base.css reads only the custom
// properties the generated part of vca.css declares: theme tokens and font
// variables, and brand variables. base.css declares none of its own.
func TestBaseCSSUsesOnlyDeclaredTokens(t *testing.T) {
	css, err := StylesheetCSS(theme.DefaultLight(), theme.DefaultDark(), fonts.Default())
	if err != nil {
		t.Fatal(err)
	}
	base := baseCSS(t)
	prefix := strings.TrimSuffix(css, base)
	if prefix == css {
		t.Fatal("vca.css does not end with base.css")
	}
	allowed := map[string]bool{}
	for _, name := range theme.Required() {
		allowed[name] = true
	}
	for _, s := range fonts.Slots(fonts.Default()) {
		allowed[s.Var] = true
	}
	for _, m := range varDecl.FindAllStringSubmatch(brand.CSS(brand.Default()), -1) {
		allowed[m[1]] = true
	}
	declared := map[string]bool{}
	for _, m := range varDecl.FindAllStringSubmatch(prefix, -1) {
		declared[m[1]] = true
	}
	used := varUse.FindAllStringSubmatch(base, -1)
	if len(used) == 0 {
		t.Fatal("base.css uses no custom property")
	}
	for _, m := range used {
		if !allowed[m[1]] {
			t.Errorf("base.css uses --%s, which is not a theme token, a font variable, or a brand variable", m[1])
		}
		if !declared[m[1]] {
			t.Errorf("base.css uses --%s, which vca.css never declares", m[1])
		}
	}
	for _, m := range varDecl.FindAllStringSubmatch(base, -1) {
		t.Errorf("base.css declares --%s; only the generated part declares properties", m[1])
	}
	for name := range allowed {
		if !declared[name] {
			t.Errorf("vca.css does not declare --%s", name)
		}
	}
}

// TestStylesheetCarriesAdamndegwaStructure checks the port of the
// adamndegwa site structure: the header bar, the inverting tiles and link
// cards, the page header, the tracked labels, and the footer monogram.
func TestStylesheetCarriesAdamndegwaStructure(t *testing.T) {
	base := baseCSS(t)
	for _, want := range []string{
		".site-header::after", ".wordmark em{font-style:normal;color:var(--primary)}",
		"letter-spacing:.14em", "letter-spacing:.18em", ".nav a::after",
		".tile:hover", ".tile:focus-visible", ".card-link:hover", ".card-link:focus-visible",
		"background:var(--invert-bg)", "color:var(--invert-fg)", "var(--invert-muted)", "var(--invert-accent)",
		".pg-header", ".pg-header-label", ".hero", ".site-footer", ".ft-monogram",
		"@media (max-width:56.25rem)", "font-variant-numeric:tabular-nums", ".num",
		"color:var(--secondary)",
	} {
		if !strings.Contains(base, want) {
			t.Errorf("base.css missing %q", want)
		}
	}
	// Only the QR code keeps a literal colour: a scanner needs a white quiet zone.
	for _, lit := range hexLit.FindAllString(base, -1) {
		if lit != "#FFFFFF" {
			t.Errorf("base.css holds the colour literal %s; use a token", lit)
		}
	}
	// Dark mode needs no extra selectors: the invert tokens differ per mode.
	if strings.Contains(base, "data-theme") {
		t.Error("base.css must not branch on data-theme")
	}
}

// TestStylesheetCarriesShell checks the portal shell: the role chip and the
// side nav draw the role accent, the shell is a grid on a wide screen, and
// under 56.25rem the side nav is a disclosure with a visible summary.
func TestStylesheetCarriesShell(t *testing.T) {
	base := baseCSS(t)
	for _, want := range []string{
		".role-chip{", "border:1px solid var(--role-accent)", ".stack-nav a[aria-current=\"true\"]", ".stack-starting",
		".user-menu form{", ".shell{flex:1;display:grid;grid-template-columns:15rem minmax(0,1fr)", ".side-nav{",
		".side-nav-toggle{display:none}", ".side-links a[aria-current=\"page\"]", ".side-label{",
	} {
		if !strings.Contains(base, want) {
			t.Errorf("base.css missing %q", want)
		}
	}
	narrow := base[strings.Index(base, "@media (max-width:56.25rem)"):]
	for _, want := range []string{".shell{display:block}", "display:list-item", ".side-nav[open] .side-nav-toggle"} {
		if !strings.Contains(narrow, want) {
			t.Errorf("narrow rules missing %q", want)
		}
	}
}

// TestStylesheetCarriesContentComponents checks the classes of the content
// components, and that a tile inverts to the invert tokens on hover.
func TestStylesheetCarriesContentComponents(t *testing.T) {
	base := baseCSS(t)
	if !strings.Contains(base, ".tile:hover,.tile:focus-visible,.card-link:hover,.card-link:focus-visible{background:var(--invert-bg);color:var(--invert-fg)}") {
		t.Error("a tile must invert to --invert-bg and --invert-fg on hover and focus")
	}
	for _, want := range []string{
		".hero-actions{", ".tiles>li{", ".tile-meta{", ".steps{", ".step-num{", ".step-state{", ".step-locked",
		".checklist{", ".check-mark{", ".check-done .check-mark", ".stats{", ".stat{", ".stat-value{",
		".stepper{", ".stepper-num{", ".stepper-current .stepper-num", ".choice{", ".choice-card{", ".choice-card:has(:checked)",
		".choice-card:has(:focus-visible)", ".fieldset{", ".fieldset legend{", ".form-actions{", ".media-row{", ".code{", ".code pre{", ".empty{", ".empty-title{",
		// The landing components: page block, diagram figure, stack cards,
		// the call to action band, and the hero note.
		".tiles-3{", ".stack-roles-group{", ".block{", ".block-head{", ".block-lead{", ".block-meta{",
		".figure{", ".fig-node{", ".fig-edge{", ".fig-label{", ".fig-text{",
		".stacks{", ".stack{", ".stack-head{", ".stack-version{", ".stack-label{", ".stack-components{", ".stack-component-name{",
		".stack-component-version{", ".stack-links{", ".stack-roles{", ".stack-role{",
		".cta{", ".cta-text{", ".cta-actions{", ".note{",
	} {
		if !strings.Contains(base, want) {
			t.Errorf("base.css missing %q", want)
		}
	}
	// The call to action band inverts like a hovered tile, and the
	// diagram draws with the theme tokens only.
	for _, want := range []string{
		".cta{", "background:var(--invert-bg)", ".fig-node{fill:var(--paper);stroke:var(--primary)", ".fig-text{fill:var(--ink)",
	} {
		if !strings.Contains(base, want) {
			t.Errorf("base.css missing %q", want)
		}
	}
}

// cssRules returns every "selector{declarations}" block of the base
// stylesheet whose selector list contains sel, with the declarations.
func cssRules(base, sel string) []string {
	var out []string
	for _, block := range strings.Split(base, "}") {
		i := strings.Index(block, "{")
		if i < 0 {
			continue
		}
		selectors := strings.TrimSpace(block[strings.LastIndex(block[:i], "\n")+1 : i])
		for _, s := range strings.Split(selectors, ",") {
			if strings.TrimSpace(s) == sel {
				out = append(out, block[i+1:])
			}
		}
	}
	return out
}

// TestHeroTitleNeverBreaksInsideAWord proves the hero title cannot break
// inside a word: its size follows the width of its column through container
// query units, so a long word shrinks instead of wrapping mid word, and the
// rules never allow break-all or anywhere.
func TestHeroTitleNeverBreaksInsideAWord(t *testing.T) {
	base := baseCSS(t)
	rules := cssRules(base, ".hero h1")
	if len(rules) == 0 {
		t.Fatal("base.css has no .hero h1 rule")
	}
	joined := strings.Join(rules, "\n")
	for _, bad := range []string{"break-all", "anywhere", "break-word"} {
		if strings.Contains(joined, bad) {
			t.Errorf(".hero h1 rules allow breaking inside a word: %q", bad)
		}
	}
	for _, want := range []string{"overflow-wrap:normal", "cqi", "text-wrap:balance"} {
		if !strings.Contains(joined, want) {
			t.Errorf(".hero h1 rules missing %q", want)
		}
	}
	left := strings.Join(cssRules(base, ".hero-left"), "\n")
	if !strings.Contains(left, "container-type:inline-size") {
		t.Error(".hero-left must be a size container, so cqi units follow the column width")
	}
	if strings.Contains(base, ".shell .hero h1") {
		t.Error("the shell needs no hero override once the size follows the column")
	}
}

// TestCredentialTitleNeverBreaksInsideAWord is P4-05. The title of a
// credential card wraps between words. It breaks a word only when that
// word alone is wider than the card, and it never breaks eagerly.
func TestCredentialTitleNeverBreaksInsideAWord(t *testing.T) {
	joined := strings.Join(cssRules(baseCSS(t), ".credential-title"), "\n")
	if joined == "" {
		t.Fatal("base.css has no .credential-title rule")
	}
	for _, bad := range []string{"break-all", "anywhere"} {
		if strings.Contains(joined, bad) {
			t.Errorf(".credential-title rules allow breaking inside a word: %q", bad)
		}
	}
	for _, want := range []string{"overflow-wrap:break-word", "text-wrap:balance", "hyphens:manual"} {
		if !strings.Contains(joined, want) {
			t.Errorf(".credential-title rules missing %q", want)
		}
	}
}

// TestBaseCSSUsesBrandVariables checks that every brand variable reaches
// the page, so a radius, a spacing step, or a role accent in the theme
// file changes what users see.
func TestBaseCSSUsesBrandVariables(t *testing.T) {
	base := baseCSS(t)
	used := map[string]bool{}
	for _, m := range varUse.FindAllStringSubmatch(base, -1) {
		used[m[1]] = true
	}
	decls := varDecl.FindAllStringSubmatch(brand.CSS(brand.Default()), -1)
	if len(decls) != 11 {
		t.Fatalf("brand declares %d variables, want 11", len(decls))
	}
	for _, m := range decls {
		if !used[m[1]] {
			t.Errorf("base.css never uses --%s", m[1])
		}
	}
	for _, want := range []string{".wordmark-text", ".wordmark-context", ".ft-note", ".pg-header-label{", "color:var(--role-accent)"} {
		if !strings.Contains(base, want) {
			t.Errorf("base.css missing %q", want)
		}
	}
}

// logoConfig returns the default config with an SVG logo.
func logoConfig() Config {
	cfg := DefaultConfig()
	cfg.Brand.Logo = brand.Logo{
		DataURI: "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`)),
		Alt:     "Crest",
	}
	return cfg
}

func TestServeLogo(t *testing.T) {
	h, err := AssetsFor(logoConfig())
	if err != nil {
		t.Fatal(err)
	}
	rec := get(h, http.MethodGet, "/static/logo.svg", "")
	if rec.Code != 200 || rec.Body.String() != `<svg xmlns="http://www.w3.org/2000/svg"/>` {
		t.Fatalf("logo: status %d, body %q", rec.Code, rec.Body.String())
	}
	for k, want := range map[string]string{
		"Content-Type":            "image/svg+xml",
		"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
		"X-Content-Type-Options":  "nosniff",
	} {
		if got := rec.Header().Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if rec := get(h, http.MethodGet, "/static/vca.css", ""); rec.Header().Get("Content-Security-Policy") != "" {
		t.Error("only the logo carries the sandbox policy")
	}
	if rec := get(newAssets(t), http.MethodGet, "/static/logo.svg", ""); rec.Code != 404 {
		t.Errorf("no logo should give 404, got %d", rec.Code)
	}
}

func TestStylesheetForOrdersFontsThemesBrandBase(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Brand.RoleAccents["issuer"] = brand.Accent{Light: "#1F4E79", Dark: "#9CC3E6"}
	css, err := StylesheetFor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	marks := []string{"@font-face", "/* theme: default-light */", "/* theme: default-dark */", "/* brand */", `[data-role="issuer"]`, "/* vca UI kit base stylesheet"}
	last := -1
	for _, m := range marks {
		i := strings.Index(css, m)
		if i <= last {
			t.Fatalf("%q is at %d, after %d; want the order %v", m, i, last, marks)
		}
		last = i
	}
	plain, err := StylesheetCSS(theme.DefaultLight(), theme.DefaultDark(), fonts.Default())
	if err != nil {
		t.Fatal(err)
	}
	if plain == css || !strings.Contains(plain, brand.CSS(brand.Default())) {
		t.Error("StylesheetCSS must use the default brand")
	}
	// A new brand gives a new ETag.
	a, b := newAssets(t), anyvalHandler(t, cfg)
	if get(a, http.MethodGet, "/static/vca.css", "").Header().Get("ETag") == get(b, http.MethodGet, "/static/vca.css", "").Header().Get("ETag") {
		t.Error("the ETag must follow the stylesheet content")
	}
}

func anyvalHandler(t *testing.T, cfg Config) http.Handler {
	t.Helper()
	h, err := AssetsFor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestAssetsForRejectsABadBrand(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Brand.Radii.Small = "3px"
	if _, err := AssetsFor(cfg); err == nil || !strings.Contains(err.Error(), "radii.small") {
		t.Errorf("bad brand should fail, got %v", err)
	}
	if _, err := StylesheetFor(cfg); err == nil {
		t.Error("StylesheetFor should report the bad brand")
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

// TestDcApiScriptServed checks the vendored script of the Digital
// Credentials API channel (ADR-043 decision 3): the kit serves it, it
// tests for the API before it shows a button, it hands the offer to
// navigator.credentials.create, and it writes into the toast region.
func TestDcApiScriptServed(t *testing.T) {
	h := newAssets(t)
	rec := get(h, http.MethodGet, "/static/dcapi.js", "")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "text/javascript; charset=utf-8" || rec.Header().Get("ETag") == "" {
		t.Fatalf("status %d type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(baseCSS(t), "[hidden]{display:none!important}") {
		t.Error("a .btn display rule would show a hidden dcapi button")
	}
	body := rec.Body.String()
	for _, want := range []string{
		"DigitalCredential", "userAgentAllowsProtocol", "'openid4vci-v1'", "navigator.credentials.create",
		"digital: { requests: [{ protocol: PROTOCOL, data: offer }] }", "button[data-dcapi-offer]",
		"getElementById('toasts')", "data-dcapi-ok", "data-dcapi-cancel", "data-dcapi-fail", "htmx:afterSettle",
		// The verify mode: navigator.credentials.get with the request of
		// the page, and a form post of the answer (P6-W2).
		"button[data-dcapi-request]", "navigator.credentials.get", "digital: { requests: [request] }", "form.submit()",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dcapi.js lacks %q", want)
		}
	}
	// A file system without the script fails at startup.
	light, dark, pack := theme.DefaultLight(), theme.DefaultDark(), fonts.Default()
	fsys := fstest.MapFS{"static/base.css": &fstest.MapFile{Data: []byte("body{}")}, "static/htmx.min.js": &fstest.MapFile{Data: []byte("htmx")}}
	for _, f := range fonts.Files(pack) {
		fsys["static/fonts/"+f] = &fstest.MapFile{Data: []byte("wOF2")}
	}
	if _, err := build(fsys, Config{Light: light, Dark: dark, Fonts: pack, Brand: brand.Default()}); err == nil || !strings.Contains(err.Error(), "dcapi.js") {
		t.Errorf("missing dcapi.js should fail, got %v", err)
	}
}

// TestCodeBlockKeepsLongTokensInsideItsBox proves a long value with no
// spaces, such as an offer link, stays inside the code box on every width.
// The block wraps anywhere, keeps line breaks, never grows past its column,
// and still scrolls when a browser cannot wrap.
func TestCodeBlockKeepsLongTokensInsideItsBox(t *testing.T) {
	base := baseCSS(t)
	pre := strings.Join(cssRules(base, ".code pre"), "\n")
	if pre == "" {
		t.Fatal("base.css has no .code pre rule")
	}
	for _, want := range []string{"white-space:pre-wrap", "overflow-wrap:anywhere", "word-break:break-all", "overflow-x:auto", "max-width:100%"} {
		if !strings.Contains(pre, want) {
			t.Errorf(".code pre rules missing %q", want)
		}
	}
	// A fixed width of zero kept the box in its column but hid the
	// end of the value behind the padding. The box now takes its
	// column width.
	if strings.Contains(pre, "width:0") {
		t.Error(".code pre must not set width:0")
	}
}

// TestFieldsetOfARowTakesTheColumn proves a fieldset whose body is a
// field row is not held to the width of a single column of fields, so
// the fields of the row sit side by side.
func TestFieldsetOfARowTakesTheColumn(t *testing.T) {
	rules := strings.Join(cssRules(baseCSS(t), ".fieldset:has(>.field-row)"), "\n")
	if !strings.Contains(rules, "max-width:none") {
		t.Error("a fieldset of a field row must drop the max width of a fieldset")
	}
}
