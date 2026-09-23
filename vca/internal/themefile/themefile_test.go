// SPDX-License-Identifier: Apache-2.0

package themefile

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/ui"
	"github.com/centre-for-dpi/vc-adapters/ui/brand"
	"github.com/centre-for-dpi/vc-adapters/ui/fonts"
	"github.com/centre-for-dpi/vc-adapters/ui/theme"
)

// shippedFile is the tracked theme file, from this package.
const shippedFile = "../../../deploy/vca/theme.yaml"

// mustLoad loads one testdata file and fails the test on an error.
func mustParse(t *testing.T, name string) *File {
	t.Helper()
	path := filepath.Join("testdata", name)
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	f, err := Parse(path, data)
	if err != nil {
		t.Fatalf("Parse(%s): %v", path, err)
	}
	return f
}

// validationError parses and validates one testdata file and returns the
// error text. The file must fail.
func validationError(t *testing.T, name string) string {
	t.Helper()
	err := mustParse(t, name).Validate()
	if err == nil {
		t.Fatalf("%s validated", name)
	}
	return err.Error()
}

func TestEmbeddedDefaultParsesAndValidates(t *testing.T) {
	f, err := Parse(DefaultPath, Default())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := f.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if f.Version != 1 || f.Name != "adamndegwa" {
		t.Errorf("version %d name %q", f.Version, f.Name)
	}
	if f.Path() != DefaultPath {
		t.Errorf("path = %q", f.Path())
	}
}

func TestShippedFileEqualsEmbeddedDefault(t *testing.T) {
	got, err := os.ReadFile(shippedFile)
	if err != nil {
		t.Fatalf("read %s: %v", shippedFile, err)
	}
	if string(got) != string(Default()) {
		t.Errorf("%s differs from the embedded default.yaml; copy one over the other", shippedFile)
	}
	if !strings.HasPrefix(string(got), "# SPDX-License-Identifier: Apache-2.0\n") {
		t.Error("the theme file has no licence line")
	}
}

func TestDefaultMatchesKitDefaults(t *testing.T) {
	f, err := Parse(DefaultPath, Default())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := f.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	cfg := f.Config()
	want := ui.DefaultConfig()
	if !reflect.DeepEqual(cfg.Light.Tokens, want.Light.Tokens) {
		t.Errorf("light tokens differ:\n got %v\nwant %v", cfg.Light.Tokens, want.Light.Tokens)
	}
	if !reflect.DeepEqual(cfg.Dark.Tokens, want.Dark.Tokens) {
		t.Errorf("dark tokens differ:\n got %v\nwant %v", cfg.Dark.Tokens, want.Dark.Tokens)
	}
	if cfg.Light.Dark || !cfg.Dark.Dark {
		t.Error("the Dark flags are wrong")
	}
	if !reflect.DeepEqual(cfg.Light.Pairings, theme.DefaultPairings()) || !reflect.DeepEqual(cfg.Dark.Pairings, theme.DefaultPairings()) {
		t.Error("the pairings are not the kit pairings")
	}
	if cfg.Fonts.Heading != want.Fonts.Heading || cfg.Fonts.Body != want.Fonts.Body || cfg.Fonts.Mono != want.Fonts.Mono {
		t.Errorf("font pack differs:\n got %+v\nwant %+v", cfg.Fonts, want.Fonts)
	}
	if cfg.Light.Name != "adamndegwa-light" || cfg.Dark.Name != "adamndegwa-dark" || cfg.Fonts.Name != "adamndegwa" {
		t.Errorf("names = %q %q %q", cfg.Light.Name, cfg.Dark.Name, cfg.Fonts.Name)
	}
	if !reflect.DeepEqual(cfg.Brand, brand.Default()) {
		t.Errorf("brand differs:\n got %+v\nwant %+v", cfg.Brand, brand.Default())
	}
	if _, err := ui.AssetsFor(cfg); err != nil {
		t.Errorf("the kit rejects the default config: %v", err)
	}
}

func TestParseRejectsUnknownKey(t *testing.T) {
	path := filepath.Join("testdata", "unknown-key.yaml")
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Parse(path, data)
	if err == nil {
		t.Fatal("an unknown key parsed")
	}
	msg := err.Error()
	want := "theme file " + path + ": line 20: field colours not found in type themefile.File"
	if msg != want {
		t.Errorf("error = %q\nwant  %q", msg, want)
	}
}

func TestParseRejectsBadVersion(t *testing.T) {
	data := strings.Replace(string(Default()), "version: 1\n", "version: 2\n", 1)
	f, err := Parse("t.yaml", []byte(data))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	err = f.Validate()
	if err == nil {
		t.Fatal("version 2 validated")
	}
	if got := err.Error(); got != "theme file t.yaml: version: 2 is not supported; use 1" {
		t.Errorf("error = %q", got)
	}
}

func TestParseRejectsMalformedYAML(t *testing.T) {
	_, err := Parse("t.yaml", []byte("version: [1\n"))
	if err == nil || !strings.HasPrefix(err.Error(), "theme file t.yaml: ") {
		t.Errorf("error = %v", err)
	}
}

func TestLowContrastNamesPairingAndRatio(t *testing.T) {
	msg := validationError(t, "low-contrast.yaml")
	want := `theme file testdata/low-contrast.yaml: colors.light: pairing "primary button label": contrast 2.77:1 is below 4.5:1 (#F0EFE9 on #5B9E73)`
	if !strings.Contains(msg, want) {
		t.Errorf("error lacks %q:\n%s", want, msg)
	}
	// The dark theme of the file is fine, so no dark line appears.
	if strings.Contains(msg, "colors.dark") {
		t.Errorf("error names the dark theme:\n%s", msg)
	}
}

func TestUnknownFontFamilyListsShipped(t *testing.T) {
	msg := validationError(t, "bad-font.yaml")
	want := `theme file testdata/bad-font.yaml: fonts.heading.family: "Big Shoulders Inline Display" is not shipped; use Cinzel or Google Sans Flex`
	if !strings.Contains(msg, want) {
		t.Errorf("error lacks %q:\n%s", want, msg)
	}
	if !strings.Contains(msg, "fonts.mono.fallback: must end with monospace") {
		t.Errorf("error lacks the mono rule:\n%s", msg)
	}
}

func TestFallbackRejectsCSSInjection(t *testing.T) {
	msg := validationError(t, "css-injection.yaml")
	want := "theme file testdata/css-injection.yaml: fonts.body.fallback: use letters, digits, spaces, commas, hyphens and single quotes only"
	if !strings.Contains(msg, want) {
		t.Errorf("error lacks %q:\n%s", want, msg)
	}
	if strings.Contains(msg, "display:none") {
		t.Errorf("error echoes the injected CSS:\n%s", msg)
	}
}

// TestValidateReportsEveryProblemAtOnce is the rule table of the plan:
// one bad file, every line prefixed with the path and the YAML path.
func TestValidateReportsEveryProblemAtOnce(t *testing.T) {
	msg := validationError(t, "many-errors.yaml")
	for _, want := range []string{
		"theme file testdata/many-errors.yaml: name: must not be empty",
		"theme file testdata/many-errors.yaml: colors.dark.invert-fg: missing",
		"theme file testdata/many-errors.yaml: colors.light.ink: use six digit hex, got #123",
		"theme file testdata/many-errors.yaml: colors.light.sparkle: unknown token",
		"theme file testdata/many-errors.yaml: wordmark.text: 40 characters, the limit is 32",
		"theme file testdata/many-errors.yaml: logo.alt: required when logo.data_uri is set",
		"theme file testdata/many-errors.yaml: radii.small: use rem, got 3px",
		"theme file testdata/many-errors.yaml: spacing[3]: 0.5rem is not larger than spacing[2] 0.75rem",
		"theme file testdata/many-errors.yaml: roles.issuer.dark: contrast 2.",
		"is below 4.5:1 on #000000",
		"theme file testdata/many-errors.yaml: fonts.mono.fallback: must end with monospace",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error lacks %q", want)
		}
	}
	for _, line := range strings.Split(msg, "\n") {
		if !strings.HasPrefix(line, "theme file testdata/many-errors.yaml: ") {
			t.Errorf("line has no path prefix: %q", line)
		}
	}
	if t.Failed() {
		t.Logf("full error:\n%s", msg)
	}
}

func TestLoadMissingFileNamesPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yaml")
	_, err := Load(path)
	if err == nil {
		t.Fatal("a missing file loaded")
	}
	if !strings.HasPrefix(err.Error(), "theme file "+path+": ") {
		t.Errorf("error = %q", err)
	}
}

func TestLoadEmptyPathUsesDefault(t *testing.T) {
	f, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if f.Path() != DefaultPath || f.Name != "adamndegwa" {
		t.Errorf("path %q name %q", f.Path(), f.Name)
	}
	if got, want := f.HeadCSS(), headOf(t, ui.DefaultConfig()); got != want {
		t.Errorf("the embedded default renders other CSS than the kit default:\n got %s\nwant %s", got, want)
	}
}

func TestLoadRejectsAnInvalidFile(t *testing.T) {
	_, err := Load(filepath.Join("testdata", "low-contrast.yaml"))
	if err == nil || !strings.Contains(err.Error(), `pairing "primary button label"`) {
		t.Errorf("error = %v", err)
	}
	_, err = Load(filepath.Join("testdata", "unknown-key.yaml"))
	if err == nil || !strings.Contains(err.Error(), "field colours not found") {
		t.Errorf("error = %v", err)
	}
}

// TestCSSGoldenForDefault keeps the generated head of the stylesheet, the
// part the file controls, equal to testdata/default.css. The full
// stylesheet starts with it and ends with the base stylesheet of the kit.
func TestCSSGoldenForDefault(t *testing.T) {
	f, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	got := f.HeadCSS()
	path := filepath.Join("testdata", "default.css")
	if os.Getenv("VCA_WRITE_GOLDEN") == "1" {
		if writeErr := os.WriteFile(path, []byte(got), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	want, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("HeadCSS differs from %s (VCA_WRITE_GOLDEN=1 rewrites it)\ngot:\n%s", path, got)
	}
	full, err := f.CSS()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(full, got) {
		t.Error("the full stylesheet does not start with the generated head")
	}
	base, err := ui.Static.ReadFile("static/base.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(full, string(base)) {
		t.Error("the full stylesheet does not end with base.css")
	}
	for _, want := range []string{
		"@font-face{font-family:'Cinzel'", "@font-face{font-family:'Google Sans Flex'", "font-display:swap",
		"--font-heading:", "--font-body:", "--font-mono:",
		":root{--accent:#7A632A;", `[data-theme="dark"]{--accent:#C9A855;`, "prefers-color-scheme: dark",
		"--radius-s:0.125rem;", "--space-7:3rem;", "--role-accent:var(--accent);",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("head lacks %q", want)
		}
	}
}

func TestRebrandExample(t *testing.T) {
	f, err := Load(filepath.Join("testdata", "rebrand.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	css, err := f.CSS()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"--primary:#1B4D8C;", "--accent:#8A4B08;", "--paper:#FFFFFF;", // light
		"--primary:#7FB2F0;", "--paper:#0A0F1A;", // dark
		`[data-role="issuer"]{--role-accent:#8A4B08;}`,
		`[data-theme="dark"] [data-role="issuer"],[data-theme="dark"][data-role="issuer"]{--role-accent:#F0B36A;}`,
		"--radius-s:0;--radius-m:0.5rem;--radius-pill:62.5rem;",
		"--font-heading:'Google Sans Flex', system-ui, sans-serif;",
		"--font-body:'Google Sans Flex', system-ui, sans-serif;",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("css lacks %q", want)
		}
	}
	cfg := f.Config()
	if cfg.Brand.Wordmark != "Ministry" || cfg.Brand.Emphasis != "ID" {
		t.Errorf("wordmark = %q %q", cfg.Brand.Wordmark, cfg.Brand.Emphasis)
	}
	if cfg.Brand.Logo.Alt != "The crest" || !strings.HasPrefix(cfg.Brand.Logo.DataURI, "data:image/svg+xml;base64,") {
		t.Errorf("logo = %+v", cfg.Brand.Logo)
	}
	if cfg.Light.Name != "ministry-light" || cfg.Dark.Name != "ministry-dark" || cfg.Fonts.Name != "ministry" {
		t.Errorf("names = %q %q %q", cfg.Light.Name, cfg.Dark.Name, cfg.Fonts.Name)
	}
	if cfg.Fonts.Heading.File != fonts.Shipped()["Google Sans Flex"].File {
		t.Errorf("heading file = %q", cfg.Fonts.Heading.File)
	}
	assets, err := ui.AssetsFor(cfg)
	if err != nil {
		t.Fatalf("AssetsFor: %v", err)
	}
	if assets == nil {
		t.Fatal("no handler")
	}
}

// headOf renders the generated head of the kit config, with the names of
// the file, so the two are comparable.
func headOf(t *testing.T, cfg ui.Config) string {
	t.Helper()
	cfg.Light.Name, cfg.Dark.Name, cfg.Fonts.Name = "adamndegwa-light", "adamndegwa-dark", "adamndegwa"
	return fonts.CSS(cfg.Fonts) + theme.CSS(cfg.Light) + theme.CSS(cfg.Dark) + brand.CSS(cfg.Brand)
}

func TestPrefixNamesEveryLine(t *testing.T) {
	got := prefix("a.yaml", "yaml: unmarshal errors:\n  line 3: field x not found in type themefile.File\n  line 9: field y not found in type themefile.Fonts")
	want := "theme file a.yaml: line 3: field x not found in type themefile.File\ntheme file a.yaml: line 9: field y not found in type themefile.Fonts"
	if got != want {
		t.Errorf("got %q", got)
	}
}

// TestBadPaperDropsRoleAccentLine covers the file whose paper is not a
// colour: the paper line stays, the role accent line of that mode goes,
// because its ratio would be meaningless, and an empty fallback is named.
func TestBadPaperDropsRoleAccentLine(t *testing.T) {
	data := string(Default())
	data = strings.Replace(data, `paper: "#000000"`, `paper: "black"`, 1)
	data = strings.Replace(data, `issuer:   { light: "", dark: "" }`, `issuer:   { light: "", dark: "#575757" }`, 1)
	data = strings.Replace(data, `fallback: "Georgia, 'Times New Roman', serif"`, `fallback: ""`, 1)
	f, err := Parse("t.yaml", []byte(data))
	if err != nil {
		t.Fatal(err)
	}
	err = f.Validate()
	if err == nil {
		t.Fatal("validated")
	}
	msg := err.Error()
	for _, want := range []string{
		"theme file t.yaml: colors.dark.paper: use six digit hex, got black",
		"theme file t.yaml: fonts.heading.fallback: must not be empty",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error lacks %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "roles.issuer.dark") {
		t.Errorf("error rates an accent against a paper that is not a colour:\n%s", msg)
	}
}
