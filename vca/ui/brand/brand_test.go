// SPDX-License-Identifier: Apache-2.0

package brand

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/ui/theme"
)

const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 8 8"><rect width="8" height="8"/></svg>`

func svgURI(body string) string {
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(body))
}

func validate(b Brand) error {
	return Validate(b, theme.DefaultLight(), theme.DefaultDark())
}

func TestDefaultValidates(t *testing.T) {
	b := Default()
	if err := validate(b); err != nil {
		t.Fatal(err)
	}
	if b.Wordmark != "VCA" || b.Emphasis != "" || b.Logo != (Logo{}) {
		t.Errorf("default wordmark and logo = %+v", b)
	}
	if b.Radii != (Radii{Small: "0.125rem", Medium: "0.25rem", Pill: "62.5rem"}) {
		t.Errorf("default radii = %+v", b.Radii)
	}
	want := []string{"0.25rem", "0.5rem", "0.75rem", "1rem", "1.5rem", "2rem", "3rem"}
	if strings.Join(b.Spacing, " ") != strings.Join(want, " ") {
		t.Errorf("default spacing = %v", b.Spacing)
	}
	if len(b.RoleAccents) != len(Roles()) {
		t.Errorf("default role accents = %v", b.RoleAccents)
	}
	for _, r := range Roles() {
		if a, ok := b.RoleAccents[r]; !ok || a != (Accent{}) {
			t.Errorf("default accent of %s = %+v, %v; want empty", r, a, ok)
		}
	}
	// Each call returns fresh values.
	b.Spacing[0] = "9rem"
	b.RoleAccents["issuer"] = Accent{Light: "#000000"}
	if Default().Spacing[0] != "0.25rem" || Default().RoleAccents["issuer"].Light != "" {
		t.Error("Default must return a new brand on each call")
	}
	r := Roles()
	r[0] = "x"
	if Roles()[0] != "admin" {
		t.Error("Roles must return a copy")
	}
}

func TestValidateAcceptsAFullBrand(t *testing.T) {
	b := Default()
	b.Wordmark, b.Emphasis = "Republic", "Credentials"
	b.Logo = Logo{DataURI: svgURI(svg), Alt: "Republic crest"}
	b.Radii = Radii{Small: "0", Medium: "1rem", Pill: "999rem"}
	b.RoleAccents["issuer"] = Accent{Light: "#1F4E79", Dark: "#9CC3E6"}
	b.RoleAccents["holder"] = Accent{Light: "#6A1B9A"}
	if err := validate(b); err != nil {
		t.Fatal(err)
	}
	for _, uri := range []string{
		"data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("\x89PNG")),
		"data:image/webp;base64," + base64.StdEncoding.EncodeToString([]byte("RIFF")),
	} {
		b.Logo.DataURI = uri
		if err := validate(b); err != nil {
			t.Errorf("%s: %v", uri[:22], err)
		}
	}
}

func TestValidateRejects(t *testing.T) {
	big := strings.Repeat("a", 70<<10)
	cases := []struct {
		name string
		edit func(b *Brand)
		want string
	}{
		{"40 character wordmark", func(b *Brand) { b.Wordmark = strings.Repeat("W", 40) }, "wordmark.text: 40 characters, the limit is 32"},
		{"empty wordmark", func(b *Brand) { b.Wordmark = " " }, "wordmark.text: must not be empty"},
		{"script wordmark", func(b *Brand) { b.Wordmark = "<script>" }, `wordmark.text: must not contain <, >, & or "`},
		{"quote emphasis", func(b *Brand) { b.Emphasis = `a"b` }, `wordmark.emphasis: must not contain <, >, & or "`},
		{"long emphasis", func(b *Brand) { b.Emphasis = strings.Repeat("é", 33) }, "wordmark.emphasis: 33 characters, the limit is 32"},
		{"radius in px", func(b *Brand) { b.Radii.Small = "3px" }, "radii.small: use rem, got 3px"},
		{"medium radius too large", func(b *Brand) { b.Radii.Medium = "2rem" }, "radii.medium: 2rem is larger than 1rem"},
		{"pill radius in percent", func(b *Brand) { b.Radii.Pill = "50%" }, "radii.pill: use rem, got 50%"},
		{"spacing not increasing", func(b *Brand) { b.Spacing[3] = "0.5rem" }, "spacing[3]: 0.5rem is not larger than spacing[2] 0.75rem"},
		{"spacing in px", func(b *Brand) { b.Spacing[1] = "8px" }, "spacing[1]: use rem, got 8px"},
		{"five spacing values", func(b *Brand) { b.Spacing = b.Spacing[:5] }, "spacing: 5 values, want 7"},
		{"70 KiB logo", func(b *Brand) { b.Logo = Logo{DataURI: svgURI(big), Alt: "x"} }, "logo.data_uri: 71680 bytes, the limit is 65536"},
		{"html logo", func(b *Brand) {
			b.Logo = Logo{DataURI: "data:text/html;base64," + base64.StdEncoding.EncodeToString([]byte("<p>")), Alt: "x"}
		}, "logo.data_uri: use data:image/svg+xml;base64, data:image/png;base64 or data:image/webp;base64"},
		{"logo not base64", func(b *Brand) { b.Logo = Logo{DataURI: "data:image/png;base64,***", Alt: "x"} }, "logo.data_uri: not valid base64"},
		{"logo without alt", func(b *Brand) { b.Logo = Logo{DataURI: svgURI(svg), Alt: " "} }, "logo.alt: required when logo.data_uri is set"},
		{"quote in alt", func(b *Brand) { b.Logo = Logo{DataURI: svgURI(svg), Alt: `a"b`} }, `logo.alt: must not contain <, >, & or "`},
		{"dark role accent at 2.9:1", func(b *Brand) { b.RoleAccents["issuer"] = Accent{Dark: "#585858"} }, "roles.issuer.dark: contrast 2.95:1 is below 4.5:1 on #000000"},
		{"light role accent too pale", func(b *Brand) { b.RoleAccents["verifier"] = Accent{Light: "#F0D053"} }, "roles.verifier.light: contrast"},
		{"role accent not hex", func(b *Brand) { b.RoleAccents["admin"] = Accent{Light: "blue"} }, `roles.admin.light: invalid hex colour "blue"`},
		{"unknown role", func(b *Brand) { b.RoleAccents["pilot"] = Accent{} }, "roles.pilot: unknown role; use admin, issuer, holder or verifier"},
	}
	for _, c := range cases {
		b := Default()
		c.edit(&b)
		err := validate(b)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
	// A theme with no paper colour cannot prove a role accent.
	noPaper := theme.DefaultDark()
	noPaper.Tokens = map[string]string{}
	b := Default()
	b.RoleAccents["holder"] = Accent{Dark: "#FFFFFF"}
	if err := Validate(b, theme.DefaultLight(), noPaper); err == nil || !strings.Contains(err.Error(), "roles.holder.dark") {
		t.Errorf("missing paper should fail, got %v", err)
	}
	// Every problem is reported at once.
	b = Default()
	b.Wordmark, b.Radii.Small = "", "1px"
	if err := validate(b); err == nil || !strings.Contains(err.Error(), "wordmark.text") || !strings.Contains(err.Error(), "radii.small") {
		t.Errorf("want both problems, got %v", err)
	}
}

func TestLogoFile(t *testing.T) {
	f, err := Logo{}.File()
	if err != nil || f.Name != "" || f.Body != nil {
		t.Errorf("no logo = %+v, %v", f, err)
	}
	cases := map[string]File{
		svgURI(svg):                       {Name: "logo.svg", ContentType: "image/svg+xml", Body: []byte(svg)},
		"data:image/png;base64,iVBORw==":  {Name: "logo.png", ContentType: "image/png", Body: []byte("\x89PNG")},
		"data:image/webp;base64,UklGRg==": {Name: "logo.webp", ContentType: "image/webp", Body: []byte("RIFF")},
	}
	for uri, want := range cases {
		got, err := Logo{DataURI: uri, Alt: "x"}.File()
		if err != nil || got.Name != want.Name || got.ContentType != want.ContentType || string(got.Body) != string(want.Body) {
			t.Errorf("%s: got %+v, %v", want.Name, got, err)
		}
	}
	if _, err := (Logo{DataURI: "data:image/gif;base64,R0lG"}).File(); err == nil {
		t.Error("a gif logo should fail")
	}
}

func TestCSSGolden(t *testing.T) {
	got := CSS(Default())
	path := filepath.Join("testdata", "default.css")
	if os.Getenv("VCA_WRITE_GOLDEN") == "1" {
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("CSS(Default()) differs from %s (VCA_WRITE_GOLDEN=1 rewrites it)\ngot:\n%s", path, got)
	}
}

func TestCSSRoleAccents(t *testing.T) {
	b := Default()
	b.Radii.Small = "0"
	b.RoleAccents["issuer"] = Accent{Light: "#1F4E79", Dark: "#9CC3E6"}
	b.RoleAccents["holder"] = Accent{Light: "#6A1B9A"}
	css := CSS(b)
	for _, want := range []string{
		"--radius-s:0;", "--role-accent:var(--accent);",
		`[data-role="issuer"]{--role-accent:#1F4E79;}`,
		`[data-theme="dark"] [data-role="issuer"],[data-theme="dark"][data-role="issuer"]{--role-accent:#9CC3E6;}`,
		`@media (prefers-color-scheme: dark){:root:not([data-theme="light"]) [data-role="issuer"],:root:not([data-theme="light"])[data-role="issuer"]{--role-accent:#9CC3E6;}}`,
		// A role with only a light accent falls back to the accent in dark mode.
		`[data-role="holder"]{--role-accent:#6A1B9A;}`,
		`[data-theme="dark"] [data-role="holder"],[data-theme="dark"][data-role="holder"]{--role-accent:var(--accent);}`,
	} {
		if !strings.Contains(css, want) {
			t.Errorf("CSS missing %q\n%s", want, css)
		}
	}
	if strings.Contains(css, `"admin"`) {
		t.Error("a role with no accent must write no rule")
	}
	if strings.Index(css, `"issuer"`) > strings.Index(css, `"holder"`) {
		t.Error("role rules must follow the order of Roles")
	}
}
