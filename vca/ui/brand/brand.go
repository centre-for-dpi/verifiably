// SPDX-License-Identifier: Apache-2.0

// Package brand holds the brand data of the vca UI kit: the wordmark, the
// logo, the corner radii, the spacing scale, and one accent colour per role.
//
// A Brand is data. Validate checks it against the light and dark themes,
// and CSS writes it as custom properties. Error texts name the key of the
// theme file, so a reader of the file can prefix them with the file path.
package brand

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/centre-for-dpi/vc-adapters/ui/theme"
)

// Limits of the brand values.
const (
	MaxWordmark  = 32       // characters of the wordmark text and of the emphasis
	MaxLogoBytes = 64 << 10 // decoded size of the logo
	MaxRadius    = 1.0      // rem, for the small and medium radii
	SpacingSteps = 7        // values of the spacing scale
)

// forbidden are the characters a wordmark or an alt text must not hold.
const forbidden = `<>&"`

// Roles returns the roles that can carry an accent, in a fixed order.
func Roles() []string {
	return []string{"admin", "issuer", "holder", "verifier"}
}

// Logo is an optional image beside the wordmark. DataURI is a base64 data
// URI of an SVG, PNG, or WebP image. Alt is required when DataURI is set.
type Logo struct {
	DataURI string
	Alt     string
}

// File is a decoded logo, ready to serve.
type File struct {
	Name        string // "logo.svg", "logo.png", or "logo.webp"
	ContentType string
	Body        []byte
}

// logoTypes maps each accepted data URI prefix to the file it serves.
var logoTypes = []struct{ prefix, name, contentType string }{
	{"data:image/svg+xml;base64,", "logo.svg", "image/svg+xml"},
	{"data:image/png;base64,", "logo.png", "image/png"},
	{"data:image/webp;base64,", "logo.webp", "image/webp"},
}

// errLogoType is the message for a data URI of any other type.
var errLogoType = errors.New("use data:image/svg+xml;base64, data:image/png;base64 or data:image/webp;base64")

// File decodes the logo. A logo with no data URI returns an empty File.
func (l Logo) File() (File, error) {
	if l.DataURI == "" {
		return File{}, nil
	}
	for _, t := range logoTypes {
		if data, ok := strings.CutPrefix(l.DataURI, t.prefix); ok {
			body, err := base64.StdEncoding.DecodeString(data)
			if err != nil {
				return File{}, errors.New("not valid base64")
			}
			return File{Name: t.name, ContentType: t.contentType, Body: body}, nil
		}
	}
	return File{}, errLogoType
}

// Radii are the corner radii, each "0" or a number of rem.
type Radii struct {
	Small  string // inputs and buttons
	Medium string // cards, dialogs, and toasts
	Pill   string // badges and chips
}

// Accent is the accent colour of one role in each mode. An empty value
// inherits the theme accent.
type Accent struct {
	Light string
	Dark  string
}

// Brand is the brand data of a deployment.
type Brand struct {
	Wordmark    string // the name in the header, for example "VCA"
	Emphasis    string // optional second part, drawn in the primary colour
	Logo        Logo
	Radii       Radii
	Spacing     []string          // seven rem values, strictly increasing
	RoleAccents map[string]Accent // keyed by the names of Roles
}

// Default returns the shipped brand: the wordmark "VCA" with no logo, the
// radii and spacing of the kit, and no role accent.
func Default() Brand {
	accents := map[string]Accent{}
	for _, r := range Roles() {
		accents[r] = Accent{}
	}
	return Brand{
		Wordmark:    "VCA",
		Radii:       Radii{Small: "0.125rem", Medium: "0.25rem", Pill: "62.5rem"},
		Spacing:     []string{"0.25rem", "0.5rem", "0.75rem", "1rem", "1.5rem", "2rem", "3rem"},
		RoleAccents: accents,
	}
}

var rem = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)rem$`)

// remValue parses "0" or "<number>rem".
func remValue(s string) (float64, bool) {
	if s == "0" {
		return 0, true
	}
	m := rem.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(m[1], 64)
	return v, err == nil
}

// Validate checks the brand. Role accents must reach the text minimum on
// the paper of their mode. It reports every problem at once.
func Validate(b Brand, light, dark theme.Theme) error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	checkText := func(key, s string, required bool) {
		if n := utf8.RuneCountInString(s); n > MaxWordmark {
			add("%s: %d characters, the limit is %d", key, n, MaxWordmark)
		}
		if required && strings.TrimSpace(s) == "" {
			add("%s: must not be empty", key)
		}
		if strings.ContainsAny(s, forbidden) {
			add(`%s: must not contain <, >, & or "`, key)
		}
	}
	checkText("wordmark.text", b.Wordmark, true)
	checkText("wordmark.emphasis", b.Emphasis, false)

	if b.Logo.DataURI != "" {
		f, err := b.Logo.File()
		switch {
		case err != nil:
			add("logo.data_uri: %v", err)
		case len(f.Body) > MaxLogoBytes:
			add("logo.data_uri: %d bytes, the limit is %d", len(f.Body), MaxLogoBytes)
		}
		if strings.TrimSpace(b.Logo.Alt) == "" {
			add("logo.alt: required when logo.data_uri is set")
		}
	}
	if strings.ContainsAny(b.Logo.Alt, forbidden) {
		add(`logo.alt: must not contain <, >, & or "`)
	}

	for _, r := range []struct {
		key, value string
		max        float64
	}{{"radii.small", b.Radii.Small, MaxRadius}, {"radii.medium", b.Radii.Medium, MaxRadius}, {"radii.pill", b.Radii.Pill, 0}} {
		v, ok := remValue(r.value)
		switch {
		case !ok:
			add("%s: use rem, got %s", r.key, r.value)
		case r.max > 0 && v > r.max:
			add("%s: %s is larger than %grem", r.key, r.value, r.max)
		}
	}

	if len(b.Spacing) != SpacingSteps {
		add("spacing: %d values, want %d", len(b.Spacing), SpacingSteps)
	}
	prev, prevOK := 0.0, false
	for i, s := range b.Spacing {
		v, ok := remValue(s)
		if !ok {
			add("spacing[%d]: use rem, got %s", i, s)
		} else if prevOK && v <= prev {
			add("spacing[%d]: %s is not larger than spacing[%d] %s", i, s, i-1, b.Spacing[i-1])
		}
		prev, prevOK = v, ok
	}

	errs = append(errs, validateAccents(b.RoleAccents, light, dark)...)
	return errors.Join(errs...)
}

// validateAccents checks every role accent against the paper of its mode.
func validateAccents(accents map[string]Accent, light, dark theme.Theme) []error {
	var errs []error
	known := map[string]bool{}
	for _, r := range Roles() {
		known[r] = true
	}
	for role := range accents {
		if !known[role] {
			errs = append(errs, fmt.Errorf("roles.%s: unknown role; use admin, issuer, holder or verifier", role))
		}
	}
	for _, role := range Roles() {
		a := accents[role]
		for _, m := range []struct {
			mode, value string
			th          theme.Theme
		}{{"light", a.Light, light}, {"dark", a.Dark, dark}} {
			if m.value == "" {
				continue
			}
			key := "roles." + role + "." + m.mode
			if _, _, _, err := theme.ParseHex(m.value); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", key, err))
				continue
			}
			paper := m.th.Tokens[theme.Paper]
			ratio, err := theme.ContrastRatio(m.value, paper)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: theme %q paper: %w", key, m.th.Name, err))
				continue
			}
			if ratio < theme.MinText {
				errs = append(errs, fmt.Errorf("%s: contrast %.2f:1 is below %.1f:1 on %s", key, ratio, theme.MinText, paper))
			}
		}
	}
	return errs
}

// CSS writes the brand as custom properties: --radius-s, --radius-m,
// --radius-pill, --space-1 to --space-7, and --role-accent, which defaults
// to var(--accent). Each role with an accent gets one rule for light mode
// and its dark twin. The dark twin follows the same mechanism as the theme:
// a data-theme stamp or, with no stamp, the system preference.
func CSS(b Brand) string {
	var root strings.Builder
	fmt.Fprintf(&root, "--radius-s:%s;--radius-m:%s;--radius-pill:%s;", b.Radii.Small, b.Radii.Medium, b.Radii.Pill)
	for i, s := range b.Spacing {
		fmt.Fprintf(&root, "--space-%d:%s;", i+1, s)
	}
	root.WriteString("--role-accent:var(--accent);")

	var out strings.Builder
	out.WriteString("/* brand */\n")
	fmt.Fprintf(&out, ":root{%s}\n", root.String())
	for _, role := range Roles() {
		a := b.RoleAccents[role]
		if a == (Accent{}) {
			continue
		}
		sel := `[data-role="` + role + `"]`
		fmt.Fprintf(&out, "%s{--role-accent:%s;}\n", sel, orAccent(a.Light))
		fmt.Fprintf(&out, "[data-theme=\"dark\"] %s,[data-theme=\"dark\"]%s{--role-accent:%s;}\n", sel, sel, orAccent(a.Dark))
		fmt.Fprintf(&out, "@media (prefers-color-scheme: dark){:root:not([data-theme=\"light\"]) %s,:root:not([data-theme=\"light\"])%s{--role-accent:%s;}}\n",
			sel, sel, orAccent(a.Dark))
	}
	return out.String()
}

// orAccent returns the colour, or the theme accent when it is empty.
func orAccent(hex string) string {
	if hex == "" {
		return "var(--accent)"
	}
	return hex
}
