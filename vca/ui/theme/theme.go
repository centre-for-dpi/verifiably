// SPDX-License-Identifier: Apache-2.0

// Package theme defines colour themes for the vca UI kit.
//
// A Theme is one Go value. Its tokens are the single source of truth for
// the CSS custom properties. Every foreground and background pairing in use
// is declared with its minimum WCAG 2.2 contrast ratio. Validate proves the
// pairings before the CSS is generated.
package theme

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Token names that every theme must define.
const (
	Ink     = "ink"     // primary text
	Paper   = "paper"   // page background
	Primary = "primary" // brand colour: links, primary buttons
	Accent  = "accent"  // details, focus ring, lines that carry meaning
	Warn    = "warn"    // warning state
	Bad     = "bad"     // error state
	OK      = "ok"      // success state
	Muted   = "muted"   // secondary text, input borders
	Line    = "line"    // decorative hairlines
)

// Required lists the token names a theme must define.
var required = []string{Ink, Paper, Primary, Accent, Warn, Bad, OK, Muted, Line}

// Minimum contrast ratios from WCAG 2.2 (1.4.3 and 1.4.11).
const (
	MinText  = 4.5 // body text
	MinLarge = 3.0 // large text and user interface components
)

// Pairing declares one foreground and background combination in use.
// Min is the contrast ratio the pairing must satisfy.
type Pairing struct {
	Name string
	FG   string // token name
	BG   string // token name
	Min  float64
}

// Theme is one named colour set.
// Dark selects the CSS selector: false renders ":root", true renders
// "[data-theme=\"dark\"]" plus a prefers-color-scheme block.
type Theme struct {
	Name     string
	Dark     bool
	Tokens   map[string]string
	Pairings []Pairing
}

var tokenName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// DefaultLight returns the light theme.
// The palette derives from the adamndegwa brand deck (Apache-2.0).
func DefaultLight() Theme {
	return Theme{
		Name: "default-light",
		Tokens: map[string]string{
			Ink:     "#0B0B09",
			Paper:   "#F0EFE9",
			Primary: "#21663F",
			Accent:  "#7A632A",
			Warn:    "#7A4B00",
			Bad:     "#A61B1B",
			OK:      "#1E6B3B",
			Muted:   "#6A6A65",
			Line:    "#D9DAD6",
		},
		Pairings: defaultPairings(),
	}
}

// DefaultDark returns the dark theme. The canvas is pure black.
func DefaultDark() Theme {
	return Theme{
		Name: "default-dark",
		Dark: true,
		Tokens: map[string]string{
			Ink:     "#F7F7F4",
			Paper:   "#000000",
			Primary: "#49A863",
			Accent:  "#C9A855",
			Warn:    "#F5D96E",
			Bad:     "#FF8A80",
			OK:      "#6FCB8A",
			Muted:   "#8A8A8A",
			Line:    "#3A3A38",
		},
		Pairings: defaultPairings(),
	}
}

// defaultPairings lists every pairing the base stylesheet uses.
func defaultPairings() []Pairing {
	return []Pairing{
		{"body text", Ink, Paper, MinText},
		{"links and primary text", Primary, Paper, MinText},
		{"accent text", Accent, Paper, MinText},
		{"warning text", Warn, Paper, MinText},
		{"error text", Bad, Paper, MinText},
		{"success text", OK, Paper, MinText},
		{"muted text", Muted, Paper, MinText},
		{"inverse: paper on ink (skip link)", Paper, Ink, MinText},
		{"primary button label", Paper, Primary, MinText},
		{"input border", Muted, Paper, MinLarge},
		{"focus ring", Accent, Paper, MinLarge},
		{"status badge outline: warn", Warn, Paper, MinLarge},
		{"status badge outline: bad", Bad, Paper, MinLarge},
		{"status badge outline: ok", OK, Paper, MinLarge},
	}
}

// Validate checks the theme. It returns an error when a required token is
// missing, a token name or colour is malformed, or a pairing is below its
// minimum contrast ratio.
func Validate(t Theme) error {
	var errs []error
	if t.Name == "" {
		errs = append(errs, errors.New("theme has no name"))
	}
	for _, name := range required {
		if _, ok := t.Tokens[name]; !ok {
			errs = append(errs, fmt.Errorf("theme %q: missing token %q", t.Name, name))
		}
	}
	for name, hex := range t.Tokens {
		if !tokenName.MatchString(name) {
			errs = append(errs, fmt.Errorf("theme %q: bad token name %q", t.Name, name))
		}
		if _, _, _, err := ParseHex(hex); err != nil {
			errs = append(errs, fmt.Errorf("theme %q: token %q: %w", t.Name, name, err))
		}
	}
	if len(t.Pairings) == 0 {
		errs = append(errs, fmt.Errorf("theme %q: declares no pairings", t.Name))
	}
	for _, p := range t.Pairings {
		fg, okFG := t.Tokens[p.FG]
		bg, okBG := t.Tokens[p.BG]
		if !okFG || !okBG {
			errs = append(errs, fmt.Errorf("theme %q: pairing %q uses unknown token", t.Name, p.Name))
			continue
		}
		ratio, err := ContrastRatio(fg, bg)
		if err != nil {
			continue // reported above as a bad token
		}
		if ratio < p.Min {
			errs = append(errs, fmt.Errorf("theme %q: pairing %q: contrast %.2f:1 is below %.1f:1 (%s on %s)",
				t.Name, p.Name, ratio, p.Min, fg, bg))
		}
	}
	return errors.Join(errs...)
}

// CSS renders the theme tokens as CSS custom properties.
// A light theme renders ":root{...}".
// A dark theme renders "[data-theme=\"dark\"]{...}" and the same block under
// "@media (prefers-color-scheme: dark)" for documents with no stamp.
func CSS(t Theme) string {
	names := make([]string, 0, len(t.Tokens))
	for name := range t.Tokens {
		names = append(names, name)
	}
	sort.Strings(names)
	var body strings.Builder
	for _, name := range names {
		fmt.Fprintf(&body, "--%s:%s;", name, t.Tokens[name])
	}
	var out strings.Builder
	fmt.Fprintf(&out, "/* theme: %s */\n", t.Name)
	if !t.Dark {
		fmt.Fprintf(&out, ":root{%s}\n", body.String())
		return out.String()
	}
	fmt.Fprintf(&out, "[data-theme=\"dark\"]{%s}\n", body.String())
	fmt.Fprintf(&out, "@media (prefers-color-scheme: dark){:root:not([data-theme=\"light\"]){%s}}\n", body.String())
	return out.String()
}
