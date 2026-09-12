// SPDX-License-Identifier: Apache-2.0

// Package fonts defines the font pack of the vca UI kit.
//
// A Pack names four roles: display, heading, body, and meta. Each role is
// one self-hosted variable font file under static/fonts/ with a fallback
// stack. CSS renders the @font-face rules with font-display: swap.
package fonts

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Role is one typographic job.
type Role struct {
	Family   string // font-family name used in @font-face
	Fallback string // generic fallback stack, for example "Georgia, serif"
	File     string // file name under static/fonts/, woff2 only
	Weight   string // font-weight range, for example "100 900"
}

// Pack is one named set of four roles.
type Pack struct {
	Name    string
	Display Role // hero and page titles
	Heading Role // section headings, labels
	Body    Role // body copy
	Meta    Role // navigation, badges, code, numbers
}

// Slot pairs a CSS variable name with a role.
type Slot struct {
	Var  string // CSS custom property name without the leading dashes
	Role Role
}

var fileName = regexp.MustCompile(`^[a-z0-9-]+\.woff2$`)

// Default returns the shipped pack. Files are the latin subsets from the
// Fontsource packages on npm. All four families are licensed under OFL-1.1.
func Default() Pack {
	return Pack{
		Name: "default",
		Display: Role{
			Family:   "Big Shoulders Inline Display",
			Fallback: "Impact, 'Arial Narrow Bold', sans-serif",
			File:     "big-shoulders-inline-display-latin-wght-normal.woff2",
			Weight:   "100 900",
		},
		Heading: Role{
			Family:   "Cinzel",
			Fallback: "Georgia, 'Times New Roman', serif",
			File:     "cinzel-latin-wght-normal.woff2",
			Weight:   "400 900",
		},
		Body: Role{
			Family:   "Google Sans Flex",
			Fallback: "system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif",
			File:     "google-sans-flex-latin-wght-normal.woff2",
			Weight:   "1 1000",
		},
		Meta: Role{
			Family:   "Google Sans Code",
			Fallback: "ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace",
			File:     "google-sans-code-latin-wght-normal.woff2",
			Weight:   "300 800",
		},
	}
}

// Slots returns the four roles in a fixed order with their CSS variable names.
func Slots(p Pack) []Slot {
	return []Slot{
		{"font-display", p.Display},
		{"font-heading", p.Heading},
		{"font-body", p.Body},
		{"font-meta", p.Meta},
	}
}

// Files returns the font file names the pack needs, in slot order.
func Files(p Pack) []string {
	var out []string
	for _, s := range Slots(p) {
		out = append(out, s.Role.File)
	}
	return out
}

// Stack returns the font-family value for a role: the family plus fallback.
func Stack(r Role) string {
	return fmt.Sprintf("'%s', %s", r.Family, r.Fallback)
}

// Validate checks that every role is complete and its file name is safe.
func Validate(p Pack) error {
	var errs []error
	if p.Name == "" {
		errs = append(errs, errors.New("font pack has no name"))
	}
	for _, s := range Slots(p) {
		r := s.Role
		if r.Family == "" || strings.ContainsAny(r.Family, `'"\`) {
			errs = append(errs, fmt.Errorf("font pack %q: %s: bad family %q", p.Name, s.Var, r.Family))
		}
		if r.Fallback == "" {
			errs = append(errs, fmt.Errorf("font pack %q: %s: no fallback stack", p.Name, s.Var))
		}
		if !fileName.MatchString(r.File) {
			errs = append(errs, fmt.Errorf("font pack %q: %s: bad file name %q", p.Name, s.Var, r.File))
		}
		if r.Weight == "" {
			errs = append(errs, fmt.Errorf("font pack %q: %s: no weight range", p.Name, s.Var))
		}
	}
	return errors.Join(errs...)
}

// CSS renders the @font-face rules and the font stack custom properties.
// Files are referenced relative to /static/fonts/.
func CSS(p Pack) string {
	var out strings.Builder
	fmt.Fprintf(&out, "/* font pack: %s */\n", p.Name)
	for _, s := range Slots(p) {
		r := s.Role
		fmt.Fprintf(&out, "@font-face{font-family:'%s';font-style:normal;font-weight:%s;font-display:swap;src:url(/static/fonts/%s) format('woff2-variations');}\n",
			r.Family, r.Weight, r.File)
	}
	out.WriteString(":root{")
	for _, s := range Slots(p) {
		fmt.Fprintf(&out, "--%s:%s;", s.Var, Stack(s.Role))
	}
	out.WriteString("}\n")
	return out.String()
}
