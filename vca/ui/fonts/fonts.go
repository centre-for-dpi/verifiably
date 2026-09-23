// SPDX-License-Identifier: Apache-2.0

// Package fonts defines the font pack of the vca UI kit.
//
// A Pack names three roles: heading, body, and mono. The heading and body
// roles are each one self-hosted variable font file under static/fonts/
// with a fallback stack. The mono role has no file: code and numbers use
// a generic monospace stack. CSS renders the @font-face rules with
// font-display: swap.
package fonts

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Role is one typographic job.
type Role struct {
	Family   string // font-family name used in @font-face; empty for a generic stack
	Fallback string // fallback stack, for example "Georgia, serif"
	File     string // file name under static/fonts/, woff2 only; empty for a generic stack
	Weight   string // font-weight range, for example "100 900"; empty for a generic stack
}

// Pack is one named set of three roles.
type Pack struct {
	Name    string
	Heading Role // page titles and section headings
	Body    Role // body copy, labels, navigation, badges, buttons
	Mono    Role // code and numbers, a generic monospace stack with no file
}

// Slot pairs a CSS variable name with a role.
type Slot struct {
	Var  string // CSS custom property name without the leading dashes
	Role Role
}

var fileName = regexp.MustCompile(`^[a-z0-9-]+\.woff2$`)

// cssUnsafe are the characters a fallback stack must not hold, so it
// cannot end the custom property or open a new rule.
const cssUnsafe = `;{}<>\`

// cinzel and googleSansFlex are the two shipped families. Files are the
// latin subsets from the Fontsource packages on npm, licensed under
// OFL-1.1.
func cinzel() Role {
	return Role{
		Family:   "Cinzel",
		Fallback: "Georgia, 'Times New Roman', serif",
		File:     "cinzel-latin-wght-normal.woff2",
		Weight:   "400 900",
	}
}

func googleSansFlex() Role {
	return Role{
		Family:   "Google Sans Flex",
		Fallback: "system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif",
		File:     "google-sans-flex-latin-wght-normal.woff2",
		Weight:   "1 1000",
	}
}

// Default returns the shipped pack: Cinzel for headings, Google Sans Flex
// for body text, and a generic monospace stack for code and numbers.
func Default() Pack {
	return Pack{
		Name:    "default",
		Heading: cinzel(),
		Body:    googleSansFlex(),
		Mono: Role{
			Fallback: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
		},
	}
}

// Shipped returns the families whose files the kit embeds, keyed by
// family name. Each call returns a new map.
func Shipped() map[string]Role {
	out := map[string]Role{}
	for _, r := range []Role{cinzel(), googleSansFlex()} {
		out[r.Family] = r
	}
	return out
}

// Slots returns the three roles in a fixed order with their CSS variable
// names.
func Slots(p Pack) []Slot {
	return []Slot{
		{"font-heading", p.Heading},
		{"font-body", p.Body},
		{"font-mono", p.Mono},
	}
}

// Files returns the font file names the pack needs, in slot order. A role
// with no file adds nothing.
func Files(p Pack) []string {
	var out []string
	for _, s := range Slots(p) {
		if s.Role.File != "" {
			out = append(out, s.Role.File)
		}
	}
	return out
}

// Stack returns the font-family value for a role: the family plus
// fallback, or the fallback alone for a role with no family.
func Stack(r Role) string {
	if r.Family == "" {
		return r.Fallback
	}
	return fmt.Sprintf("'%s', %s", r.Family, r.Fallback)
}

// Validate checks that every role is complete and its file name is safe.
// The heading and body roles need a family, a file, and a weight. The
// mono role is a generic stack: no family, no file, no weight, and a
// fallback that ends in monospace.
func Validate(p Pack) error {
	var errs []error
	if p.Name == "" {
		errs = append(errs, errors.New("font pack has no name"))
	}
	for _, s := range Slots(p) {
		r := s.Role
		if r.Fallback == "" {
			errs = append(errs, fmt.Errorf("font pack %q: %s: no fallback stack", p.Name, s.Var))
		}
		if strings.ContainsAny(r.Fallback, cssUnsafe) {
			errs = append(errs, fmt.Errorf("font pack %q: %s: fallback %q holds one of %s", p.Name, s.Var, r.Fallback, cssUnsafe))
		}
		if s.Var == "font-mono" {
			errs = append(errs, validateMono(p.Name, r)...)
			continue
		}
		if r.Family == "" || strings.ContainsAny(r.Family, `'"\`) {
			errs = append(errs, fmt.Errorf("font pack %q: %s: bad family %q", p.Name, s.Var, r.Family))
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

func validateMono(pack string, r Role) []error {
	var errs []error
	if r.Family != "" || r.File != "" || r.Weight != "" {
		errs = append(errs, fmt.Errorf("font pack %q: font-mono: a generic stack takes no family, file, or weight", pack))
	}
	if !strings.HasSuffix(r.Fallback, "monospace") {
		errs = append(errs, fmt.Errorf("font pack %q: font-mono: fallback %q does not end in monospace", pack, r.Fallback))
	}
	return errs
}

// CSS renders the @font-face rules and the font stack custom properties.
// Files are referenced relative to /static/fonts/. A role with no file
// gets a custom property and no @font-face rule.
func CSS(p Pack) string {
	var out strings.Builder
	fmt.Fprintf(&out, "/* font pack: %s */\n", p.Name)
	for _, s := range Slots(p) {
		r := s.Role
		if r.File == "" {
			continue
		}
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
