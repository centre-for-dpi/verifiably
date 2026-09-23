// SPDX-License-Identifier: Apache-2.0

// Package themefile reads the theme file of a deployment, deploy/vca/theme.yaml
// (ADR-032). The file sets the colours, the fonts, the wordmark, the logo,
// the radii, the spacing scale, and one accent per role. The kit keeps the
// pairings and their minimum ratios, so no file can make a page fail AA.
//
// Parse rejects an unknown key with its line number. Validate reports every
// problem at once. Each line starts with "theme file <path>:" and the YAML
// path of the value. Config turns a valid file into the kit values, and
// CSS renders the stylesheet the services serve.
//
// The package is the one place that reads YAML for the look. The kit under
// ui stays standard library only.
package themefile

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/ui"
	"github.com/centre-for-dpi/vc-adapters/ui/brand"
	"github.com/centre-for-dpi/vc-adapters/ui/fonts"
	"github.com/centre-for-dpi/vc-adapters/ui/theme"
)

// Version is the one file version this reader accepts.
const Version = 1

// EnvVar names the variable a service reads the file path from. An empty
// value selects the embedded default.
const EnvVar = "VCA_THEME_FILE"

// DefaultPath is the path Parse reports for the embedded default.
const DefaultPath = "embedded default"

// ShippedPath is the path of the tracked file, from the repository root.
// vca setup writes it when it is absent, and a test keeps it equal to the
// embedded default.
const ShippedPath = "deploy/vca/theme.yaml"

//go:embed default.yaml
var defaultYAML []byte

// Default returns the embedded default file. Each call returns a copy.
func Default() []byte {
	return append([]byte(nil), defaultYAML...)
}

// File is the theme file. The yaml tags are the keys of deploy/vca/theme.yaml.
type File struct {
	Version  int      `yaml:"version"`
	Name     string   `yaml:"name"`
	Wordmark Wordmark `yaml:"wordmark"`
	Logo     Logo     `yaml:"logo"`
	Fonts    Fonts    `yaml:"fonts"`
	Colors   Colors   `yaml:"colors"`
	Radii    Radii    `yaml:"radii"`
	Spacing  []string `yaml:"spacing"`
	Roles    Roles    `yaml:"roles"`

	path string
}

// Wordmark is the name in the header and the footer.
type Wordmark struct {
	Text     string `yaml:"text"`
	Emphasis string `yaml:"emphasis"`
}

// Logo is an optional image beside the wordmark.
type Logo struct {
	DataURI string `yaml:"data_uri"`
	Alt     string `yaml:"alt"`
}

// Fonts names the two shipped families and the three fallback stacks.
type Fonts struct {
	Heading Family `yaml:"heading"`
	Body    Family `yaml:"body"`
	Mono    Stack  `yaml:"mono"`
}

// Family is one shipped family with its fallback stack.
type Family struct {
	Family   string `yaml:"family"`
	Fallback string `yaml:"fallback"`
}

// Stack is a generic fallback stack with no file.
type Stack struct {
	Fallback string `yaml:"fallback"`
}

// Colors holds the tokens of each mode, keyed by token name.
type Colors struct {
	Light map[string]string `yaml:"light"`
	Dark  map[string]string `yaml:"dark"`
}

// Radii are the corner radii.
type Radii struct {
	Small  string `yaml:"small"`
	Medium string `yaml:"medium"`
	Pill   string `yaml:"pill"`
}

// Roles holds the optional accent of each role.
type Roles struct {
	Admin    Accent `yaml:"admin"`
	Issuer   Accent `yaml:"issuer"`
	Holder   Accent `yaml:"holder"`
	Verifier Accent `yaml:"verifier"`
}

// Accent is one colour per mode. An empty value inherits the theme accent.
type Accent struct {
	Light string `yaml:"light"`
	Dark  string `yaml:"dark"`
}

// Path returns the path Parse or Load was given, or DefaultPath.
func (f *File) Path() string { return f.path }

// Load reads, parses, and validates the file at path. An empty path loads
// the embedded default.
func Load(path string) (*File, error) {
	data := Default()
	name := DefaultPath
	if path != "" {
		var err error
		data, err = os.ReadFile(path) // #nosec G304 -- the operator names the file
		if err != nil {
			return nil, fmt.Errorf("theme file %s: %w", path, err)
		}
		name = path
	}
	f, err := Parse(name, data)
	if err != nil {
		return nil, err
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	return f, nil
}

// Parse decodes data. An unknown key fails with its line number. The path
// names the file in every error.
func Parse(path string, data []byte) (*File, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, errors.New(prefix(path, err.Error()))
	}
	f.path = path
	return &f, nil
}

// prefix puts "theme file <path>: " before every line of a yaml error and
// drops the header line of a multi error.
func prefix(path, msg string) string {
	var out []string
	for _, line := range strings.Split(msg, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "yaml: "))
		if line == "" || line == "unmarshal errors:" {
			continue
		}
		out = append(out, "theme file "+path+": "+line)
	}
	return strings.Join(out, "\n")
}

// fallbackChars are the characters a fallback stack may hold. Anything
// else could end the custom property or open a new rule.
var fallbackChars = regexp.MustCompile(`^[A-Za-z0-9 ,'-]+$`)

// Validate checks every rule of the file and reports every problem at
// once. Each line starts with the path of the file and the YAML path.
func (f *File) Validate() error {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}
	if f.Version != Version {
		add("version: %d is not supported; use %d", f.Version, Version)
	}
	if strings.TrimSpace(f.Name) == "" {
		add("name: must not be empty")
	}
	problems = append(problems, f.validateFonts()...)
	lightErrs := validateMode("light", f.Colors.Light)
	darkErrs := validateMode("dark", f.Colors.Dark)
	problems = append(problems, lightErrs...)
	problems = append(problems, darkErrs...)
	lightTheme, darkTheme := f.themes()
	if err := brand.Validate(f.brand(), lightTheme, darkTheme); err != nil {
		problems = append(problems, keepBrandProblems(err.Error(), f.Colors)...)
	}
	if len(problems) == 0 {
		return nil
	}
	for i, p := range problems {
		problems[i] = "theme file " + f.path + ": " + p
	}
	return errors.New(strings.Join(problems, "\n"))
}

// keepBrandProblems keeps the brand lines that stand on their own. A role
// accent line compares the colour with the paper of its mode, so it stays
// only when that paper is a colour; a bad paper has its own line.
func keepBrandProblems(msg string, colors Colors) []string {
	paperOK := map[string]bool{
		"light": isHex(colors.Light[theme.Paper]),
		"dark":  isHex(colors.Dark[theme.Paper]),
	}
	var out []string
	for _, line := range strings.Split(msg, "\n") {
		if strings.HasPrefix(line, "roles.") {
			key, _, _ := strings.Cut(line, ":")
			parts := strings.Split(key, ".")
			if len(parts) == 3 && !paperOK[parts[2]] {
				continue
			}
		}
		out = append(out, line)
	}
	return out
}

// isHex reports whether s is a six digit hex colour.
func isHex(s string) bool {
	_, _, _, err := theme.ParseHex(s)
	return err == nil
}

// shippedNames lists the shipped families in a fixed order for messages.
func shippedNames() string {
	names := make([]string, 0, len(fonts.Shipped()))
	for name := range fonts.Shipped() {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, " or ")
}

// validateFonts checks the families against the shipped set and the
// fallback stacks against the safe character set.
func (f *File) validateFonts() []string {
	var out []string
	shipped := fonts.Shipped()
	for _, fam := range []struct {
		key string
		Family
	}{{"fonts.heading", f.Fonts.Heading}, {"fonts.body", f.Fonts.Body}} {
		if _, ok := shipped[fam.Family.Family]; !ok {
			out = append(out, fmt.Sprintf("%s.family: %q is not shipped; use %s", fam.key, fam.Family.Family, shippedNames()))
		}
		out = append(out, checkFallback(fam.key+".fallback", fam.Fallback)...)
	}
	out = append(out, checkFallback("fonts.mono.fallback", f.Fonts.Mono.Fallback)...)
	if !strings.HasSuffix(strings.TrimSpace(f.Fonts.Mono.Fallback), "monospace") {
		out = append(out, "fonts.mono.fallback: must end with monospace")
	}
	return out
}

// checkFallback checks one fallback stack. The message never echoes the
// value, so an injected string stays out of the logs.
func checkFallback(key, value string) []string {
	if strings.TrimSpace(value) == "" {
		return []string{key + ": must not be empty"}
	}
	if !fallbackChars.MatchString(value) {
		return []string{key + ": use letters, digits, spaces, commas, hyphens and single quotes only"}
	}
	return nil
}

// validateMode checks the tokens of one mode: every required token is
// present, every token is known, every value is six digit hex, and every
// kit pairing reaches its minimum.
func validateMode(mode string, tokens map[string]string) []string {
	var out []string
	known := map[string]bool{}
	for _, name := range theme.Required() {
		known[name] = true
		if _, ok := tokens[name]; !ok {
			out = append(out, fmt.Sprintf("colors.%s.%s: missing", mode, name))
		}
	}
	names := make([]string, 0, len(tokens))
	for name := range tokens {
		names = append(names, name)
	}
	sort.Strings(names)
	bad := false
	for _, name := range names {
		if !known[name] {
			out = append(out, fmt.Sprintf("colors.%s.%s: unknown token; use %s", mode, name, strings.Join(theme.Required(), ", ")))
			continue
		}
		if _, _, _, err := theme.ParseHex(tokens[name]); err != nil {
			out = append(out, fmt.Sprintf("colors.%s.%s: use six digit hex, got %s", mode, name, tokens[name]))
			bad = true
		}
	}
	if len(out) > 0 || bad {
		return out
	}
	for _, p := range theme.DefaultPairings() {
		fg, bg := tokens[p.FG], tokens[p.BG]
		// Every token is a colour here, so the ratio never fails.
		ratio := anyval.OrZero(theme.ContrastRatio(fg, bg))
		if ratio < p.Min {
			out = append(out, fmt.Sprintf("colors.%s: pairing %q: contrast %.2f:1 is below %.1f:1 (%s on %s)",
				mode, p.Name, ratio, p.Min, fg, bg))
		}
	}
	return out
}

// themes builds the two kit themes from the file. Validate checks them.
func (f *File) themes() (light, dark theme.Theme) {
	light = theme.Theme{Name: f.Name + "-light", Tokens: copyTokens(f.Colors.Light), Pairings: theme.DefaultPairings()}
	dark = theme.Theme{Name: f.Name + "-dark", Dark: true, Tokens: copyTokens(f.Colors.Dark), Pairings: theme.DefaultPairings()}
	return light, dark
}

func copyTokens(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// brand builds the kit brand from the file.
func (f *File) brand() brand.Brand {
	return brand.Brand{
		Wordmark: f.Wordmark.Text,
		Emphasis: f.Wordmark.Emphasis,
		Logo:     brand.Logo{DataURI: f.Logo.DataURI, Alt: f.Logo.Alt},
		Radii:    brand.Radii{Small: f.Radii.Small, Medium: f.Radii.Medium, Pill: f.Radii.Pill},
		Spacing:  append([]string(nil), f.Spacing...),
		RoleAccents: map[string]brand.Accent{
			"admin":    {Light: f.Roles.Admin.Light, Dark: f.Roles.Admin.Dark},
			"issuer":   {Light: f.Roles.Issuer.Light, Dark: f.Roles.Issuer.Dark},
			"holder":   {Light: f.Roles.Holder.Light, Dark: f.Roles.Holder.Dark},
			"verifier": {Light: f.Roles.Verifier.Light, Dark: f.Roles.Verifier.Dark},
		},
	}
}

// pack builds the kit font pack. The file and the weight of a family come
// from the shipped set; the file sets only the fallback stack.
func (f *File) pack() fonts.Pack {
	shipped := fonts.Shipped()
	role := func(fam Family) fonts.Role {
		r := shipped[fam.Family]
		r.Fallback = fam.Fallback
		return r
	}
	return fonts.Pack{
		Name:    f.Name,
		Heading: role(f.Fonts.Heading),
		Body:    role(f.Fonts.Body),
		Mono:    fonts.Role{Fallback: f.Fonts.Mono.Fallback},
	}
}

// Config returns the kit values of a valid file. Call Validate first: the
// kit rejects the values of a file that failed it.
func (f *File) Config() ui.Config {
	light, dark := f.themes()
	return ui.Config{Light: light, Dark: dark, Fonts: f.pack(), Brand: f.brand()}
}

// HeadCSS returns the part of the stylesheet the file controls: the font
// faces and stacks, the light and dark tokens, and the brand properties.
// The base stylesheet of the kit follows it in CSS.
func (f *File) HeadCSS() string {
	cfg := f.Config()
	return fonts.CSS(cfg.Fonts) + theme.CSS(cfg.Light) + theme.CSS(cfg.Dark) + brand.CSS(cfg.Brand)
}

// CSS returns the whole text of /static/vca.css for the file.
func (f *File) CSS() (string, error) {
	return ui.StylesheetFor(f.Config())
}
