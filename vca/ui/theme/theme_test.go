// SPDX-License-Identifier: Apache-2.0

package theme

import (
	"math"
	"strings"
	"testing"
)

func TestParseHex(t *testing.T) {
	r, g, b, err := ParseHex("#21663F")
	if err != nil {
		t.Fatal(err)
	}
	if r != 0x21 || g != 0x66 || b != 0x3F {
		t.Errorf("got %02x %02x %02x", r, g, b)
	}
	for _, bad := range []string{"", "#12345", "21663F", "#GGGGGG", "#1234567"} {
		if _, _, _, err := ParseHex(bad); err == nil {
			t.Errorf("ParseHex(%q) should fail", bad)
		}
	}
}

func TestRelativeLuminance(t *testing.T) {
	cases := map[string]float64{"#000000": 0, "#FFFFFF": 1}
	for hex, want := range cases {
		got, err := RelativeLuminance(hex)
		if err != nil {
			t.Fatal(err)
		}
		if math.Abs(got-want) > 1e-9 {
			t.Errorf("L(%s) = %v, want %v", hex, got, want)
		}
	}
	if _, err := RelativeLuminance("nope"); err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestContrastRatio(t *testing.T) {
	if r := mustRatio(t, "#000000", "#FFFFFF"); math.Abs(r-21) > 0.01 {
		t.Errorf("black/white = %v, want 21", r)
	}
	if r := mustRatio(t, "#21663F", "#21663F"); math.Abs(r-1) > 0.001 {
		t.Errorf("same colour = %v, want 1", r)
	}
	a := mustRatio(t, "#0B0B09", "#F7F7F4")
	b := mustRatio(t, "#F7F7F4", "#0B0B09")
	if math.Abs(a-b) > 1e-9 {
		t.Errorf("ratio not symmetric: %v vs %v", a, b)
	}
	if _, err := ContrastRatio("bad", "#FFFFFF"); err == nil {
		t.Error("expected error for invalid fg")
	}
	if _, err := ContrastRatio("#FFFFFF", "bad"); err == nil {
		t.Error("expected error for invalid bg")
	}
}

// TestDefaultsValidate is the WCAG 2.2 AA proof for the shipped themes.
func TestDefaultsValidate(t *testing.T) {
	for _, th := range []Theme{DefaultLight(), DefaultDark()} {
		if err := Validate(th); err != nil {
			t.Errorf("%s: %v", th.Name, err)
		}
		if len(th.Pairings) < 10 {
			t.Errorf("%s: only %d pairings declared", th.Name, len(th.Pairings))
		}
	}
	if DefaultLight().Dark || !DefaultDark().Dark {
		t.Error("Dark flag is wrong on a default theme")
	}
}

func TestValidateRejectsBadThemes(t *testing.T) {
	noInvert := DefaultLight()
	noInvert.Tokens = withToken(DefaultLight().Tokens, Ink, DefaultLight().Tokens[Ink])
	delete(noInvert.Tokens, InvertFG)
	if err := Validate(noInvert); err == nil || !strings.Contains(err.Error(), `missing token "invert-fg"`) {
		t.Errorf("a theme without invert-fg should fail, got %v", err)
	}

	low := DefaultLight()
	low.Tokens = map[string]string{}
	for k, v := range DefaultLight().Tokens {
		low.Tokens[k] = v
	}
	low.Tokens[Muted] = "#C0C0C0"
	err := Validate(low)
	if err == nil || !strings.Contains(err.Error(), "muted text") {
		t.Errorf("low contrast should fail on the muted pairing, got %v", err)
	}

	cases := map[string]Theme{
		"no name":       {Tokens: DefaultLight().Tokens, Pairings: DefaultPairings()},
		"missing token": {Name: "x", Tokens: map[string]string{Ink: "#000000"}, Pairings: DefaultPairings()},
		"bad hex": {Name: "x", Tokens: withToken(DefaultLight().Tokens, Ink, "black"),
			Pairings: DefaultPairings()},
		"bad token name": {Name: "x", Tokens: withToken(DefaultLight().Tokens, "Bad Name", "#000000"),
			Pairings: DefaultPairings()},
		"no pairings": {Name: "x", Tokens: DefaultLight().Tokens},
		"unknown pairing token": {Name: "x", Tokens: DefaultLight().Tokens,
			Pairings: []Pairing{{"ghost", "ghost", Paper, MinText}}},
	}
	for name, th := range cases {
		if err := Validate(th); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// brandTokens copies the adamndegwa brand (internal/brand/brand.go:12-34)
// into the kit token names, plus the kit status colours. Line in dark mode
// is the kit hairline: the brand draws its dark hairline as a translucent
// paper, and its dark mist is a text colour the kit does not use.
var brandTokens = map[bool]map[string]string{
	false: {
		Ink: "#0B0B09", Paper: "#F0EFE9", Primary: "#21663F", Accent: "#7A632A",
		Spark: "#F0D053", Secondary: "#3B3F39", Muted: "#6A6A65", Line: "#D9DAD6",
		InvertBG: "#21663F", InvertFG: "#F0EFE9", InvertMuted: "#D9DAD6", InvertAccent: "#F0D053",
		Warn: "#7A4B00", Bad: "#A61B1B", OK: "#1E6B3B",
	},
	true: {
		Ink: "#F7F7F4", Paper: "#000000", Primary: "#49A863", Accent: "#C9A855",
		Spark: "#F5D96E", Secondary: "#A8A8A4", Muted: "#888888", Line: "#3A3A38",
		InvertBG: "#49A863", InvertFG: "#000000", InvertMuted: "#000000", InvertAccent: "#000000",
		Warn: "#F5D96E", Bad: "#FF8A80", OK: "#6FCB8A",
	},
}

func TestDefaultsMirrorAdamndegwaBrand(t *testing.T) {
	for _, th := range []Theme{DefaultLight(), DefaultDark()} {
		want := brandTokens[th.Dark]
		if len(th.Tokens) != len(want) {
			t.Errorf("%s: %d tokens, want %d", th.Name, len(th.Tokens), len(want))
		}
		for name, hex := range want {
			if th.Tokens[name] != hex {
				t.Errorf("%s: token %s = %q, want %q", th.Name, name, th.Tokens[name], hex)
			}
		}
	}
}

// brandPairing is one pairing of the adamndegwa brand
// (internal/brand/brand.go:55-83) and the kit pairing that draws it.
type brandPairing struct {
	name   string
	dark   bool
	fg, bg string
	min    float64
	kit    string // kit pairing name; empty when the kit never draws it
}

var brandPairings = []brandPairing{
	{"body ink on paper", false, "#0B0B09", "#F0EFE9", 4.5, "body text"},
	{"charcoal on paper", false, "#3B3F39", "#F0EFE9", 4.5, "secondary text"},
	{"stone on paper", false, "#6A6A65", "#F0EFE9", 4.5, "muted text"},
	{"pine on paper", false, "#21663F", "#F0EFE9", 4.5, "links and primary text"},
	{"gold meta on paper", false, "#7A632A", "#F0EFE9", 4.5, "accent text"},
	{"paper on ink (selection/inverse)", false, "#F0EFE9", "#0B0B09", 4.5, "inverse: paper on ink (skip link)"},
	{"paper on pine (tile hover)", false, "#F0EFE9", "#21663F", 4.5, "inverted text"},
	{"mist on pine (tile hover desc)", false, "#D9DAD6", "#21663F", 4.5, "inverted muted text"},
	{"brass on pine (tile hover accent)", false, "#F0D053", "#21663F", 4.5, "inverted accent text"},
	// The kit draws spark only as inverted accent text, never on ink.
	{"brass on ink (large spark)", false, "#F0D053", "#0B0B09", 3.0, ""},
	{"paper on black", true, "#F7F7F4", "#000000", 4.5, "body text"},
	{"charcoal on black", true, "#A8A8A4", "#000000", 4.5, "secondary text"},
	{"stone on black", true, "#888888", "#000000", 4.5, "muted text"},
	{"moss on black", true, "#49A863", "#000000", 4.5, "links and primary text"},
	{"gold meta on black", true, "#C9A855", "#000000", 4.5, "accent text"},
	{"black on moss (selection/inverse)", true, "#000000", "#49A863", 4.5, "primary button label"},
	// Dark warn is brass, so warning text draws this pairing.
	{"brass on black (hover spark)", true, "#F5D96E", "#000000", 4.5, "warning text"},
	// Dark mist is a brand text colour with no kit token.
	{"mist on black", true, "#8A8A8A", "#000000", 4.5, ""},
	{"black on moss (card/tile hover)", true, "#000000", "#49A863", 4.5, "inverted text"},
}

func TestDefaultPairingsCoverBrandPairings(t *testing.T) {
	kit := map[string]Pairing{}
	for _, p := range DefaultPairings() {
		kit[p.Name] = p
	}
	for _, bp := range brandPairings {
		th := DefaultLight()
		if bp.dark {
			th = DefaultDark()
		}
		if bp.kit == "" {
			for _, p := range th.Pairings {
				if th.Tokens[p.FG] == bp.fg && th.Tokens[p.BG] == bp.bg {
					t.Errorf("%q: the kit draws it as %q, so map it", bp.name, p.Name)
				}
			}
			continue
		}
		p, ok := kit[bp.kit]
		if !ok {
			t.Errorf("%q: kit pairing %q does not exist", bp.name, bp.kit)
			continue
		}
		if th.Tokens[p.FG] != bp.fg || th.Tokens[p.BG] != bp.bg {
			t.Errorf("%q: kit pairing %q in %s is %s on %s, want %s on %s",
				bp.name, p.Name, th.Name, th.Tokens[p.FG], th.Tokens[p.BG], bp.fg, bp.bg)
		}
		if p.Min < bp.min {
			t.Errorf("%q: kit minimum %.1f is below the brand minimum %.1f", bp.name, p.Min, bp.min)
		}
		if r := mustRatio(t, bp.fg, bp.bg); r < bp.min {
			t.Errorf("%q: contrast %.2f:1 is below %.1f:1", bp.name, r, bp.min)
		}
	}
	if err := Validate(DefaultLight()); err != nil {
		t.Error(err)
	}
	if err := Validate(DefaultDark()); err != nil {
		t.Error(err)
	}
}

func TestDefaultPairingsAreACopy(t *testing.T) {
	a := DefaultPairings()
	a[0].Min = 1
	if DefaultPairings()[0].Min == 1 {
		t.Error("DefaultPairings must return a fresh slice")
	}
	if len(DefaultLight().Pairings) != len(DefaultPairings()) || len(DefaultDark().Pairings) != len(DefaultPairings()) {
		t.Error("the default themes must declare every kit pairing")
	}
}

func withToken(base map[string]string, name, hex string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	out[name] = hex
	return out
}

func TestCSSContainsEveryToken(t *testing.T) {
	light := DefaultLight()
	css := CSS(light)
	if !strings.HasPrefix(css, "/* theme: default-light */\n:root{") {
		t.Errorf("light CSS has wrong prefix: %q", css[:40])
	}
	for name, hex := range light.Tokens {
		if !strings.Contains(css, "--"+name+":"+hex+";") {
			t.Errorf("light CSS missing token %s", name)
		}
	}
	if strings.Contains(css, "data-theme") {
		t.Error("light CSS must not carry a data-theme selector")
	}

	dark := DefaultDark()
	css = CSS(dark)
	if !strings.Contains(css, `[data-theme="dark"]{`) {
		t.Error("dark CSS missing data-theme block")
	}
	if !strings.Contains(css, `@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){`) {
		t.Error("dark CSS missing prefers-color-scheme block")
	}
	for name, hex := range dark.Tokens {
		if strings.Count(css, "--"+name+":"+hex+";") != 2 {
			t.Errorf("dark CSS should carry token %s twice", name)
		}
	}
	// Tokens are sorted so the output is stable.
	if strings.Index(css, "--accent:") > strings.Index(css, "--bad:") {
		t.Error("tokens are not sorted")
	}
}

// mustRatio returns the contrast ratio of two colours.
func mustRatio(t *testing.T, fg, bg string) float64 {
	t.Helper()
	r, err := ContrastRatio(fg, bg)
	if err != nil {
		t.Fatalf("ContrastRatio(%s, %s): %v", fg, bg, err)
	}
	return r
}

func TestRequiredListsEveryDefaultToken(t *testing.T) {
	names := Required()
	if len(names) != len(DefaultLight().Tokens) {
		t.Errorf("Required() has %d names, the default has %d tokens", len(names), len(DefaultLight().Tokens))
	}
	for _, n := range names {
		if _, ok := DefaultDark().Tokens[n]; !ok {
			t.Errorf("default dark theme lacks %q", n)
		}
	}
	names[0] = "changed"
	if Required()[0] == "changed" {
		t.Error("Required must return a copy")
	}
}
