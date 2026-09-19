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
		"no name":       {Tokens: DefaultLight().Tokens, Pairings: defaultPairings()},
		"missing token": {Name: "x", Tokens: map[string]string{Ink: "#000000"}, Pairings: defaultPairings()},
		"bad hex": {Name: "x", Tokens: withToken(DefaultLight().Tokens, Ink, "black"),
			Pairings: defaultPairings()},
		"bad token name": {Name: "x", Tokens: withToken(DefaultLight().Tokens, "Bad Name", "#000000"),
			Pairings: defaultPairings()},
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
