// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
)

func TestParseDotenv(t *testing.T) {
	in := strings.Join([]string{
		"# a comment",
		"",
		"VCA_PUBLIC_URL=https://issuer.example",
		"export VCA_LOG_LEVEL=debug",
		`VCA_NOTE="two words"`,
		"VCA_SINGLE='one'",
		"VCA_EMPTY=",
		"  VCA_SPACED = value  ",
	}, "\n")
	got, err := ParseDotenv(strings.NewReader(in))
	if err != nil {
		t.Fatalf("ParseDotenv: %v", err)
	}
	want := map[string]string{
		"VCA_PUBLIC_URL": "https://issuer.example",
		"VCA_LOG_LEVEL":  "debug",
		"VCA_NOTE":       "two words",
		"VCA_SINGLE":     "one",
		"VCA_EMPTY":      "",
		"VCA_SPACED":     "value",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d variables, want %d", len(got), len(want))
	}
}

func TestParseDotenvRejectsBadLine(t *testing.T) {
	for _, in := range []string{"NOT A LINE", "=value"} {
		if _, err := ParseDotenv(strings.NewReader(in)); err == nil {
			t.Errorf("ParseDotenv(%q) passed", in)
		}
	}
}

func TestRenderDotenv(t *testing.T) {
	list := []Resolution{
		{Setting: Setting{Env: "VCA_PUBLIC_URL", Description: "The public URL.", Validation: "An absolute https URL."}, Value: "https://x.example"},
		{Setting: Setting{Env: "VCA_EMPTY", Description: "Nothing."}, Value: ""},
		{Setting: Setting{Env: "VCA_NOTE", Description: "A note."}, Value: "two words"},
	}
	out := RenderDotenv("issuer-waltid", list, map[string]string{"VCA_PORTS_PORTAL": "8080", "VCA_A": "1"})
	if !strings.Contains(out, "# issuer-waltid") {
		t.Error("the header is missing")
	}
	if !strings.Contains(out, "VCA_PUBLIC_URL=https://x.example") {
		t.Errorf("value missing:\n%s", out)
	}
	if !strings.Contains(out, "# Rule: An absolute https URL.") {
		t.Error("the rule comment is missing")
	}
	if strings.Contains(out, "VCA_EMPTY") {
		t.Error("an empty value reached the file")
	}
	if !strings.Contains(out, `VCA_NOTE="two words"`) {
		t.Error("a spaced value was not quoted")
	}
	// The extra block is sorted, so the output is the same on every run.
	if strings.Index(out, "VCA_A=1") > strings.Index(out, "VCA_PORTS_PORTAL=8080") {
		t.Error("the extra block is not sorted")
	}
	if RenderDotenv("x", nil, nil) != RenderDotenv("x", nil, nil) {
		t.Error("the output is not deterministic")
	}
}

func TestQuoteValue(t *testing.T) {
	cases := map[string]string{
		"plain":    "plain",
		"":         `""`,
		"a b":      `"a b"`,
		`a"b`:      `"a\"b"`,
		`a$b`:      `"a\$b"`,
		`a\b`:      `"a\\b"`,
		"with#has": `"with#has"`,
	}
	for in, want := range cases {
		if got := quoteValue(in); got != want {
			t.Errorf("quoteValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRenderThenParseRoundTrip(t *testing.T) {
	list := []Resolution{
		{Setting: Setting{Env: "VCA_A", Description: "a"}, Value: "one two"},
		{Setting: Setting{Env: "VCA_B", Description: "b"}, Value: "plain"},
	}
	out := RenderDotenv("h", list, nil)
	got, err := ParseDotenv(strings.NewReader(out))
	if err != nil {
		t.Fatalf("ParseDotenv: %v", err)
	}
	if got["VCA_A"] != `one two` || got["VCA_B"] != "plain" {
		t.Errorf("round trip = %v", got)
	}
}
