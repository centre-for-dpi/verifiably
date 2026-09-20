// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestAskTakesTheAnswer(t *testing.T) {
	var out bytes.Buffer
	p := NewPrompter(strings.NewReader("https://issuer.example\n"), &out)
	s := find(t, Settings(), "public_url")
	got, err := p.Ask(s, "")
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if got != "https://issuer.example" {
		t.Errorf("got %q", got)
	}
	if !strings.Contains(out.String(), s.Description) {
		t.Error("the question does not show the description")
	}
	if !strings.Contains(out.String(), "Rule:") {
		t.Error("the question does not show the rule")
	}
}

func TestAskTakesTheOfferedValueOnEnter(t *testing.T) {
	var out bytes.Buffer
	p := NewPrompter(strings.NewReader("\n"), &out)
	got, err := p.Ask(find(t, Settings(), "log_level"), "info")
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if got != "info" {
		t.Errorf("got %q, want info", got)
	}
	if !strings.Contains(out.String(), "[info]") {
		t.Error("the offered value is not shown")
	}
}

func TestAskShowsChoices(t *testing.T) {
	var out bytes.Buffer
	p := NewPrompter(strings.NewReader("debug\n"), &out)
	if _, err := p.Ask(find(t, Settings(), "role"), ""); err != nil {
		// role has choices; an invalid answer repeats the question.
		_ = err
	}
	if !strings.Contains(out.String(), "Choices: issuer, holder") {
		t.Errorf("choices are missing:\n%s", out.String())
	}
}

func TestAskMasksASecret(t *testing.T) {
	var out bytes.Buffer
	p := NewPrompter(strings.NewReader("\n"), &out)
	s := find(t, Settings(), "database_url")
	got, err := p.Ask(s, "postgres://u:p@h/d")
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if got != "postgres://u:p@h/d" {
		t.Errorf("got %q", got)
	}
	if strings.Contains(out.String(), "u:p@h") {
		t.Errorf("the prompt printed a secret:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "********") {
		t.Error("the prompt shows no mask")
	}
}

func TestAskRepeatsAfterABadAnswer(t *testing.T) {
	var out bytes.Buffer
	p := NewPrompter(strings.NewReader("http://x\nhttps://x.example\n"), &out)
	got, err := p.Ask(find(t, Settings(), "public_url"), "")
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if got != "https://x.example" {
		t.Errorf("got %q", got)
	}
	if !strings.Contains(out.String(), "scheme must be https") {
		t.Errorf("the reason is missing:\n%s", out.String())
	}
}

func TestAskGivesUpAfterThreeBadAnswers(t *testing.T) {
	var out bytes.Buffer
	p := NewPrompter(strings.NewReader("a\nb\nc\nd\n"), &out)
	if _, err := p.Ask(find(t, Settings(), "public_url"), ""); err == nil {
		t.Fatal("Ask accepted three bad answers")
	}
}

func TestAskReportsClosedInput(t *testing.T) {
	var out bytes.Buffer
	p := NewPrompter(strings.NewReader(""), &out)
	if _, err := p.Ask(find(t, Settings(), "public_url"), ""); !errors.Is(err, ErrNoInput) {
		t.Fatalf("got %v, want ErrNoInput", err)
	}
	// An offered value survives a closed input.
	p = NewPrompter(strings.NewReader(""), &out)
	got, err := p.Ask(find(t, Settings(), "log_level"), "info")
	if err != nil || got != "info" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestAskMissingAsksOnlyForAMissingRequiredValue(t *testing.T) {
	settings := Filter(Settings(), roleHolder(t), dpgWaltid(t))
	var out bytes.Buffer
	p := NewPrompter(strings.NewReader("redis://cache:6379\n"), &out)
	list := resolveWithDefaults(settings, Sources{}, Pair{Role: roleHolder(t), Dpg: dpgWaltid(t)})
	answers, err := p.AskMissing(list)
	if err != nil {
		t.Fatalf("AskMissing: %v", err)
	}
	if answers["VCA_REDIS_URL"] != "redis://cache:6379" {
		t.Errorf("got %q", answers["VCA_REDIS_URL"])
	}
	for _, name := range []string{
		"VCA_PUBLIC_URL", "VCA_DPG_URL", "VCA_OIDC_DISCOVERY_URL",
		"VCA_DATABASE_URL", "VCA_LOG_LEVEL", "VCA_SECRETS_SESSION_KEY", "VCA_ROLE",
	} {
		if _, ok := answers[name]; ok {
			t.Errorf("the CLI asked for %s", name)
		}
	}
}

// TestAskMissingAsksNothingOnALaptop is the laptop path of
// ADR-008 decision 7. Every value of the issuer pair has a default.
func TestAskMissingAsksNothingOnALaptop(t *testing.T) {
	p := issuerPair()
	settings := Filter(Settings(), p.Role, p.Dpg)
	var out bytes.Buffer
	prompter := NewPrompter(strings.NewReader(""), &out)
	answers, err := prompter.AskMissing(resolveWithDefaults(settings, Sources{}, p))
	if err != nil {
		t.Fatalf("AskMissing: %v", err)
	}
	if len(answers) != 0 {
		t.Errorf("the CLI asked %d questions: %v", len(answers), answers)
	}
	if out.Len() != 0 {
		t.Errorf("the CLI printed a question:\n%s", out.String())
	}
}

func TestAskMissingReportsAFailedQuestion(t *testing.T) {
	var out bytes.Buffer
	p := NewPrompter(strings.NewReader(""), &out)
	list := []Resolution{{Setting: find(t, Settings(), "public_url")}}
	list[0].Setting.Required = true
	if _, err := p.AskMissing(list); err == nil {
		t.Fatal("AskMissing passed with no input")
	}
}

func TestConfirm(t *testing.T) {
	cases := []struct {
		in       string
		fallback bool
		want     bool
	}{
		{"y\n", false, true}, {"yes\n", false, true}, {"n\n", true, false},
		{"\n", true, true}, {"\n", false, false}, {"maybe\n", true, false},
	}
	for _, c := range cases {
		var out bytes.Buffer
		p := NewPrompter(strings.NewReader(c.in), &out)
		got, err := p.Confirm("Write the files?", c.fallback)
		if err != nil {
			t.Fatalf("Confirm(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("Confirm(%q, %v) = %v, want %v", c.in, c.fallback, got, c.want)
		}
	}
}

func TestAsksQuestion(t *testing.T) {
	all := Settings()
	if asksQuestion(find(t, all, "secrets.session_key")) {
		t.Error("the CLI asks for a generated secret")
	}
	if !asksQuestion(find(t, all, "database_url")) {
		t.Error("the CLI does not ask for the database URL")
	}
	if asksQuestion(find(t, all, "ports.services")) {
		t.Error("the CLI asks for the service port map")
	}
}
