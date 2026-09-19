// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
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
	if _, err := p.Ask(find(t, Settings(), "public_url"), ""); err != ErrNoInput {
		t.Fatalf("got %v, want ErrNoInput", err)
	}
	// An offered value survives a closed input.
	p = NewPrompter(strings.NewReader(""), &out)
	got, err := p.Ask(find(t, Settings(), "log_level"), "info")
	if err != nil || got != "info" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestAskAllSkipsWhatHigherSourcesFilled(t *testing.T) {
	settings := Filter(Settings(), roleAdmin(t), dpgWaltid(t))
	var out bytes.Buffer
	// Blank lines take the offered default of every optional question.
	lines := strings.Repeat("\n", 30)
	p := NewPrompter(strings.NewReader(lines), &out)
	src := Sources{
		Flags: map[string]string{
			"VCA_PUBLIC_URL":         "https://flag.example",
			"VCA_DATABASE_URL":       "postgres://flag/db",
			"VCA_OIDC_DISCOVERY_URL": "https://idp.example/.well-known/openid-configuration",
		},
		File: map[string]string{"VCA_LOG_LEVEL": "warn"},
	}
	answers, err := p.AskAll(settings, src)
	if err != nil {
		t.Fatalf("AskAll: %v", err)
	}
	if _, ok := answers["VCA_PUBLIC_URL"]; ok {
		t.Error("the CLI asked for a value a flag already set")
	}
	if _, ok := answers["VCA_LOG_LEVEL"]; ok {
		t.Error("the CLI asked for a value the env file already set")
	}
	if _, ok := answers["VCA_SECRETS_SESSION_KEY"]; ok {
		t.Error("the CLI asked for a generated secret")
	}
	if _, ok := answers["VCA_ROLE"]; ok {
		t.Error("the CLI asked for the role")
	}
}

func TestAskAllOffersAnExistingSecret(t *testing.T) {
	s := find(t, Settings(), "database_url")
	var out bytes.Buffer
	p := NewPrompter(strings.NewReader("\n"), &out)
	answers, err := p.AskAll([]Setting{s}, Sources{
		Existing: map[string]string{"VCA_DATABASE_URL": "postgres://kept/db"},
	})
	if err != nil {
		t.Fatalf("AskAll: %v", err)
	}
	if answers["VCA_DATABASE_URL"] != "postgres://kept/db" {
		t.Errorf("got %q", answers["VCA_DATABASE_URL"])
	}
}

func TestAskAllReportsAFailedQuestion(t *testing.T) {
	var out bytes.Buffer
	p := NewPrompter(strings.NewReader(""), &out)
	if _, err := p.AskAll([]Setting{find(t, Settings(), "public_url")}, Sources{}); err == nil {
		t.Fatal("AskAll passed with no input")
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
