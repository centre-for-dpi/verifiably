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

// TestAskAllAsksOnlyForAMissingRequiredValue uses a pair with no DPG.
// No stack backs it, so the discovery URL has no default.
func TestAskAllAsksOnlyForAMissingRequiredValue(t *testing.T) {
	pair := Pair{Role: roleHolder(t)}
	settings := Filter(Settings(), pair.Role, pair.Dpg)
	var out bytes.Buffer
	// The first line answers the public URL question with the default.
	p := NewPrompter(strings.NewReader(
		"\nhttps://idp.example/.well-known/openid-configuration\nhttp://dpg:8080\n"), &out)
	answers, err := p.AskAll(resolveWithDefaults(settings, Sources{}, pair, ""), nil)
	if err != nil {
		t.Fatalf("AskAll: %v", err)
	}
	if answers["VCA_OIDC_DISCOVERY_URL"] != "https://idp.example/.well-known/openid-configuration" {
		t.Errorf("got %q", answers["VCA_OIDC_DISCOVERY_URL"])
	}
	for _, name := range []string{
		"VCA_REDIS_URL", "VCA_DATABASE_URL", "VCA_LOG_LEVEL",
		"VCA_SECRETS_SESSION_KEY", "VCA_ROLE",
	} {
		if _, ok := answers[name]; ok {
			t.Errorf("the CLI asked for %s", name)
		}
	}
}

// TestAskAllAsksOneQuestionOnALaptop is the laptop path of
// ADR-008 decision 7. Every value of the issuer pair has a default, so
// the public URL is the one question.
func TestAskAllAsksOneQuestionOnALaptop(t *testing.T) {
	p := issuerPair()
	settings := Filter(Settings(), p.Role, p.Dpg)
	var out bytes.Buffer
	prompter := NewPrompter(strings.NewReader("\n"), &out)
	answers, err := prompter.AskAll(resolveWithDefaults(settings, Sources{}, p, ""), nil)
	if err != nil {
		t.Fatalf("AskAll: %v", err)
	}
	if answers["VCA_PUBLIC_URL"] != LocalPublicURL(p) {
		t.Errorf("an empty answer did not keep the default: %q", answers["VCA_PUBLIC_URL"])
	}
	if len(answers) != 1 {
		t.Errorf("the CLI asked %d questions: %v", len(answers), answers)
	}
	// The question reads "Public URL [http://localhost:18002]: ".
	want := "Public URL [" + LocalPublicURL(p) + "]: "
	if !strings.Contains(out.String(), want) {
		t.Errorf("the question is not %q:\n%s", want, out.String())
	}
	for _, note := range []string{
		"Leave blank for localhost", "https://issuer.example", "Variable: VCA_PUBLIC_URL",
	} {
		if !strings.Contains(out.String(), note) {
			t.Errorf("the question misses %q:\n%s", note, out.String())
		}
	}
}

// TestAskAllSkipsAPromptSettingThatASourceFilled proves a --set flag
// answers the question, so the run stays silent.
func TestAskAllSkipsAPromptSettingThatASourceFilled(t *testing.T) {
	p := issuerPair()
	settings := Filter(Settings(), p.Role, p.Dpg)
	src := Sources{Flags: map[string]string{"VCA_PUBLIC_URL": "https://issuer.example"}}
	var out bytes.Buffer
	prompter := NewPrompter(strings.NewReader(""), &out)
	answers, err := prompter.AskAll(resolveWithDefaults(settings, src, p, ""), nil)
	if err != nil {
		t.Fatalf("AskAll: %v", err)
	}
	if len(answers) != 0 || out.Len() != 0 {
		t.Errorf("the CLI asked a question it had the answer to:\n%s", out.String())
	}
}

// TestAskAllUsesTheOffer proves a --all run pre-fills the question with
// the answer of the last pair.
func TestAskAllUsesTheOffer(t *testing.T) {
	p := issuerPair()
	settings := Filter(Settings(), p.Role, p.Dpg)
	var out bytes.Buffer
	prompter := NewPrompter(strings.NewReader("\n"), &out)
	offers := map[string]string{"VCA_PUBLIC_URL": "https://one.example"}
	answers, err := prompter.AskAll(resolveWithDefaults(settings, Sources{}, p, ""), offers)
	if err != nil {
		t.Fatalf("AskAll: %v", err)
	}
	if answers["VCA_PUBLIC_URL"] != "https://one.example" {
		t.Errorf("the offer was not repeated: %q", answers["VCA_PUBLIC_URL"])
	}
}

func TestAskAllReportsAFailedQuestion(t *testing.T) {
	var out bytes.Buffer
	p := NewPrompter(strings.NewReader(""), &out)
	list := []Resolution{{Setting: find(t, Settings(), "public_url")}}
	list[0].Setting.Required = true
	list[0].Setting.Prompt = false
	if _, err := p.AskAll(list, nil); err == nil {
		t.Fatal("AskAll passed with no input")
	}
	list[0].Setting.Prompt = true
	if _, err := p.AskAll(list, nil); err == nil {
		t.Fatal("AskAll passed a prompt question with no input")
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
