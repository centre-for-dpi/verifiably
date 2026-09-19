// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// maxTries is the number of times the CLI asks one question again after a
// bad answer.
const maxTries = 3

// Prompter asks the questions of a setup run.
// It reads from In and writes to Out, so a test drives it with buffers.
type Prompter struct {
	In  *bufio.Reader
	Out io.Writer
}

// NewPrompter builds a Prompter over a reader and a writer.
func NewPrompter(in io.Reader, out io.Writer) Prompter {
	return Prompter{In: bufio.NewReader(in), Out: out}
}

// ErrNoInput reports that the operator closed the input.
var ErrNoInput = errors.New("setup: the input ended before every question was answered")

// Ask shows one question and returns the answer. An empty answer takes
// the offered value. Ask asks again while the answer breaks the rule of
// the setting.
func (p Prompter) Ask(s Setting, offered string) (string, error) {
	for try := 0; try < maxTries; try++ {
		p.printQuestion(s, offered)
		line, err := p.In.ReadString('\n')
		answer := strings.TrimSpace(line)
		if answer == "" && err != nil {
			if errors.Is(err, io.EOF) && offered != "" {
				return offered, nil
			}
			return "", ErrNoInput
		}
		if answer == "" {
			answer = offered
		}
		if verr := Validate(s, answer); verr != nil {
			fmt.Fprintf(p.Out, "  %s\n", verr)
			continue
		}
		return answer, nil
	}
	return "", fmt.Errorf("setup: %s got %d bad answers", s.Env, maxTries)
}

// printQuestion writes the help text, the rule, and the offered value.
func (p Prompter) printQuestion(s Setting, offered string) {
	fmt.Fprintf(p.Out, "\n%s\n", s.Description)
	if s.Validation != "" {
		fmt.Fprintf(p.Out, "  Rule: %s\n", s.Validation)
	}
	if len(s.Choices) > 0 {
		fmt.Fprintf(p.Out, "  Choices: %s\n", strings.Join(s.Choices, ", "))
	}
	shown := offered
	if s.Secret {
		shown = Mask(offered)
	}
	if shown != "" {
		fmt.Fprintf(p.Out, "%s [%s]: ", s.Env, shown)
		return
	}
	fmt.Fprintf(p.Out, "%s: ", s.Env)
}

// asksQuestion reports whether the CLI asks the operator for a setting.
// The CLI generates every secret it can, so it never asks for one
// (ADR-007 decision 5).
func asksQuestion(s Setting) bool {
	if !s.Asks() {
		return false
	}
	return !s.Secret || s.Kind != KindSecretRef
}

// AskAll asks every question that no higher source already answered.
// It returns the answers keyed by environment variable name.
// A setting that a flag, the environment, or the env file already filled
// gets no question, because those sources win anyway (ADR-007 decision 4).
func (p Prompter) AskAll(settings []Setting, src Sources) (map[string]string, error) {
	answers := make(map[string]string)
	for _, s := range settings {
		if !asksQuestion(s) {
			continue
		}
		if _, origin := Resolve(s, src); origin == OriginFlag || origin == OriginEnv || origin == OriginFile {
			continue
		}
		offered := s.Default
		if v, ok := lookup(src.Existing, s.Env); ok && s.Secret {
			offered = v
		}
		answer, err := p.Ask(s, offered)
		if err != nil {
			return nil, err
		}
		if answer != "" {
			answers[s.Env] = answer
		}
	}
	return answers, nil
}

// Confirm asks a yes or no question. It returns the fallback when the
// operator presses enter.
func (p Prompter) Confirm(question string, fallback bool) (bool, error) {
	offered := "y/N"
	if fallback {
		offered = "Y/n"
	}
	fmt.Fprintf(p.Out, "\n%s [%s]: ", question, offered)
	line, err := p.In.ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	if answer == "" {
		if err != nil && !errors.Is(err, io.EOF) {
			return false, ErrNoInput
		}
		return fallback, nil
	}
	return answer == "y" || answer == "yes", nil
}
