// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
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
			anyval.DiscardWrite(fmt.Fprintf(p.Out, "  %s\n", verr))
			continue
		}
		return answer, nil
	}
	return "", fmt.Errorf("setup: %s got %d bad answers", s.Env, maxTries)
}

// printQuestion writes the help text, the rule, and the offered value.
func (p Prompter) printQuestion(s Setting, offered string) {
	anyval.DiscardWrite(fmt.Fprintf(p.Out, "\n%s\n", s.Description))
	if s.Validation != "" {
		anyval.DiscardWrite(fmt.Fprintf(p.Out, "  Rule: %s\n", s.Validation))
	}
	if len(s.Choices) > 0 {
		anyval.DiscardWrite(fmt.Fprintf(p.Out, "  Choices: %s\n", strings.Join(s.Choices, ", ")))
	}
	shown := offered
	if s.Secret {
		shown = Mask(offered)
	}
	if shown != "" {
		anyval.DiscardWrite(fmt.Fprintf(p.Out, "%s [%s]: ", s.Env, shown))
		return
	}
	anyval.DiscardWrite(fmt.Fprintf(p.Out, "%s: ", s.Env))
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

// AskAll asks every question of one setup run. It asks the settings the
// proto marks with prompt first, then each required value that no source
// and no default filled. It returns the answers keyed by environment
// variable name (ADR-007 decision 2, ADR-008 decision 7).
//
// The offers map pre-fills one question, keyed by environment variable
// name. A --all run passes the answer of the last pair, so the operator
// presses enter to repeat it. Set an optional value with --set or with
// the env file.
func (p Prompter) AskAll(list []Resolution, offers map[string]string) (map[string]string, error) {
	answers := make(map[string]string)
	if err := p.askPrompted(list, offers, answers); err != nil {
		return nil, err
	}
	if err := p.askMissing(list, answers); err != nil {
		return nil, err
	}
	return answers, nil
}

// askPrompted asks the settings the proto marks with prompt. The
// question shows the default in brackets, so an empty answer keeps it.
// A value that a flag, the environment, or the env file supplied needs
// no question.
func (p Prompter) askPrompted(list []Resolution, offers, answers map[string]string) error {
	for _, r := range list {
		if !r.Setting.Prompt || !asksQuestion(r.Setting) || !opensAQuestion(r.Origin) {
			continue
		}
		offered := r.Value
		if v, ok := offers[r.Setting.Env]; ok && v != "" {
			offered = v
		}
		answer, err := p.Ask(r.Setting, offered)
		if err != nil {
			return err
		}
		if answer != "" {
			answers[r.Setting.Env] = answer
		}
	}
	return nil
}

// askMissing asks one question per required value that no source and no
// default filled. Every value of a laptop deployment has a default, so
// that run answers no question here.
func (p Prompter) askMissing(list []Resolution, answers map[string]string) error {
	for _, r := range list {
		if r.Value != "" || !r.Setting.Required || !asksQuestion(r.Setting) {
			continue
		}
		answer, err := p.Ask(r.Setting, "")
		if err != nil {
			return err
		}
		if answer != "" {
			answers[r.Setting.Env] = answer
		}
	}
	return nil
}

// opensAQuestion reports whether an origin still leaves the question
// open. A default or no value at all does. A value the operator supplied
// does not, because the run must not ask for what it already has.
func opensAQuestion(o Origin) bool { return o == OriginNone || o == OriginDefault }

// ErrEmptyMenu reports that a menu was built with no option.
var ErrEmptyMenu = errors.New("setup: the menu has no option")

// Choose shows a numbered menu and returns the chosen option. The
// operator answers with the number or with the name. The options keep
// the order the caller gave, which is the order of the proto enum
// (ADR-007 decision 2).
func (p Prompter) Choose(question string, options []string) (string, error) {
	if len(options) == 0 {
		return "", ErrEmptyMenu
	}
	for try := 0; try < maxTries; try++ {
		p.printMenu(question, options)
		line, err := p.In.ReadString('\n')
		answer := strings.TrimSpace(line)
		if answer == "" && err != nil {
			return "", ErrNoInput
		}
		if choice, ok := matchOption(answer, options); ok {
			return choice, nil
		}
		anyval.DiscardWrite(fmt.Fprintf(p.Out,
			"  Answer with a number from 1 to %d, or with the name.\n", len(options)))
	}
	return "", fmt.Errorf("setup: the menu got %d bad answers", maxTries)
}

// printMenu writes the question and one numbered line per option.
func (p Prompter) printMenu(question string, options []string) {
	anyval.DiscardWrite(fmt.Fprintf(p.Out, "\n%s\n", question))
	for i, o := range options {
		anyval.DiscardWrite(fmt.Fprintf(p.Out, "  %d) %s\n", i+1, o))
	}
	anyval.DiscardWrite(fmt.Fprintf(p.Out, "Number [1-%d]: ", len(options)))
}

// matchOption reads one menu answer. It accepts the number of a line or
// the name on it.
func matchOption(answer string, options []string) (string, bool) {
	if n, err := strconv.Atoi(answer); err == nil {
		if n >= 1 && n <= len(options) {
			return options[n-1], true
		}
		return "", false
	}
	for _, o := range options {
		if strings.EqualFold(answer, o) {
			return o, true
		}
	}
	return "", false
}

// Confirm asks a yes or no question. It returns the fallback when the
// operator presses enter.
func (p Prompter) Confirm(question string, fallback bool) (bool, error) {
	offered := "y/N"
	if fallback {
		offered = "Y/n"
	}
	anyval.DiscardWrite(fmt.Fprintf(p.Out, "\n%s [%s]: ", question, offered))
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
