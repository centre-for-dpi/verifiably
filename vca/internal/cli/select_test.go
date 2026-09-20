// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// tty builds an Environment that acts as a terminal with scripted
// answers.
func tty(root, answers string) Environment {
	return Environment{
		Root:  root,
		In:    strings.NewReader(answers),
		IsTTY: func() bool { return true },
	}
}

func TestChooseTakesTheNumber(t *testing.T) {
	var out bytes.Buffer
	p := NewPrompter(strings.NewReader("2\n"), &out)
	got, err := p.Choose(DpgQuestion, DpgNames())
	if err != nil {
		t.Fatalf("Choose: %v", err)
	}
	if got != DpgNames()[1] {
		t.Errorf("got %q, want %q", got, DpgNames()[1])
	}
	text := out.String()
	if !strings.Contains(text, DpgQuestion) {
		t.Error("the menu does not show the question")
	}
	for i, name := range DpgNames() {
		if !strings.Contains(text, "  "+itoa(i+1)+") "+name+"\n") {
			t.Errorf("the menu has no line for %s", name)
		}
	}
}

// itoa keeps the test free of a strconv import in the assertions.
func itoa(n int) string { return string(rune('0' + n)) }

func TestChooseTakesTheName(t *testing.T) {
	var out bytes.Buffer
	p := NewPrompter(strings.NewReader("CREDEBL\n"), &out)
	got, err := p.Choose(DpgQuestion, DpgNames())
	if err != nil {
		t.Fatalf("Choose: %v", err)
	}
	if got != "credebl" {
		t.Errorf("got %q", got)
	}
}

func TestChooseAsksAgainAfterABadAnswer(t *testing.T) {
	var out bytes.Buffer
	p := NewPrompter(strings.NewReader("9\nmayor\n1\n"), &out)
	got, err := p.Choose(RoleQuestion, RoleNames())
	if err != nil {
		t.Fatalf("Choose: %v", err)
	}
	if got != RoleNames()[0] {
		t.Errorf("got %q", got)
	}
	if strings.Count(out.String(), "Answer with a number") != 2 {
		t.Errorf("output = %q", out.String())
	}
}

func TestChooseStopsAfterThreeBadAnswers(t *testing.T) {
	var out bytes.Buffer
	p := NewPrompter(strings.NewReader("a\nb\nc\n"), &out)
	if _, err := p.Choose(RoleQuestion, RoleNames()); err == nil {
		t.Fatal("three bad answers passed")
	}
}

func TestChooseReportsAnEmptyMenu(t *testing.T) {
	var out bytes.Buffer
	p := NewPrompter(strings.NewReader("1\n"), &out)
	_, err := p.Choose(RoleQuestion, nil)
	if !errors.Is(err, ErrEmptyMenu) {
		t.Errorf("err = %v", err)
	}
}

func TestChooseReportsAClosedInput(t *testing.T) {
	var out bytes.Buffer
	p := NewPrompter(strings.NewReader(""), &out)
	_, err := p.Choose(RoleQuestion, RoleNames())
	if !errors.Is(err, ErrNoInput) {
		t.Errorf("err = %v", err)
	}
}

func TestMenusListEveryNameInProtoOrder(t *testing.T) {
	s := selection{allowAll: true}
	wantRoles := append(RoleNames(), AllChoice)
	if strings.Join(s.roleChoices(), ",") != strings.Join(wantRoles, ",") {
		t.Errorf("roles = %v", s.roleChoices())
	}
	wantDpgs := append(DpgNames(), AllChoice)
	if strings.Join(s.dpgChoices(), ",") != strings.Join(wantDpgs, ",") {
		t.Errorf("dpgs = %v", s.dpgChoices())
	}
	plain := selection{}
	if strings.Join(plain.dpgChoices(), ",") != strings.Join(DpgNames(), ",") {
		t.Errorf("a command with no --all offers %v", plain.dpgChoices())
	}
}

func TestDeployAsksTheRoleAndTheDpg(t *testing.T) {
	status, out, errOut := run(t, tty(t.TempDir(), "1\n1\n"), "deploy", "--dry-run")
	if status != 0 {
		t.Fatalf("status = %d\n%s", status, errOut)
	}
	if !strings.Contains(out, RoleQuestion) || !strings.Contains(out, DpgQuestion) {
		t.Fatalf("output = %q", out)
	}
	want := Pair{Role: Roles()[0], Dpg: Dpgs()[0]}.Name()
	if !strings.Contains(out, "# "+want+"\n") {
		t.Errorf("the dry run has no command for %s", want)
	}
}

func TestDeployAsksOnlyTheMissingName(t *testing.T) {
	status, out, errOut := run(t, tty(t.TempDir(), "3\n"), "deploy", "--dpg", "credebl", "--dry-run")
	if status != 0 {
		t.Fatalf("status = %d\n%s", status, errOut)
	}
	if strings.Contains(out, DpgQuestion) {
		t.Error("the run asked for a DPG that the flag named")
	}
	want := Pair{Role: Roles()[2], Dpg: Dpgs()[2]}.Name()
	if !strings.Contains(out, "# "+want+"\n") {
		t.Errorf("the dry run has no command for %s\n%s", want, out)
	}
}

func TestMenuAllRoleTakesEveryPair(t *testing.T) {
	answer := itoa(len(RoleNames())+1) + "\n" + itoa(len(DpgNames())+1) + "\n"
	status, out, errOut := run(t, tty(t.TempDir(), answer), "deploy", "--dry-run")
	if status != 0 {
		t.Fatalf("status = %d\n%s", status, errOut)
	}
	for _, p := range AllPairs() {
		if !strings.Contains(out, "# "+p.Name()+"\n") {
			t.Errorf("the dry run has no command for %s", p.Name())
		}
	}
}

func TestMenuAllDpgTakesEveryDpgOfOneRole(t *testing.T) {
	answer := "1\n" + itoa(len(DpgNames())+1) + "\n"
	status, out, errOut := run(t, tty(t.TempDir(), answer), "deploy", "--dry-run")
	if status != 0 {
		t.Fatalf("status = %d\n%s", status, errOut)
	}
	for _, p := range PairsForRole(Roles()[0]) {
		if !strings.Contains(out, "# "+p.Name()+"\n") {
			t.Errorf("the dry run has no command for %s", p.Name())
		}
	}
	if strings.Contains(out, "# "+Pair{Role: Roles()[1], Dpg: Dpgs()[0]}.Name()+"\n") {
		t.Error("one role took a pair of another role")
	}
}

func TestMenuAllRoleWithADpgFlagTakesThatStack(t *testing.T) {
	answer := itoa(len(RoleNames())+1) + "\n"
	status, out, errOut := run(t, tty(t.TempDir(), answer), "deploy", "--dpg", "inji", "--dry-run")
	if status != 0 {
		t.Fatalf("status = %d\n%s", status, errOut)
	}
	for _, p := range PairsForDpg(Dpgs()[1]) {
		if !strings.Contains(out, "# "+p.Name()+"\n") {
			t.Errorf("the dry run has no command for %s", p.Name())
		}
	}
}

func TestNonInteractiveKeepsTheError(t *testing.T) {
	for _, args := range [][]string{
		{"deploy", "--dry-run"},
		{"status"},
		{"down"},
		{"ports"},
		{"doctor"},
		{"images", "build"},
		{"setup"},
	} {
		status, _, errOut := run(t, Environment{Root: t.TempDir()}, args...)
		if status == 0 {
			t.Errorf("%v passed with no role", args)
		}
		if !strings.Contains(errOut, "--all") {
			t.Errorf("%v error = %q", args, errOut)
		}
	}
}

func TestNonInteractiveFlagStopsTheMenu(t *testing.T) {
	env := tty(t.TempDir(), "1\n1\n")
	status, out, errOut := run(t, env, "deploy", "--non-interactive", "--dry-run")
	if status == 0 {
		t.Fatalf("the run passed\n%s", out)
	}
	if strings.Contains(out, RoleQuestion) {
		t.Error("--non-interactive asked a question")
	}
	if !strings.Contains(errOut, "--all") {
		t.Errorf("error = %q", errOut)
	}
}

func TestMenuStopsOnAClosedInput(t *testing.T) {
	status, _, errOut := run(t, tty(t.TempDir(), ""), "deploy", "--dry-run")
	if status == 0 {
		t.Fatal("a closed input passed")
	}
	if !strings.Contains(errOut, "input ended") {
		t.Errorf("error = %q", errOut)
	}
}

func TestDoctorSuggestAsksNothing(t *testing.T) {
	status, out, errOut := run(t, tty(t.TempDir(), ""), "doctor", "--suggest")
	if status != 0 {
		t.Fatalf("status = %d\n%s", status, errOut)
	}
	if strings.Contains(out, RoleQuestion) || strings.Contains(out, DpgQuestion) {
		t.Errorf("--suggest asked a question\n%s", out)
	}
}

func TestDpgBootstrapAsksTheDpgAndTheRole(t *testing.T) {
	env := tty(t.TempDir(), "1\n1\n")
	_, out, _ := run(t, env, "dpg", "bootstrap")
	if !strings.Contains(out, DpgQuestion) || !strings.Contains(out, RoleQuestion) {
		t.Errorf("output = %q", out)
	}
}

func TestDpgBootstrapKeepsTheRoleFlag(t *testing.T) {
	env := tty(t.TempDir(), "1\n")
	_, out, _ := run(t, env, "dpg", "bootstrap", "--role", "verifier")
	if strings.Contains(out, RoleQuestion) {
		t.Error("the run asked for a role that the flag named")
	}
	if !strings.Contains(out, DpgQuestion) {
		t.Errorf("output = %q", out)
	}
}

func TestDpgBootstrapNamesTheDpgWithNoTerminal(t *testing.T) {
	status, _, errOut := run(t, Environment{Root: t.TempDir()}, "dpg", "bootstrap", "--non-interactive")
	if status == 0 {
		t.Fatal("a run with no DPG passed")
	}
	if !strings.Contains(errOut, "name the DPG") {
		t.Errorf("error = %q", errOut)
	}
}

func TestPairsForRoleListsEveryDpgInProtoOrder(t *testing.T) {
	got := PairsForRole(Roles()[0])
	if len(got) != len(Dpgs()) {
		t.Fatalf("got %d pairs", len(got))
	}
	for i, d := range Dpgs() {
		if got[i].Dpg != d {
			t.Errorf("pair %d is %s", i, got[i].Name())
		}
	}
}

func TestIsTTYDefaultsToFalseWhenTheCallerGivesTheInput(t *testing.T) {
	env := Environment{In: strings.NewReader("")}.withDefaults()
	if env.IsTTY() {
		t.Error("a supplied input reads as a terminal")
	}
	// A run that supplies no input reads the real standard input. The
	// test suite runs with a pipe, so that is not a terminal either.
	real := Environment{}.withDefaults()
	if real.IsTTY() != stdinIsTerminal() {
		t.Error("the default does not read the standard input")
	}
}
