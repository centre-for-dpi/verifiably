// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

// injiIssuerPair returns the issuer and Inji pair.
func injiIssuerPair(t *testing.T) Pair {
	t.Helper()
	for _, p := range AllPairs() {
		if p.Name() == "issuer-inji" {
			return p
		}
	}
	t.Fatal("no issuer-inji pair")
	return Pair{}
}

const sampleComposeConfig = `{
  "name": "vca",
  "services": {
    "inji-certify": {"container_name": "inji-certify", "image": "injistack/inji-certify-with-plugins:0.14.0"},
    "inji-keycloak": {"container_name": "inji-keycloak"},
    "issuer-inji-issuance": {"container_name": "issuer-inji-issuance"},
    "unnamed": {"image": "x"}
  }
}`

const samplePs = "inji-certify\tinji-legacy\n" +
	"inji-keycloak\tvca\n" +
	"/by-hand\t\n" +
	"\n" +
	"issuer-inji-issuance\tvca\n"

func TestComposeContainerNames(t *testing.T) {
	got, err := ComposeContainerNames(sampleComposeConfig)
	if err != nil {
		t.Fatal(err)
	}
	want := "inji-certify inji-keycloak issuer-inji-issuance"
	if strings.Join(got, " ") != want {
		t.Errorf("got %q, want %q", strings.Join(got, " "), want)
	}
	if _, err := ComposeContainerNames("not json"); err == nil {
		t.Error("bad JSON passed")
	}
}

func TestParseContainerOwners(t *testing.T) {
	got := ParseContainerOwners(samplePs)
	if len(got) != 4 {
		t.Fatalf("got %d containers: %v", len(got), got)
	}
	if got["inji-certify"] != "inji-legacy" {
		t.Errorf("inji-certify: got %q", got["inji-certify"])
	}
	if got["by-hand"] != "" {
		t.Errorf("by-hand: got %q", got["by-hand"])
	}
}

func TestContainerConflicts(t *testing.T) {
	names := []string{"inji-certify", "inji-keycloak", "by-hand", "absent"}
	got := ContainerConflicts(names, ParseContainerOwners(samplePs))
	if len(got) != 2 {
		t.Fatalf("got %d conflicts: %v", len(got), got)
	}
	if got[0].Name != "inji-certify" || got[0].Project != "inji-legacy" {
		t.Errorf("first: %+v", got[0])
	}
	if got[1].Name != "by-hand" || got[1].Project != "" {
		t.Errorf("second: %+v", got[1])
	}
}

func TestConflictMessage(t *testing.T) {
	p := injiIssuerPair(t)
	one := ConflictMessage(p, []ContainerConflict{{Name: "inji-certify", Project: "old"}})
	for _, want := range []string{
		"deploy issuer-inji: 1 container name is in use",
		"inji-certify  held by compose project old",
		"docker rm -f inji-certify",
	} {
		if !strings.Contains(one, want) {
			t.Errorf("message has no %q:\n%s", want, one)
		}
	}
	two := ConflictMessage(p, []ContainerConflict{{Name: "a"}, {Name: "b", Project: "x"}})
	for _, want := range []string{
		"2 container names are in use",
		"a  held by a container that compose did not start",
		"docker rm -f a b",
	} {
		if !strings.Contains(two, want) {
			t.Errorf("message has no %q:\n%s", want, two)
		}
	}
}

// outputScript answers docker commands from a fixed table.
type outputScript struct {
	config    string
	configErr error
	ps        string
	psErr     error
	calls     [][]string
}

func (s *outputScript) run(_ context.Context, name string, args []string) (string, error) {
	s.calls = append(s.calls, append([]string{name}, args...))
	if len(args) > 1 && args[0] == "compose" {
		return s.config, s.configErr
	}
	return s.ps, s.psErr
}

func TestDeployStopsOnAContainerNameConflict(t *testing.T) {
	p := injiIssuerPair(t)
	root := deployRoot(t, p)
	rec := &recorder{}
	script := &outputScript{config: sampleComposeConfig, ps: samplePs}
	var out bytes.Buffer
	err := Deploy(context.Background(), DeployOptions{
		Root: root, Pairs: []Pair{p}, Out: &out, Run: rec.run, Output: script.run,
	})
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("got %v, want a ConflictError", err)
	}
	if len(conflict.Conflicts) != 1 || conflict.Conflicts[0].Name != "inji-certify" {
		t.Errorf("conflicts: %+v", conflict.Conflicts)
	}
	if !strings.Contains(err.Error(), "docker rm -f inji-certify") {
		t.Errorf("no fix in %q", err.Error())
	}
	if len(rec.calls) != 0 {
		t.Errorf("compose up ran %d times after a conflict", len(rec.calls))
	}
	if len(script.calls) != 2 {
		t.Fatalf("got %d docker calls", len(script.calls))
	}
	config := strings.Join(script.calls[0], " ")
	for _, want := range []string{"--project-name vca", "--profile issuer-inji", "config --format json"} {
		if !strings.Contains(config, want) {
			t.Errorf("config call has no %q: %s", want, config)
		}
	}
	if ps := strings.Join(script.calls[1], " "); !strings.Contains(ps, "ps --all --format") {
		t.Errorf("ps call: %s", ps)
	}
}

func TestDeployRunsWhenNoNameConflicts(t *testing.T) {
	p := injiIssuerPair(t)
	root := deployRoot(t, p)
	rec := &recorder{}
	script := &outputScript{config: sampleComposeConfig, ps: "inji-keycloak\tvca\nother\tsomething\n"}
	var out bytes.Buffer
	err := Deploy(context.Background(), DeployOptions{
		Root: root, Pairs: []Pair{p}, Out: &out, Run: rec.run, Output: script.run, Build: true,
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if len(rec.calls) != 1 {
		t.Fatalf("compose up ran %d times", len(rec.calls))
	}
	if config := strings.Join(script.calls[0], " "); !strings.Contains(config, "compose.build.yaml") {
		t.Errorf("a build run reads the configuration without the build file: %s", config)
	}
}

func TestDeployReportsAFailedConfigOrPs(t *testing.T) {
	p := injiIssuerPair(t)
	root := deployRoot(t, p)
	boom := errors.New("boom")
	cases := map[string]*outputScript{
		"config":   {configErr: boom},
		"bad json": {config: "{"},
		"ps":       {config: sampleComposeConfig, psErr: boom},
	}
	for name, script := range cases {
		t.Run(name, func(t *testing.T) {
			rec := &recorder{}
			err := Deploy(context.Background(), DeployOptions{
				Root: root, Pairs: []Pair{p}, Out: &bytes.Buffer{}, Run: rec.run, Output: script.run,
			})
			if err == nil {
				t.Fatal("no error")
			}
			if !strings.HasPrefix(err.Error(), "deploy issuer-inji: ") {
				t.Errorf("got %q", err.Error())
			}
			if len(rec.calls) != 0 {
				t.Error("compose up ran after a failed check")
			}
		})
	}
}

func TestStatusAndDownSkipTheNameCheck(t *testing.T) {
	p := injiIssuerPair(t)
	root := deployRoot(t, p)
	script := &outputScript{configErr: errors.New("must not run")}
	for _, fn := range []func(context.Context, DeployOptions) error{Status, Down} {
		rec := &recorder{}
		err := fn(context.Background(), DeployOptions{
			Root: root, Pairs: []Pair{p}, Out: &bytes.Buffer{}, Run: rec.run, Output: script.run,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(script.calls) != 0 {
		t.Errorf("status or down read the compose configuration %d times", len(script.calls))
	}
}
