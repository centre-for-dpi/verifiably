// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// P7-04: the doctor, the floors and the documents agree with the stack
// files and the catalogue.

// TestDoctorChecksTheVerifier2Port: a wallet fetches the requests of
// verifier-api2 on host port 17004, so the doctor checks that port for a
// walt.id verifier pair and for no other pair.
func TestDoctorChecksTheVerifier2Port(t *testing.T) {
	verifier := Pair{Role: commonv1.Role_ROLE_VERIFIER, Dpg: configv1.Dpg_DPG_WALTID}
	want := DpgPort{Container: "waltid-verifier-api2", Host: 17004, Env: "WALTID_VERIFIER2_HOST_PORT", Port: 7004}
	if !slices.Contains(DpgHostPorts(verifier), want) {
		t.Errorf("ports = %v, want %v", DpgHostPorts(verifier), want)
	}
	for _, p := range AllPairs() {
		if p != verifier && slices.Contains(DpgHostPorts(p), want) {
			t.Errorf("%s checks the verifier-api2 port", p.Name())
		}
	}
	probe := healthyProbe()
	probe.busyPorts = map[int]bool{17004: true}
	var out strings.Builder
	if err := Doctor(DoctorOptions{Pairs: []Pair{verifier}, Probe: probe, Out: &out}); !errors.Is(err, ErrDoctorFailed) {
		t.Fatalf("err = %v", err)
	}
	for _, text := range []string{"port 17004", "waltid-verifier-api2: another program holds it", "WALTID_VERIFIER2_HOST_PORT"} {
		if !strings.Contains(out.String(), text) {
			t.Errorf("the report lacks %q:\n%s", text, out.String())
		}
	}
	// The stack file publishes the port the doctor checks.
	data, err := os.ReadFile(filepath.Join(repoRoot(), "deploy", "vca", "dpg", "waltid.yaml")) // #nosec G304 -- a fixed test path
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "${WALTID_VERIFIER2_HOST_PORT:-17004}:7004") {
		t.Error("the walt.id stack file does not publish host port 17004")
	}
}

// TestFloorOfAVerifierCountsVerifierAuth: the verifier floor counts the
// sign in service of the verifier staff (ADR-036).
func TestFloorOfAVerifierCountsVerifierAuth(t *testing.T) {
	for _, d := range Dpgs() {
		p := Pair{Role: commonv1.Role_ROLE_VERIFIER, Dpg: d}
		names := make([]string, 0)
		for _, s := range ServicesFor(p) {
			names = append(names, s.Name)
		}
		if !slices.Contains(names, "verifier-auth") || Floor(p).Services != len(names) {
			t.Errorf("%s: services %v, floor counts %d", p.Name(), names, Floor(p).Services)
		}
	}
}

// oneLine collapses the white space of a text, so a sentence that a
// document wraps still matches.
func oneLine(text string) string { return strings.Join(strings.Fields(text), " ") }

// TestDocsHoldTheFloorsOfTheCode keeps every floor figure of the
// documents equal to the code: the pair range and the role table of the
// getting started guide, the stack table and the sum of --all in both
// guides, and the stack sentence of the CLI document.
func TestDocsHoldTheFloorsOfTheCode(t *testing.T) {
	read := func(name string) string {
		data, err := os.ReadFile(filepath.Join(repoRoot(), "vca", "docs", name)) // #nosec G304 -- a fixed test path
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	started, deploy, cli := read("getting-started.md"), read("deploy.md"), read("cli.md")
	for name, text := range map[string]string{
		"the pair range":  PairFloorRange(),
		"the role table":  RoleFloorTable(),
		"the stack table": StackFloorTable(),
		"the sum of all":  AllFloorSentence(),
	} {
		if !strings.Contains(oneLine(started), oneLine(text)) {
			t.Errorf("docs/getting-started.md does not hold %s:\n%s", name, text)
		}
	}
	for name, text := range map[string]string{"the stack table": StackFloorTable(), "the sum of all": AllFloorSentence()} {
		if !strings.Contains(oneLine(deploy), oneLine(text)) {
			t.Errorf("docs/deploy.md does not hold %s:\n%s", name, text)
		}
	}
	if !strings.Contains(oneLine(cli), StackFloorSentence()) {
		t.Errorf("docs/cli.md does not hold %q", StackFloorSentence())
	}
}
