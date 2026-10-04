// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// findingsOf returns the lines of the failed checks.
func findingsOf(checks []Check) []string {
	var out []string
	for _, c := range failed(checks) {
		out = append(out, c.Line())
	}
	return out
}

// TestDoctorChecksThePeerIdentities is ADR-075 for vca doctor: a missing
// authority, a missing or stale identity file, and a key file that the
// container user cannot read each give one line with the fix command.
func TestDoctorChecksThePeerIdentities(t *testing.T) {
	deploy, pairs := writeOldDeployment(t)
	checks := PeerChecks(deploy, pairs)
	lines := findingsOf(checks)
	want := 1 + len(ServicesFor(pairs[0])) + len(ServicesFor(pairs[1])) + 1 // the authority, every service, the landing
	if len(lines) != want {
		t.Fatalf("%d findings, want %d:\n%s", len(lines), want, strings.Join(lines, "\n"))
	}
	if !strings.Contains(lines[0], "deploy/peer/authority.pem") && !strings.Contains(lines[0], PeerAuthorityFile) {
		t.Errorf("the first finding is not the authority: %s", lines[0])
	}
	for _, l := range lines {
		if !strings.Contains(l, "fix: vca dpg upgrade-secrets") {
			t.Errorf("a finding names no fix command: %s", l)
		}
	}
	if _, err := UpgradePeerIdentities(PeerUpgradeOptions{Deploy: deploy, Random: rand.Reader, Out: io.Discard}); err != nil {
		t.Fatal(err)
	}
	checks = PeerChecks(deploy, pairs)
	if current := findingsOf(checks); len(current) != 0 {
		t.Fatalf("a current deployment has findings:\n%s", strings.Join(current, "\n"))
	}
	if len(checks) != 1 || !checks[0].OK {
		t.Errorf("a current deployment gives %+v, want one passing line", checks)
	}
	// A key file that only the operator reads.
	key := filepath.Join(OutputDir(deploy, pairs[0]), PeerKeyFile("issuance"))
	if err := os.Chmod(key, 0o600); err != nil {
		t.Fatal(err)
	}
	// A host port that moved makes the identity stale.
	if err := os.WriteFile(filepath.Join(OutputDir(deploy, pairs[1]), EnvFileName), []byte("VCA_ROLE=x\nVCA_HOST_PORT_ADMIN=19998\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A missing identity file.
	if err := os.Remove(filepath.Join(OutputDir(deploy, pairs[0]), PeerFile("schema-registry"))); err != nil {
		t.Fatal(err)
	}
	lines = findingsOf(PeerChecks(deploy, pairs))
	text := strings.Join(lines, "\n")
	if len(lines) != 3 {
		t.Fatalf("want three findings:\n%s", text)
	}
	for _, want := range []string{"chmod 0644 " + key, "schema-registry", "missing", "admin", "stale"} {
		if !strings.Contains(text, want) {
			t.Errorf("the findings name no %q:\n%s", want, text)
		}
	}
	// A pair with no .env yet has nothing to check: setup comes first.
	fresh := t.TempDir()
	if checks := PeerChecks(fresh, pairs); len(checks) != 0 {
		t.Errorf("a host before setup gets %+v", checks)
	}
}

// TestDoctorRunsThePeerChecks puts the peer checks in the report of vca
// doctor once a deploy directory is set.
func TestDoctorRunsThePeerChecks(t *testing.T) {
	deploy, pairs := writeOldDeployment(t)
	var out strings.Builder
	err := Doctor(DoctorOptions{Pairs: pairs, Deploy: deploy, Probe: healthyProbe(), Out: &out})
	if err == nil || !strings.Contains(out.String(), "peer authority") || !strings.Contains(out.String(), "fix: vca dpg upgrade-secrets") {
		t.Errorf("Doctor = %v:\n%s", err, out.String())
	}
}
