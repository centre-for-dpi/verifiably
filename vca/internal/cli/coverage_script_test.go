// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runCoverage runs hack/coverage.sh on a fixed output of go test.
func runCoverage(t *testing.T, output string) (string, error) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "out.txt")
	if err := os.WriteFile(file, []byte(output), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", filepath.Join(repoRoot(), "vca", "hack", "coverage.sh"), "90") // #nosec G204 -- a fixed script of the tree
	cmd.Env = append(os.Environ(), "GO_TEST_CMD=cat "+file)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestCoverageGateReadsATestOnlyPackage: a package that holds tests only,
// such as the walkthrough, reports no statements. The gate skips it and
// still checks every other package.
func TestCoverageGateReadsATestOnlyPackage(t *testing.T) {
	good := "ok  \tgithub.com/x/services/a\t0.1s\tcoverage: 95.0% of statements\n" +
		"ok  \tgithub.com/x/services/walkthrough\t3.7s\tcoverage: [no statements]\n"
	if out, err := runCoverage(t, good); err != nil {
		t.Fatalf("the gate failed on a test only package: %v\n%s", err, out)
	}
	low := good + "ok  \tgithub.com/x/services/b\t0.1s\tcoverage: 80.0% of statements\n"
	out, err := runCoverage(t, low)
	if err == nil || !strings.Contains(out, "FAIL: github.com/x/services/b coverage 80.0% below 90%") {
		t.Fatalf("the gate passed a package below the floor: %v\n%s", err, out)
	}
}
