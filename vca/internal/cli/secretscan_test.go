// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestSecretScanScript runs the cases of hack/secret-scan_test.sh, so
// the test gate covers the key=value rule of the secret scan as well
// as the Go code (ADR-055 decision 5). Each case is a small git
// repository with one tracked file.
func TestSecretScanScript(t *testing.T) {
	script := filepath.Join(repoRoot(), "vca", "hack", "secret-scan_test.sh")
	cmd := exec.CommandContext(context.Background(), "sh", script) // #nosec G204 -- a fixed script of the repository
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", script, err, out)
	}
	t.Logf("%s", out)
}
