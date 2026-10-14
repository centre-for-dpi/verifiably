// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// TestDoctorNamesAMissingStackEnv is ADR-055 for vca doctor: a deploy
// tree from before the generated stack secrets has the .env of each pair
// but not deploy/<dpg>/.env, which compose requires. The doctor names
// the file and the command that writes it.
func TestDoctorNamesAMissingStackEnv(t *testing.T) {
	t.Parallel()
	deploy := t.TempDir()
	pairs := []Pair{issuerPair()}
	if err := os.MkdirAll(filepath.Join(deploy, pairs[0].Name()), 0o750); err != nil {
		t.Fatal(err)
	}
	checks := StackEnvChecks(deploy, pairs)
	lines := findingsOf(checks)
	if len(lines) != 1 {
		t.Fatalf("%d findings, want one:\n%s", len(lines), strings.Join(lines, "\n"))
	}
	for _, want := range []string{StackEnvFile(pairs[0].Dpg), "vca setup"} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("finding %q lacks %q", lines[0], want)
		}
	}
	if err := os.MkdirAll(filepath.Join(deploy, filepath.Dir(StackEnvFile(configv1.Dpg_DPG_WALTID))), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deploy, StackEnvFile(pairs[0].Dpg)), []byte("WALTID_DB_PASSWORD=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	checks = StackEnvChecks(deploy, pairs)
	if current := findingsOf(checks); len(current) != 0 {
		t.Fatalf("a complete deployment has findings:\n%s", strings.Join(current, "\n"))
	}
	if len(checks) != 1 || !checks[0].OK {
		t.Errorf("a complete deployment gives %+v, want one passing line", checks)
	}
}
