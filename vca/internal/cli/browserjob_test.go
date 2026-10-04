// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// pinnedAction matches an action pinned to a commit with its version.
var pinnedAction = regexp.MustCompile(`^[\w.-]+/[\w.-]+@[0-9a-f]{40} # v\d+(\.\d+)*$`)

// TestTheBrowserJobDrivesWalletJS is ADR-004 decision 6: vca-ci runs
// the Playwright test of wallet.js in Chromium on every pull request,
// and every action that the job adds is pinned to a commit.
func TestTheBrowserJobDrivesWalletJS(t *testing.T) {
	ci := readText(t, filepath.Join(repoRoot(), ".github", "workflows", "vca-ci.yml"))
	_, job, ok := strings.Cut(ci, "\n  browser:\n")
	if !ok {
		t.Fatal("vca-ci has no browser job")
	}
	if next := regexp.MustCompile(`\n  [a-z-]+:\n`).FindStringIndex(job); next != nil {
		job = job[:next[0]]
	}
	for _, want := range []string{
		"npx playwright install --with-deps chromium",
		"VCA_PLAYWRIGHT: '1'",
		"-run TestWalletScriptInChromium",
	} {
		if !strings.Contains(job, want) {
			t.Errorf("the browser job does not hold %q", want)
		}
	}
	for _, line := range strings.Split(ci, "\n") {
		_, ref, found := strings.Cut(strings.TrimSpace(line), "uses: ")
		if !found {
			continue
		}
		if !pinnedAction.MatchString(ref) {
			t.Errorf("the action %q is not pinned to a commit with its version in a comment", ref)
		}
	}
}
