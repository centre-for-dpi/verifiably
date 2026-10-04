// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// pinnedWorkflows are the workflows of VCA whose actions run with the
// token of the repository.
var pinnedWorkflows = []string{"vca-ci.yml", "vca-release.yml", "vca-nightly.yml"}

// TestEveryWorkflowActionIsPinnedToACommit keeps the rule of
// docs/ci.md, "Pinned actions": a tag of an action can move, a commit
// cannot. So every uses line of the VCA workflows names a full commit,
// with the version of the tag in a comment.
func TestEveryWorkflowActionIsPinnedToACommit(t *testing.T) {
	uses := regexp.MustCompile(`^\s*(?:- )?uses:\s*(.+)$`)
	seen := 0
	for _, name := range pinnedWorkflows {
		text := readText(t, filepath.Join(repoRoot(), ".github", "workflows", name))
		for i, line := range strings.Split(text, "\n") {
			m := uses.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			seen++
			if !pinnedAction.MatchString(strings.TrimSpace(m[1])) {
				t.Errorf("%s:%d: %q is not a full commit with its version in a comment", name, i+1, strings.TrimSpace(m[1]))
			}
		}
	}
	if seen < 30 {
		t.Fatalf("the workflows hold %d uses lines; the test reads the wrong files", seen)
	}
}
