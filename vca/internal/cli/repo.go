// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"
)

// RepoMarker is the file that marks the repository root. The tool reads
// deploy/vca/compose.yaml under that root, so the operator can run vca
// from any directory (ADR-008 decision 1).
const RepoMarker = "ADR.md"

// RepoEnv is the variable that names the repository root.
const RepoEnv = "VCA_REPO"

// FindRepoRoot walks up from start and returns the first directory that
// holds the marker file. The second result is false when no parent holds
// it.
func FindRepoRoot(start string) (string, bool) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", false
	}
	for {
		if hasMarker(dir) {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// hasMarker reports whether one directory holds the marker file.
func hasMarker(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, RepoMarker))
	return err == nil && !info.IsDir()
}

// ResolveRepoRoot returns the repository root of one run. The order is
// the --repo flag, the VCA_REPO variable, and then a walk up from the
// working directory. The current directory is the last answer.
func ResolveRepoRoot(flag string, getenv func(string) string, wd string) (string, error) {
	if flag != "" {
		return checkRepoRoot(flag, "--repo")
	}
	if getenv != nil {
		if value := getenv(RepoEnv); value != "" {
			return checkRepoRoot(value, RepoEnv)
		}
	}
	if root, ok := FindRepoRoot(wd); ok {
		return root, nil
	}
	return ".", nil
}

// checkRepoRoot reports a named directory that holds no marker file.
func checkRepoRoot(dir, source string) (string, error) {
	if hasMarker(dir) {
		return dir, nil
	}
	return "", fmt.Errorf("%s %s: no %s is there; name the repository root",
		source, dir, RepoMarker)
}
