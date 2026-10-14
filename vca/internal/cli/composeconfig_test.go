// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestComposeReadsTheConfigurationOfEveryPair runs what vca deploy runs
// first, docker compose config, against a deploy tree that a full setup
// wrote. Compose interpolates every included stack file whatever profile
// runs, so a variable that one stack requires and setup does not write
// fails the deploy of every pair. The test needs the compose plugin and
// no daemon; it skips where the plugin is absent.
func TestComposeReadsTheConfigurationOfEveryPair(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not on PATH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "compose", "version").Run(); err != nil {
		t.Skip("the compose plugin is not available:", err)
	}
	root := t.TempDir()
	// The compose files and the stack files as the checkout holds them.
	src := filepath.Join("..", "..", "..", "deploy", "vca")
	if err := copyTree(src, filepath.Join(root, "deploy", "vca")); err != nil {
		t.Fatal(err)
	}
	status, out, errOut := run(t, Environment{Root: root}, "setup", "--all", "--yes", "--non-interactive",
		"--domain", "labs.example.org",
		"--set", "VCA_CREDEBL_PLATFORM_ADMIN_EMAIL=admin@labs.example.org",
		"--set", "VCA_CREDEBL_INDY_LEDGERS=bcovrin:testnet")
	if status != 0 {
		t.Fatalf("setup --all: status %d\n%s%s", status, out, errOut)
	}
	for _, p := range AllPairs() {
		args := ComposeArgs(root, p, []string{"config", "--format", "json"})
		cmd := exec.CommandContext(ctx, "docker", args...) // #nosec G204 -- the test builds the arguments
		cmd.Env = append(os.Environ(), "DOCKER_HOST=unix:///nonexistent/docker.sock")
		said, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("%s: docker compose config: %v\n%s", p.Name(), err, lastLines(string(said), 8))
		}
	}
}

// copyTree copies a directory of plain files.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		data, err := os.ReadFile(path) // #nosec G304 -- the test reads its own checkout
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	})
}
