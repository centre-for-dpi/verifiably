// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// markedRoot builds a directory that holds the marker file.
func markedRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, RepoMarker), []byte("# ADR\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestFindRepoRootWalksUp(t *testing.T) {
	root := markedRoot(t)
	deep := filepath.Join(root, "vca", "internal", "cli")
	if err := os.MkdirAll(deep, 0o750); err != nil {
		t.Fatal(err)
	}
	got, ok := FindRepoRoot(deep)
	if !ok {
		t.Fatal("the root was not found")
	}
	if got != root {
		t.Errorf("root = %q, want %q", got, root)
	}
}

func TestFindRepoRootFindsNothing(t *testing.T) {
	if _, ok := FindRepoRoot(t.TempDir()); ok {
		t.Error("a directory with no marker must find nothing")
	}
}

func TestFindRepoRootSkipsADirectoryMarker(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, RepoMarker), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, ok := FindRepoRoot(root); ok {
		t.Error("a directory named ADR.md is not the marker")
	}
}

func TestResolveRepoRootOrder(t *testing.T) {
	flagRoot := markedRoot(t)
	envRoot := markedRoot(t)
	walkRoot := markedRoot(t)
	getenv := func(name string) string {
		if name == RepoEnv {
			return envRoot
		}
		return ""
	}
	got, err := ResolveRepoRoot(flagRoot, getenv, walkRoot)
	if err != nil || got != flagRoot {
		t.Errorf("flag: got %q, %v", got, err)
	}
	got, err = ResolveRepoRoot("", getenv, walkRoot)
	if err != nil || got != envRoot {
		t.Errorf("environment: got %q, %v", got, err)
	}
	got, err = ResolveRepoRoot("", func(string) string { return "" }, walkRoot)
	if err != nil || got != walkRoot {
		t.Errorf("walk: got %q, %v", got, err)
	}
	got, err = ResolveRepoRoot("", nil, t.TempDir())
	if err != nil || got != "." {
		t.Errorf("fallback: got %q, %v", got, err)
	}
}

func TestResolveRepoRootRejectsADirectoryWithNoMarker(t *testing.T) {
	dir := t.TempDir()
	_, err := ResolveRepoRoot(dir, nil, dir)
	if err == nil || !strings.Contains(err.Error(), RepoMarker) {
		t.Errorf("err = %v", err)
	}
	_, err = ResolveRepoRoot("", func(string) string { return dir }, dir)
	if err == nil || !strings.Contains(err.Error(), RepoEnv) {
		t.Errorf("err = %v", err)
	}
}

func TestCliFindsTheRepositoryRootFromAnyDirectory(t *testing.T) {
	root := markedRoot(t)
	pair := issuerPair()
	dir := filepath.Join(root, "deploy", pair.Name())
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, EnvFileName), []byte("VCA_ROLE=issuer\n"))
	deep := filepath.Join(root, "vca", "services")
	if err := os.MkdirAll(deep, 0o750); err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	env := Environment{
		Getwd:  func() (string, error) { return deep, nil },
		Getenv: func(string) string { return "" },
		Run:    rec.run,
	}
	status, out, errOut := run(t, env, "deploy", "--role", "issuer", "--dpg", "waltid")
	if status != 0 {
		t.Fatalf("status = %d, out = %s, err = %s", status, out, errOut)
	}
	if len(rec.calls) != 1 || !strings.Contains(strings.Join(rec.calls[0], " "), ComposePath(root)) {
		t.Errorf("calls = %v", rec.calls)
	}
}

func TestRepoFlagBeatsTheWorkingDirectory(t *testing.T) {
	root := markedRoot(t)
	status, out, errOut := run(t, Environment{
		Getwd:  func() (string, error) { return t.TempDir(), nil },
		Getenv: func(string) string { return "" },
	}, "deploy", "--repo", root, "--role", "issuer", "--dpg", "waltid", "--dry-run")
	if status != 0 {
		t.Fatalf("status = %d, err = %s", status, errOut)
	}
	if !strings.Contains(out, ComposePath(root)) {
		t.Errorf("out has no %s", ComposePath(root))
	}
}

func TestRepoFlagRejectsABadPath(t *testing.T) {
	status, _, errOut := run(t, Environment{
		Getwd:  func() (string, error) { return t.TempDir(), nil },
		Getenv: func(string) string { return "" },
	}, "deploy", "--repo", t.TempDir(), "--role", "issuer", "--dpg", "waltid", "--dry-run")
	if status == 0 || !strings.Contains(errOut, RepoMarker) {
		t.Errorf("status = %d, err = %s", status, errOut)
	}
}

func TestBadWorkingDirectoryFails(t *testing.T) {
	status, _, errOut := run(t, Environment{
		Getwd:  func() (string, error) { return "", os.ErrPermission },
		Getenv: func(string) string { return "" },
	}, "ports", "--role", "issuer", "--dpg", "waltid")
	if status == 0 || !strings.Contains(errOut, "working directory") {
		t.Errorf("status = %d, err = %s", status, errOut)
	}
}
