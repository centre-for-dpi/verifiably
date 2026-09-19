// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/internal/migrate"
)

// legacyStateDir writes a small legacy state directory.
func legacyStateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	items := []migrate.LegacyIssued{{
		ID: "vc-1", SchemaID: "schema-a", Format: "vc+sd-jwt", IssuerDpg: "waltid",
		SubjectFields: map[string]string{"id": "holder-1", "fullName": "A Person"},
		IssuedAt:      time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
		StatusList:    &migrate.LegacyStatusRef{Type: "bitstring", ListID: "bitstring-v1", Index: 1},
	}}
	data, err := json.Marshal(items)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	writeFile(t, filepath.Join(dir, migrate.IssuedLogName), data)
	list, err := json.Marshal(map[string]any{"size": 32, "nextFree": 2, "bits": "AAAAAA"})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	writeFile(t, filepath.Join(dir, "status-list-bitstring-v1.json"), list)
	return dir
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// runCLI runs the command tree and returns the output.
func runCLI(t *testing.T, env Environment, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	env.Out = &out
	env.ErrOut = &out
	env.Args = args
	root := NewRootCommand(env)
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func TestMigrateExportFromStateDir(t *testing.T) {
	dir := legacyStateDir(t)
	out := filepath.Join(t.TempDir(), "migration")
	text, err := runCLI(t, Environment{Root: t.TempDir()}, "migrate", "export",
		"--from-state-dir", dir, "--out", out, "--salt", "pepper", "--keep-claim", "fullName",
		"--status-base-url", "https://status.example")
	if err != nil {
		t.Fatalf("export: %v (%s)", err, text)
	}
	if !strings.Contains(text, "sessions and caches are not migrated") {
		t.Fatalf("output: %s", text)
	}
	bundle, err := migrate.Read(out)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(bundle.Issued.Entries) != 1 || len(bundle.Bitstring) != 1 {
		t.Fatalf("bundle: %+v", bundle.Counts())
	}
	if _, err := runCLI(t, Environment{Root: t.TempDir()}, "migrate", "export",
		"--from-state-dir", dir, "--out", out, "--salt", "pepper"); !errors.Is(err, migrate.ErrExists) {
		t.Fatalf("second run: %v", err)
	}
	if _, err := runCLI(t, Environment{Root: t.TempDir()}, "migrate", "export",
		"--from-state-dir", dir, "--out", out, "--salt", "pepper", "--force"); err != nil {
		t.Fatalf("force: %v", err)
	}
}

func TestMigrateExportSaltSources(t *testing.T) {
	dir := legacyStateDir(t)
	saltFile := filepath.Join(t.TempDir(), "salt")
	writeFile(t, saltFile, []byte("pepper\n"))
	if _, err := runCLI(t, Environment{Root: t.TempDir()}, "migrate", "export",
		"--from-state-dir", dir, "--out", filepath.Join(t.TempDir(), "a"), "--salt-file", saltFile); err != nil {
		t.Fatalf("salt file: %v", err)
	}
	empty := filepath.Join(t.TempDir(), "empty")
	writeFile(t, empty, []byte("  "))
	if _, err := runCLI(t, Environment{Root: t.TempDir()}, "migrate", "export",
		"--from-state-dir", dir, "--out", filepath.Join(t.TempDir(), "b"), "--salt-file", empty); err == nil {
		t.Fatal("want an error for an empty salt file")
	}
	if _, err := runCLI(t, Environment{Root: t.TempDir()}, "migrate", "export",
		"--from-state-dir", dir, "--out", filepath.Join(t.TempDir(), "c"),
		"--salt-file", filepath.Join(t.TempDir(), "gone")); err == nil {
		t.Fatal("want an error for a missing salt file")
	}
	env := Environment{Root: t.TempDir(), Getenv: func(name string) string {
		if name == SaltEnv {
			return "pepper"
		}
		return ""
	}}
	if _, err := runCLI(t, env, "migrate", "export",
		"--from-state-dir", dir, "--out", filepath.Join(t.TempDir(), "d")); err != nil {
		t.Fatalf("environment salt: %v", err)
	}
	if _, err := runCLI(t, Environment{Root: t.TempDir(), Getenv: func(string) string { return "" }},
		"migrate", "export", "--from-state-dir", dir, "--out", filepath.Join(t.TempDir(), "e")); err == nil {
		t.Fatal("want an error when no source holds the salt")
	}
}

func TestMigrateExportFlagErrors(t *testing.T) {
	env := Environment{Root: t.TempDir()}
	cases := [][]string{
		{"migrate", "export", "--salt", "s", "--out", "x"},
		{"migrate", "export", "--salt", "s", "--out", "x", "--from-pg", "dsn", "--from-state-dir", "d"},
		{"migrate", "export", "--salt", "s", "--from-state-dir", "d"},
	}
	for _, args := range cases {
		if _, err := runCLI(t, env, args...); err == nil {
			t.Fatalf("%v: want an error", args)
		}
	}
	if _, err := runCLI(t, env, "migrate", "export", "--salt", "s", "--out",
		filepath.Join(t.TempDir(), "o"), "--from-state-dir", filepath.Join(t.TempDir(), "gone")); err == nil {
		t.Fatal("want an error for a missing state directory")
	}
}

func TestMigrateExportRejectsBadRecord(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, migrate.IssuedLogName), []byte(`[{"id":"vc-1"}]`))
	if _, err := runCLI(t, Environment{Root: t.TempDir()}, "migrate", "export",
		"--from-state-dir", dir, "--out", filepath.Join(t.TempDir(), "o"),
		"--salt", "pepper"); !errors.Is(err, migrate.ErrInput) {
		t.Fatalf("want ErrInput, got %v", err)
	}
}

func TestMigrateExportFromPostgres(t *testing.T) {
	var gotDriver, gotDSN string
	env := Environment{Root: t.TempDir(), OpenDB: func(driver, dsn string) (*sql.DB, error) {
		gotDriver, gotDSN = driver, dsn
		return openFakeLegacyDB(t)
	}}
	out := filepath.Join(t.TempDir(), "migration")
	if _, err := runCLI(t, env, "migrate", "export", "--from-pg", "postgres://legacy",
		"--out", out, "--salt", "pepper"); err != nil {
		t.Fatalf("export: %v", err)
	}
	if gotDriver != DefaultPgDriver || gotDSN != "postgres://legacy" {
		t.Fatalf("driver %q dsn %q", gotDriver, gotDSN)
	}
	bundle, err := migrate.Read(out)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(bundle.Trust.Entries) != 1 || len(bundle.Issued.Entries) != 1 {
		t.Fatalf("bundle: %+v", bundle.Counts())
	}
}

func TestMigrateExportPostgresErrors(t *testing.T) {
	boom := errors.New("no driver")
	env := Environment{Root: t.TempDir(), OpenDB: func(string, string) (*sql.DB, error) { return nil, boom }}
	if _, err := runCLI(t, env, "migrate", "export", "--from-pg", "dsn",
		"--out", filepath.Join(t.TempDir(), "o"), "--salt", "s"); !errors.Is(err, boom) {
		t.Fatalf("open: %v", err)
	}
	real := Environment{Root: t.TempDir()}
	if _, err := runCLI(t, real, "migrate", "export", "--from-pg", "dsn", "--pg-driver", "",
		"--out", filepath.Join(t.TempDir(), "o"), "--salt", "s"); err == nil {
		t.Fatal("want an error without a linked driver")
	}
}

func TestMigrateImport(t *testing.T) {
	dir := legacyStateDir(t)
	out := filepath.Join(t.TempDir(), "migration")
	if _, err := runCLI(t, Environment{Root: t.TempDir()}, "migrate", "export",
		"--from-state-dir", dir, "--out", out, "--salt", "pepper"); err != nil {
		t.Fatalf("export: %v", err)
	}
	into := filepath.Join(t.TempDir(), "state")
	text, err := runCLI(t, Environment{Root: t.TempDir()}, "migrate", "import", "--from", out, "--into", into)
	if err != nil {
		t.Fatalf("import: %v (%s)", err, text)
	}
	if !strings.Contains(text, migrate.IssuedFile) {
		t.Fatalf("output: %s", text)
	}
	if _, err := os.Stat(filepath.Join(into, migrate.BitstringDir, migrate.ListsDir, "bitstring-v1.json")); err != nil {
		t.Fatalf("list file: %v", err)
	}
	if _, err := runCLI(t, Environment{Root: t.TempDir()}, "migrate", "import", "--from", out, "--into", into); err == nil {
		t.Fatal("want an error for files that exist")
	}
	if _, err := runCLI(t, Environment{Root: t.TempDir()}, "migrate", "import", "--from", out); err == nil {
		t.Fatal("want an error without --into")
	}
}
