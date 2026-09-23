// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/internal/themefile"
)

// themeRoot returns a repository root whose deploy/vca holds the shipped
// theme file.
func themeRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "deploy", "vca"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, themefile.ShippedPath), themefile.Default(), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

// lowContrastTheme writes a theme file with a light primary colour that
// fails the button label pairing and returns its path.
func lowContrastTheme(t *testing.T, dir string) string {
	t.Helper()
	data := strings.Replace(string(themefile.Default()),
		`primary: "#21663F"      # pine: links, primary buttons, emphasis`, `primary: "#5B9E73"`, 1)
	path := filepath.Join(dir, "theme.yaml")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// pairOf builds a pair from two names.
func pairOf(t *testing.T, role, dpg string) Pair {
	t.Helper()
	r, err := ParseRole(role)
	if err != nil {
		t.Fatal(err)
	}
	d, err := ParseDpg(dpg)
	if err != nil {
		t.Fatal(err)
	}
	return Pair{Role: r, Dpg: d}
}

// deployPair writes the .env file of a pair under root, as vca setup does.
func deployPair(t *testing.T, root string, p Pair) {
	t.Helper()
	dir := filepath.Join(root, "deploy", p.Name())
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, EnvFileName), []byte("VCA_ROLE=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestThemeCheckPassesOnShippedFile(t *testing.T) {
	root := themeRoot(t)
	status, out, errOut := run(t, Environment{Root: root}, "theme", "check")
	if status != 0 {
		t.Fatalf("status = %d\n%s\n%s", status, out, errOut)
	}
	want := "theme file " + filepath.Join(root, themefile.ShippedPath) + ": valid\n"
	if out != want {
		t.Errorf("output = %q, want %q", out, want)
	}
}

func TestThemeCheckFailsAndNamesPairing(t *testing.T) {
	root := themeRoot(t)
	path := lowContrastTheme(t, t.TempDir())
	status, out, errOut := run(t, Environment{Root: root}, "theme", "check", "--file", path)
	if status != 1 {
		t.Fatalf("status = %d\n%s\n%s", status, out, errOut)
	}
	if strings.Contains(out, "valid") {
		t.Errorf("a bad file printed valid:\n%s", out)
	}
	for _, want := range []string{
		"theme file " + path + `: colors.light: pairing "primary button label": contrast 2.77:1 is below 4.5:1`,
		"theme file " + path + `: colors.light: pairing "links and primary text"`,
	} {
		if !strings.Contains(errOut, want) {
			t.Errorf("error output lacks %q:\n%s", want, errOut)
		}
	}
}

func TestThemeCheckReadsHostVariable(t *testing.T) {
	root := themeRoot(t)
	// A relative value resolves against deploy/vca, as the compose file does.
	if err := os.WriteFile(filepath.Join(root, "deploy", "theme.local.yaml"), themefile.Default(), 0o600); err != nil {
		t.Fatal(err)
	}
	getenv := func(k string) string {
		if k == ThemeHostFileEnv {
			return "../theme.local.yaml"
		}
		return ""
	}
	status, out, errOut := run(t, Environment{Root: root, Getenv: getenv}, "theme", "check")
	if status != 0 {
		t.Fatalf("status = %d\n%s\n%s", status, out, errOut)
	}
	want := "theme file " + filepath.Join(root, "deploy", "theme.local.yaml") + ": valid\n"
	if out != want {
		t.Errorf("output = %q, want %q", out, want)
	}
	// An absolute value is used as it is; a missing file names its path.
	missing := filepath.Join(t.TempDir(), "none.yaml")
	getenv = func(k string) string {
		if k == ThemeHostFileEnv {
			return missing
		}
		return ""
	}
	status, _, errOut = run(t, Environment{Root: root, Getenv: getenv}, "theme", "check")
	if status != 1 || !strings.Contains(errOut, "theme file "+missing+": ") {
		t.Errorf("status %d, error output %q", status, errOut)
	}
}

func TestThemeApplyRestartsOnlyUIServices(t *testing.T) {
	root := themeRoot(t)
	issuer := pairOf(t, "issuer", "waltid")
	admin := pairOf(t, "admin", "inji")
	deployPair(t, root, issuer)
	deployPair(t, root, admin)
	rec := &recorder{}
	status, out, errOut := run(t, Environment{Root: root, Run: rec.run}, "theme", "apply")
	if status != 0 {
		t.Fatalf("status = %d\n%s\n%s", status, out, errOut)
	}
	if !strings.HasPrefix(out, "theme file "+filepath.Join(root, themefile.ShippedPath)+": valid\n") {
		t.Errorf("apply did not check first:\n%s", out)
	}
	if len(rec.calls) != 2 {
		t.Fatalf("got %d commands, want 2:\n%v", len(rec.calls), rec.calls)
	}
	wantIssuer := append(ComposeArgs(root, issuer, []string{"restart"}),
		"issuer-waltid-schema-builder-ui", "issuer-waltid-schema-registry")
	if got := strings.Join(rec.calls[0][1:], " "); got != strings.Join(wantIssuer, " ") || rec.calls[0][0] != "docker" {
		t.Errorf("issuer command = %v\nwant docker %v", rec.calls[0], wantIssuer)
	}
	wantAdmin := append(ComposeArgs(root, admin, []string{"restart"}), "admin-inji-admin")
	if got := strings.Join(rec.calls[1][1:], " "); got != strings.Join(wantAdmin, " ") {
		t.Errorf("admin command = %v\nwant docker %v", rec.calls[1], wantAdmin)
	}
	for _, call := range rec.calls {
		text := strings.Join(call, " ")
		if strings.Contains(text, "dpg-adapter") || strings.Contains(text, "issuance") || strings.Contains(text, "trust-registry") {
			t.Errorf("apply restarted a service with no pages: %s", text)
		}
	}
	for _, want := range []string{"docker compose", "restart issuer-waltid-schema-builder-ui", "restart admin-inji-admin"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestThemeApplyWithNoDeployedPairSaysSo(t *testing.T) {
	root := themeRoot(t)
	rec := &recorder{}
	status, out, _ := run(t, Environment{Root: root, Run: rec.run}, "theme", "apply")
	if status != 0 || len(rec.calls) != 0 {
		t.Fatalf("status %d, calls %v", status, rec.calls)
	}
	if !strings.Contains(out, "no deployed pair") {
		t.Errorf("output = %q", out)
	}
}

func TestThemeApplyStopsOnInvalidFile(t *testing.T) {
	root := themeRoot(t)
	issuer := pairOf(t, "issuer", "waltid")
	deployPair(t, root, issuer)
	path := lowContrastTheme(t, t.TempDir())
	rec := &recorder{}
	status, _, errOut := run(t, Environment{Root: root, Run: rec.run}, "theme", "apply", "--file", path)
	if status != 1 {
		t.Fatalf("status = %d", status)
	}
	if len(rec.calls) != 0 {
		t.Errorf("apply restarted services with a bad file: %v", rec.calls)
	}
	if !strings.Contains(errOut, `pairing "primary button label"`) {
		t.Errorf("error output = %q", errOut)
	}
}

func TestThemeApplyReportsARunnerFailure(t *testing.T) {
	root := themeRoot(t)
	deployPair(t, root, issuerPair())
	failing := func(context.Context, string, []string) error { return context.DeadlineExceeded }
	status, _, errOut := run(t, Environment{Root: root, Run: failing}, "theme", "apply")
	if status != 1 || !strings.Contains(errOut, "issuer-waltid") {
		t.Errorf("status %d, error output %q", status, errOut)
	}
}

func TestPrintDefaultEqualsShippedFile(t *testing.T) {
	root := themeRoot(t)
	status, out, _ := run(t, Environment{Root: root}, "theme", "print-default")
	if status != 0 {
		t.Fatalf("status = %d", status)
	}
	shipped, err := os.ReadFile(filepath.Join(repoRoot(), themefile.ShippedPath))
	if err != nil {
		t.Fatal(err)
	}
	if out != string(shipped) {
		t.Error("print-default differs from the tracked deploy/vca/theme.yaml")
	}
}

func TestSetupWritesDefaultThemeWhenAbsent(t *testing.T) {
	root := t.TempDir()
	plan, err := BuildPlan(SetupRequest{Pair: issuerPair(), Flags: issuerFlags(), Random: rand.Reader})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	written, err := WritePlan(root, plan)
	if err != nil {
		t.Fatalf("WritePlan: %v", err)
	}
	path := filepath.Join(root, "vca", "theme.yaml")
	found := false
	for _, w := range written {
		if w == path {
			found = true
		}
	}
	if !found {
		t.Errorf("WritePlan did not report the theme file; wrote %v", written)
	}
	got, err := os.ReadFile(path) // #nosec G304 -- a test path
	if err != nil {
		t.Fatalf("read the theme file: %v", err)
	}
	if !bytes.Equal(got, themefile.Default()) {
		t.Error("the written theme file is not the embedded default")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("theme file mode = %04o, want 0644 so the container user reads it", info.Mode().Perm())
	}
}

func TestSetupKeepsAnEditedTheme(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "vca", "theme.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	edited := []byte("# edited by the operator\nversion: 1\n")
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(SetupRequest{Pair: issuerPair(), Flags: issuerFlags(), Random: rand.Reader})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	written, err := WritePlan(root, plan)
	if err != nil {
		t.Fatalf("WritePlan: %v", err)
	}
	for _, w := range written {
		if w == path {
			t.Error("WritePlan reported an existing theme file as written")
		}
	}
	got, err := os.ReadFile(path) // #nosec G304 -- a test path
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, edited) {
		t.Error("WritePlan replaced an edited theme file")
	}
}

func TestSetupReportsAThemeFileItCannotWrite(t *testing.T) {
	root := t.TempDir()
	// deploy/vca is a file, so the theme file cannot be written.
	if err := os.WriteFile(filepath.Join(root, "vca"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(SetupRequest{Pair: issuerPair(), Flags: issuerFlags(), Random: rand.Reader})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if _, err := WritePlan(root, plan); err == nil {
		t.Error("WritePlan passed with no place for the theme file")
	}
}

func TestDeployedPairsListsPairsWithAnEnvFile(t *testing.T) {
	root := themeRoot(t)
	if got := DeployedPairs(root); len(got) != 0 {
		t.Errorf("an empty root has pairs: %v", got)
	}
	holder := pairOf(t, "holder", "credebl")
	deployPair(t, root, holder)
	deployPair(t, root, issuerPair())
	got := DeployedPairs(root)
	if len(got) != 2 || got[0] != issuerPair() || got[1] != holder {
		t.Errorf("pairs = %v", got)
	}
}
