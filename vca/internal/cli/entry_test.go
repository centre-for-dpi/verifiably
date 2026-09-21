// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePairEnv writes a .env file and a Caddyfile for one pair.
func writePairEnv(t *testing.T, root string, p Pair, env, caddy string) {
	t.Helper()
	dir := filepath.Join(root, "deploy", p.Name())
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, EnvFileName), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	if caddy != "" {
		if err := os.WriteFile(filepath.Join(dir, CaddyFile), []byte(caddy), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEntryPointsAndReport(t *testing.T) {
	root := t.TempDir()
	pairs := PairsForDpg(dpgWaltid(t))
	for _, p := range pairs {
		if p.Name() == "admin-waltid" {
			continue // no .env: left out
		}
		writePairEnv(t, root, p,
			"VCA_PUBLIC_URL=https://"+p.Name()+".labs.example/\nVCA_OIDC_PUBLIC_URL=https://waltid-keycloak.labs.example\n", "")
	}
	points, err := EntryPoints(root, pairs)
	if err != nil {
		t.Fatal(err)
	}
	if len(points) != 3 {
		t.Fatalf("got %d entry points", len(points))
	}
	if points[0].Pair.Name() != "issuer-waltid" || points[0].Portal != "schema-registry" ||
		points[0].URL != "https://issuer-waltid.labs.example" || points[0].Local {
		t.Errorf("first = %+v", points[0])
	}
	// The pages come from the route table: the home page first.
	if len(points[0].Pages) != 2 || points[0].Pages[0].URL != "https://issuer-waltid.labs.example/portal/" ||
		points[0].Pages[1].URL != "https://issuer-waltid.labs.example/builder/" {
		t.Errorf("issuer pages = %+v", points[0].Pages)
	}
	report := EntryReport(points)
	for _, want := range []string{
		"Open\n  issuer-waltid\n",
		"    Schemas                schema-registry     https://issuer-waltid.labs.example/portal/\n",
		"    Schema builder         schema-builder-ui   https://issuer-waltid.labs.example/builder/\n",
		"  holder-waltid\n    Wallet                 wallet-portal       https://holder-waltid.labs.example/wallet/\n",
		"  verifier-waltid\n    Verification results   verifier-results    https://verifier-waltid.labs.example/portal/\n",
		"    Citizen check          verifier-results    https://verifier-waltid.labs.example/verify/\n",
		"Login\n  https://waltid-keycloak.labs.example\n",
		"vca proxy --all | sudo tee /etc/caddy/vca.caddy",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report has no %q:\n%s", want, report)
		}
	}
	if strings.Count(report, "waltid-keycloak") != 1 {
		t.Errorf("the login URL repeats:\n%s", report)
	}
	if EntryReport(nil) != "" {
		t.Error("no points must give no report")
	}
}

func TestEntryReportLocalNeedsNoProxy(t *testing.T) {
	root := t.TempDir()
	p := issuerPair()
	writePairEnv(t, root, p, "VCA_PUBLIC_URL=http://localhost:18006\nVCA_OIDC_PUBLIC_URL=http://localhost:17010\n", "")
	points, err := EntryPoints(root, []Pair{p})
	if err != nil || len(points) != 1 || !points[0].Local {
		t.Fatalf("points = %+v, %v", points, err)
	}
	if report := EntryReport(points); strings.Contains(report, "vca proxy") || !strings.Contains(report, "http://localhost:18006/portal/") {
		t.Errorf("report:\n%s", report)
	}
}

func TestDeployPrintsTheEntryPoints(t *testing.T) {
	root := t.TempDir()
	p := issuerPair()
	writePairEnv(t, root, p, "VCA_PUBLIC_URL=https://issuer-waltid.labs.example\n", "")
	rec := &recorder{}
	var out bytes.Buffer
	err := Deploy(context.Background(), DeployOptions{Root: root, Pairs: []Pair{p}, Out: &out, Run: rec.run})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Open\n  issuer-waltid\n    Schemas                schema-registry     https://issuer-waltid.labs.example/portal/") {
		t.Errorf("out:\n%s", out.String())
	}
	// A dry run prints the commands only.
	out.Reset()
	if err := Deploy(context.Background(), DeployOptions{Root: root, Pairs: []Pair{p}, Out: &out, DryRun: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "Open\n") {
		t.Error("a dry run printed entry points")
	}
}

func TestProxySnippet(t *testing.T) {
	root := t.TempDir()
	pairs := PairsForDpg(dpgWaltid(t))
	writePairEnv(t, root, pairs[0], "x=1\n", "issuer-waltid.labs.example {\n\treverse_proxy 127.0.0.1:18002\n}\n")
	writePairEnv(t, root, pairs[1], "x=1\n", "holder-waltid.labs.example {\n\treverse_proxy 127.0.0.1:18302\n}\n")
	snippet, skipped, err := ProxySnippet(root, pairs)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(skipped, " ") != "verifier-waltid admin-waltid" {
		t.Errorf("skipped = %v", skipped)
	}
	if !strings.HasPrefix(snippet, "# Every VCA pair") ||
		strings.Index(snippet, "issuer-waltid.labs.example {") > strings.Index(snippet, "holder-waltid.labs.example {") {
		t.Errorf("snippet:\n%s", snippet)
	}
	// A directory in place of the file is an error, not a skip.
	if err := os.MkdirAll(filepath.Join(root, "deploy", pairs[2].Name(), CaddyFile), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ProxySnippet(root, pairs); err == nil {
		t.Error("an unreadable Caddyfile passed")
	}
}

func TestProxyCommand(t *testing.T) {
	root := t.TempDir()
	p := issuerPair()
	writePairEnv(t, root, p, "x=1\n", "issuer-waltid.labs.example {\n}\n")
	status, out, errOut := run(t, Environment{Root: root}, "proxy", "--all", "--dpg", "waltid")
	if status != 0 {
		t.Fatalf("status = %d\n%s\n%s", status, out, errOut)
	}
	if !strings.Contains(out, "issuer-waltid.labs.example {") || strings.Contains(out, "proxy:") {
		t.Errorf("out:\n%s", out)
	}
	if !strings.Contains(errOut, "proxy: holder-waltid has no Caddyfile") {
		t.Errorf("errOut:\n%s", errOut)
	}
}
