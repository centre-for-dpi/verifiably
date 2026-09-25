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
			"VCA_PUBLIC_URL=https://"+p.Name()+".labs.example/\nVCA_OIDC_PUBLIC_URL=https://waltid-keycloak.labs.example\n"+
				"VCA_OIDC_DISCOVERY_URL="+DefaultDiscoveryURL(p)+"\n", "")
	}
	points, err := EntryPoints(root, pairs)
	if err != nil {
		t.Fatal(err)
	}
	if len(points) != 3 {
		t.Fatalf("got %d entry points", len(points))
	}
	if points[0].Pair.Name() != "issuer-waltid" || points[0].Portal != "issuance" ||
		points[0].URL != "https://issuer-waltid.labs.example" || points[0].Local {
		t.Errorf("first = %+v", points[0])
	}
	// The pages come from the route table: the home page first, then
	// the rest in service order (ADR-035, ADR-044 decision 1).
	if len(points[0].Pages) != 10 || points[0].Pages[0].URL != "https://issuer-waltid.labs.example/issuer/" ||
		points[0].Pages[1].URL != "https://issuer-waltid.labs.example/sources/" || points[0].Pages[1].Title != "Data sources" ||
		points[0].Pages[2].URL != "https://issuer-waltid.labs.example/identity/" ||
		points[0].Pages[6].URL != "https://issuer-waltid.labs.example/issued/" || points[0].Pages[6].Title != "Issued credentials" ||
		points[0].Pages[7].URL != "https://issuer-waltid.labs.example/auth/" || points[0].Pages[7].Title != "Sign in" ||
		points[0].Pages[9].URL != "https://issuer-waltid.labs.example/portal/" {
		t.Errorf("issuer pages = %+v", points[0].Pages)
	}
	report := EntryReport("", points)
	for _, want := range []string{
		"Open\n  issuer-waltid\n    Issuer portal          issuance            https://issuer-waltid.labs.example/issuer/\n",
		"    Schemas                schema-registry     https://issuer-waltid.labs.example/portal/\n",
		"    Sign in                issuer-auth         https://issuer-waltid.labs.example/auth/\n",
		"    Schema builder         schema-builder-ui   https://issuer-waltid.labs.example/builder/\n",
		"  holder-waltid\n    Wallet                 wallet-portal       https://holder-waltid.labs.example/wallet/\n",
		"  verifier-waltid\n    Verification results   verifier-results    https://verifier-waltid.labs.example/portal/\n",
		"    Citizen check          verifier-results    https://verifier-waltid.labs.example/verify/\n",
		"Login\n  https://waltid-keycloak.labs.example\n",
		"    console https://waltid-keycloak.labs.example/admin/, administrator in deploy/keycloak-waltid/.env\n",
		"vca proxy --all | sudo tee /etc/caddy/vca.caddy",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report has no %q:\n%s", want, report)
		}
	}
	if strings.Count(report, "Login\n") != 1 || strings.Count(report, "console ") != 1 {
		t.Errorf("the login URL repeats:\n%s", report)
	}
	// Another provider gets no console hint, because the CLI knows no
	// administrator of it.
	writePairEnv(t, root, issuerPair(),
		"VCA_PUBLIC_URL=https://issuer-waltid.labs.example/\nVCA_OIDC_PUBLIC_URL=https://idp.example\n"+
			"VCA_OIDC_DISCOVERY_URL=https://idp.example/.well-known/openid-configuration\n", "")
	other, err := EntryPoints(root, []Pair{issuerPair()})
	if err != nil || len(other) != 1 || other[0].Console != "" || other[0].AdminEnv != "" {
		t.Errorf("another provider = %+v, %v", other, err)
	}
	if strings.Contains(EntryReport("", other), "console") {
		t.Error("another provider got a console hint")
	}
	if EntryReport("", nil) != "" {
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
	if report := EntryReport("", points); strings.Contains(report, "vca proxy") || !strings.Contains(report, "http://localhost:18006/portal/") {
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
	if !strings.Contains(out.String(), "Open\n  issuer-waltid\n    Issuer portal          issuance            https://issuer-waltid.labs.example/issuer/") {
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

// writeLandingEnv writes deploy/landing/.env under root.
func writeLandingEnv(t *testing.T, root, env string) {
	t.Helper()
	dir := filepath.Join(root, "deploy", LandingDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, EnvFileName), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestEntryReportStartsWithTheLanding puts the one address that starts
// every journey first (ADR-033 consequence 1).
func TestEntryReportStartsWithTheLanding(t *testing.T) {
	root := t.TempDir()
	p := issuerPair()
	writePairEnv(t, root, p, "VCA_PUBLIC_URL=https://issuer-waltid.labs.example\n", "")
	writeLandingEnv(t, root, "VCA_LANDING_PUBLIC_URL=https://vca.labs.example\n")
	landing, err := LandingURL(root)
	if err != nil || landing != "https://vca.labs.example" {
		t.Fatalf("LandingURL = %q, %v", landing, err)
	}
	points, err := EntryPoints(root, []Pair{p})
	if err != nil {
		t.Fatal(err)
	}
	report := EntryReport(landing, points)
	if !strings.HasPrefix(report, "\nStart here\n  https://vca.labs.example\n") {
		t.Errorf("report:\n%s", report)
	}
	if !strings.Contains(report, "Open\n  issuer-waltid\n") {
		t.Errorf("the pairs follow the landing:\n%s", report)
	}
	// With no landing file the report keeps the pairs alone, and a
	// directory in place of the file is an error.
	if got := EntryReport("", points); strings.Contains(got, "Start here") {
		t.Errorf("report without a landing:\n%s", got)
	}
	empty := t.TempDir()
	if got, err := LandingURL(empty); err != nil || got != "" {
		t.Errorf("LandingURL of an empty root = %q, %v", got, err)
	}
	if err := os.MkdirAll(filepath.Join(empty, "deploy", LandingDir, EnvFileName), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := LandingURL(empty); err == nil {
		t.Error("an unreadable landing file passed")
	}
	// The deploy command prints it.
	rec := &recorder{}
	var out bytes.Buffer
	if err := Deploy(context.Background(), DeployOptions{Root: root, Pairs: []Pair{p}, Out: &out, Run: rec.run}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Start here\n  https://vca.labs.example\n") {
		t.Errorf("deploy output:\n%s", out.String())
	}
}

// TestProxySnippetHoldsTheLandingSite routes vca.<domain> to the landing
// (ADR-033 decision 2).
func TestProxySnippetHoldsTheLandingSite(t *testing.T) {
	root := t.TempDir()
	p := issuerPair()
	writePairEnv(t, root, p, "x=1\n", "issuer-waltid.labs.example {\n\treverse_proxy 127.0.0.1:18002\n}\n")
	writeLandingEnv(t, root, "VCA_LANDING_PUBLIC_URL=https://vca.labs.example\n")
	snippet, _, err := ProxySnippet(root, []Pair{p})
	if err != nil {
		t.Fatal(err)
	}
	site := "vca.labs.example {\n\tencode gzip\n\treverse_proxy 127.0.0.1:17900\n}\n"
	if !strings.Contains(snippet, site) {
		t.Errorf("snippet has no landing site:\n%s", snippet)
	}
	if strings.Index(snippet, "vca.labs.example {") > strings.Index(snippet, "issuer-waltid.labs.example {") {
		t.Errorf("the landing site comes first:\n%s", snippet)
	}
	// A host port override of the landing file wins.
	writeLandingEnv(t, root, "VCA_LANDING_PUBLIC_URL=https://vca.labs.example\nVCA_HOST_PORT_LANDING=17999\n")
	snippet, _, err = ProxySnippet(root, []Pair{p})
	if err != nil || !strings.Contains(snippet, "reverse_proxy 127.0.0.1:17999") {
		t.Errorf("snippet with an override:\n%s\n%v", snippet, err)
	}
	// A local landing needs no site, and a missing file gives none.
	writeLandingEnv(t, root, "VCA_LANDING_PUBLIC_URL=http://localhost:17900\n")
	snippet, _, err = ProxySnippet(root, []Pair{p})
	if err != nil || strings.Contains(snippet, "localhost") || strings.Contains(snippet, "17900") {
		t.Errorf("snippet of a local landing:\n%s\n%v", snippet, err)
	}
	if got := LandingCaddyfile(map[string]string{}); got != "" {
		t.Errorf("no public URL gave a site:\n%s", got)
	}
	if _, _, err := ProxySnippet(t.TempDir(), []Pair{p}); err != nil {
		t.Errorf("a root without a landing file: %v", err)
	}
}
