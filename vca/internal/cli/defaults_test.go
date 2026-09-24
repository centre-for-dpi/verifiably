// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
)

// stackFile reads the compose file of one DPG stack.
func stackFile(t *testing.T, dpg string) string {
	t.Helper()
	path := filepath.Join(repoRoot(), "deploy", "vca", "dpg", dpg+".yaml")
	data, err := os.ReadFile(path) // #nosec G304 -- a path under deploy
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func TestDefaultDpgURLCoversEveryDpgRole(t *testing.T) {
	for _, p := range AllPairs() {
		url := DefaultDpgURL(p)
		if p.Role == commonv1.Role_ROLE_ADMIN {
			if url != "" {
				t.Errorf("%s has the DPG URL %q", p.Name(), url)
			}
			continue
		}
		if !strings.HasPrefix(url, "http://") {
			t.Errorf("%s has the DPG URL %q", p.Name(), url)
		}
	}
}

// TestDefaultDpgURLNamesAContainerOfTheStack keeps the default equal to
// the compose file of the stack.
func TestDefaultDpgURLNamesAContainerOfTheStack(t *testing.T) {
	for _, p := range AllPairs() {
		url := DefaultDpgURL(p)
		if url == "" {
			continue
		}
		host := strings.TrimPrefix(url, "http://")
		name, port, found := strings.Cut(host, ":")
		if !found {
			t.Fatalf("%s: %q has no port", p.Name(), url)
		}
		text := stackFile(t, ShortName(p.Dpg.String()))
		if !strings.Contains(text, "container_name: "+name) {
			t.Errorf("%s: the stack runs no container %s", p.Name(), name)
		}
		if !strings.Contains(text, ":"+port) {
			t.Errorf("%s: the stack maps no port %s", p.Name(), port)
		}
	}
}

// baseFlags holds the values that no default fills yet.
func baseFlags() map[string]string {
	return map[string]string{
		"VCA_OIDC_DISCOVERY_URL": "https://idp.example/.well-known/openid-configuration",
		"VCA_REDIS_URL":          "redis://redis:6379",
	}
}

func TestBuildPlanDefaultsTheDpgURL(t *testing.T) {
	for _, p := range AllPairs() {
		want := DefaultDpgURL(p)
		if want == "" {
			continue
		}
		plan, err := BuildPlan(SetupRequest{Pair: p, Flags: baseFlags(), Random: rand.Reader})
		if err != nil {
			t.Fatalf("%s: BuildPlan: %v", p.Name(), err)
		}
		got := Values(plan.Resolutions)["VCA_DPG_URL"]
		if got != want {
			t.Errorf("%s: VCA_DPG_URL = %q, want %q", p.Name(), got, want)
		}
	}
}

func TestBuildPlanKeepsASuppliedDpgURL(t *testing.T) {
	p := issuerPair()
	plan, err := BuildPlan(SetupRequest{
		Pair: p,
		Flags: map[string]string{
			"VCA_DPG_URL":            "https://issuer-api.example",
			"VCA_OIDC_DISCOVERY_URL": "https://idp.example/.well-known/openid-configuration",
		},
		Random: rand.Reader,
	})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if got := Values(plan.Resolutions)["VCA_DPG_URL"]; got != "https://issuer-api.example" {
		t.Errorf("VCA_DPG_URL = %q", got)
	}
}

func TestDpgURLTableHoldsEveryPair(t *testing.T) {
	table := DpgURLTable()
	for _, p := range AllPairs() {
		if DefaultDpgURL(p) == "" {
			continue
		}
		if !strings.Contains(table, "`"+p.Name()+"`") {
			t.Errorf("the table misses %s", p.Name())
		}
	}
}

// TestEveryStackShipsAKeycloak is the local path of ADR-010 decision 2.
// Every DPG stack must ship an identity provider.
func TestEveryStackShipsAKeycloak(t *testing.T) {
	for _, d := range Dpgs() {
		name := KeycloakContainer(d)
		if name == "" {
			t.Fatalf("%s ships no Keycloak", ShortName(d.String()))
		}
		text := stackFile(t, ShortName(d.String()))
		if !strings.Contains(text, "container_name: "+name) {
			t.Errorf("%s runs no container %s", ShortName(d.String()), name)
		}
		if !strings.Contains(text, "quay.io/keycloak/keycloak:25.0") {
			t.Errorf("%s pins another Keycloak version", ShortName(d.String()))
		}
		if !strings.Contains(text, "--import-realm") {
			t.Errorf("%s imports no realm", ShortName(d.String()))
		}
		port := strconv.Itoa(KeycloakHostPort(d))
		if !strings.Contains(text, KeycloakHostPortEnv(d)+":-"+port+"}:8080") {
			t.Errorf("%s maps another host port than %s", ShortName(d.String()), port)
		}
	}
}

func TestKeycloakHostPortsAreUnique(t *testing.T) {
	seen := map[int]bool{}
	for _, d := range Dpgs() {
		port := KeycloakHostPort(d)
		if seen[port] {
			t.Errorf("two stacks map host port %d", port)
		}
		seen[port] = true
	}
}

func TestBuildPlanDefaultsTheIdp(t *testing.T) {
	for _, p := range AllPairs() {
		plan, err := BuildPlan(SetupRequest{Pair: p, Flags: baseFlags(), Random: rand.Reader})
		if err != nil {
			t.Fatalf("%s: BuildPlan: %v", p.Name(), err)
		}
		values := Values(plan.Resolutions)
		want := map[string]string{
			"VCA_OIDC_DISCOVERY_URL": DefaultDiscoveryURL(p),
			"VCA_OIDC_PUBLIC_URL":    DefaultOidcPublicURL(p),
			"VCA_OIDC_CLIENT_ID":     DefaultClientID(p.Role),
		}
		for name, value := range want {
			if name == "VCA_OIDC_DISCOVERY_URL" {
				continue
			}
			if values[name] != value {
				t.Errorf("%s: %s = %q, want %q", p.Name(), name, values[name], value)
			}
		}
		if values["VCA_OIDC_CLIENT_SECRET"] == "" {
			t.Errorf("%s: the client secret was not generated", p.Name())
		}
	}
}

// TestBuildPlanDefaultsTheDiscoveryURL checks the value that the laptop
// path needs. No flag supplies it.
func TestBuildPlanDefaultsTheDiscoveryURL(t *testing.T) {
	for _, p := range AllPairs() {
		flags := map[string]string{"VCA_REDIS_URL": "redis://redis:6379"}
		plan, err := BuildPlan(SetupRequest{Pair: p, Flags: flags, Random: rand.Reader})
		if err != nil {
			t.Fatalf("%s: BuildPlan: %v", p.Name(), err)
		}
		got := Values(plan.Resolutions)["VCA_OIDC_DISCOVERY_URL"]
		if got != DefaultDiscoveryURL(p) {
			t.Errorf("%s: VCA_OIDC_DISCOVERY_URL = %q", p.Name(), got)
		}
		if !strings.Contains(got, "/realms/"+RealmName(p.Role)+"/.well-known/openid-configuration") {
			t.Errorf("%s: the discovery path is wrong: %q", p.Name(), got)
		}
	}
}

// TestGeneratedRealmHoldsTheClient keeps the realm equal to the values
// the services read.
func TestGeneratedRealmHoldsTheClient(t *testing.T) {
	p := issuerPair()
	plan, err := BuildPlan(SetupRequest{Pair: p, Flags: baseFlags(), Random: rand.Reader})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	values := Values(plan.Resolutions)
	text := string(sharedFile(t, plan, RealmFileOf(p)).Data)
	for _, want := range []string{
		`"clientId": "` + DefaultClientID(p.Role) + `"`,
		`"secret": "` + values["VCA_OIDC_CLIENT_SECRET"] + `"`,
		`"publicClient": false`,
		`"realm": "` + RealmName(p.Role) + `"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the realm has no %s:\n%s", want, text)
		}
	}
}

func TestDpgHostPortsNameTheKeycloak(t *testing.T) {
	ports := DpgHostPorts(issuerPair())
	if len(ports) != 1 {
		t.Fatalf("got %d ports", len(ports))
	}
	if ports[0].Container != "waltid-keycloak" || ports[0].Host != 17010 {
		t.Errorf("port = %+v", ports[0])
	}
	if DpgHostPorts(Pair{}) != nil {
		t.Error("a pair with no DPG has a host port")
	}
}

func TestIdpTableHoldsEveryStack(t *testing.T) {
	table := IdpTable()
	for _, d := range Dpgs() {
		if !strings.Contains(table, KeycloakContainer(d)) {
			t.Errorf("the table misses %s", ShortName(d.String()))
		}
	}
	path := filepath.Join(repoRoot(), "vca", "docs", "deploy.md")
	data, err := os.ReadFile(path) // #nosec G304 -- a fixed test path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !strings.Contains(string(data), table) {
		t.Errorf("docs/deploy.md does not hold the IdP table:\n%s", table)
	}
}

// TestDeployDocHoldsTheDpgURLTable keeps the documentation equal to the
// table in the code.
func TestDeployDocHoldsTheDpgURLTable(t *testing.T) {
	path := filepath.Join(repoRoot(), "vca", "docs", "deploy.md")
	data, err := os.ReadFile(path) // #nosec G304 -- a fixed test path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !strings.Contains(string(data), DpgURLTable()) {
		t.Errorf("docs/deploy.md does not hold the DPG URL table:\n%s", DpgURLTable())
	}
	if !strings.Contains(string(data), FloorTable()) {
		t.Errorf("docs/deploy.md does not hold the memory floor table:\n%s", FloorTable())
	}
}

func TestOidcPublicURLFollowsThePublicHost(t *testing.T) {
	p := issuerPair()
	cases := map[string]string{
		"":                            "http://localhost:17010",
		"http://localhost:18002":      "http://localhost:17010",
		"http://127.0.0.1:18002":      "http://localhost:17010",
		"https://labs.example":        "http://labs.example:17010",
		"https://labs.example/":       "http://labs.example:17010",
		"https://issuer.example:8443": "http://issuer.example:17010",
		"not a url":                   "http://localhost:17010",
	}
	for public, want := range cases {
		if got := OidcPublicURLFor(p, public); got != want {
			t.Errorf("%q: got %q, want %q", public, got, want)
		}
	}
	if DefaultOidcPublicURL(p) != "http://localhost:17010" {
		t.Errorf("DefaultOidcPublicURL = %q", DefaultOidcPublicURL(p))
	}
}

func TestBuildPlanDerivesTheOidcPublicURLFromThePublicURL(t *testing.T) {
	flags := baseFlags()
	flags["VCA_PUBLIC_URL"] = "https://labs.example"
	for _, p := range AllPairs() {
		plan, err := BuildPlan(SetupRequest{Pair: p, Flags: flags, Random: rand.Reader})
		if err != nil {
			t.Fatalf("%s: BuildPlan: %v", p.Name(), err)
		}
		values := Values(plan.Resolutions)
		want := fmt.Sprintf("http://labs.example:%d", KeycloakHostPort(p.Dpg))
		if values["VCA_OIDC_PUBLIC_URL"] != want {
			t.Errorf("%s: VCA_OIDC_PUBLIC_URL = %q, want %q", p.Name(), values["VCA_OIDC_PUBLIC_URL"], want)
		}
	}
	flags["VCA_OIDC_PUBLIC_URL"] = "https://idp.example"
	plan, err := BuildPlan(SetupRequest{Pair: issuerPair(), Flags: flags, Random: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	if got := Values(plan.Resolutions)["VCA_OIDC_PUBLIC_URL"]; got != "https://idp.example" {
		t.Errorf("a given value lost: %q", got)
	}
}
