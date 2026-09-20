// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"os"
	"path/filepath"
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
}
