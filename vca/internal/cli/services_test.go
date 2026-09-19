// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

func TestCatalogMatchesTheServiceDirectories(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "..", "services"))
	if err != nil {
		t.Skipf("services directory not readable: %v", err)
	}
	onDisk := map[string]bool{}
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "internal" {
			continue
		}
		if _, err := os.Stat(filepath.Join("..", "..", "services", e.Name(), "Dockerfile")); err != nil {
			continue
		}
		onDisk[e.Name()] = true
	}
	inCatalog := map[string]bool{}
	for _, s := range Catalog() {
		inCatalog[s.Name] = true
		if !onDisk[s.Name] {
			t.Errorf("catalog names %s, which has no Dockerfile", s.Name)
		}
	}
	for name := range onDisk {
		if !inCatalog[name] {
			t.Errorf("service %s is missing from the catalog", name)
		}
	}
}

func TestCatalogExposedPortsMatchTheDockerfiles(t *testing.T) {
	rx := regexp.MustCompile(`(?m)^EXPOSE\s+(\d+)`)
	for _, s := range Catalog() {
		data, err := os.ReadFile(filepath.Join("..", "..", "services", s.Name, "Dockerfile"))
		if err != nil {
			t.Skipf("Dockerfile not readable: %v", err)
		}
		m := rx.FindSubmatch(data)
		if m == nil {
			t.Errorf("%s has no EXPOSE line", s.Name)
			continue
		}
		want, _ := strconv.Atoi(string(m[1]))
		if s.ExposedPort != want {
			t.Errorf("%s exposed port = %d, want %d", s.Name, s.ExposedPort, want)
		}
	}
}

func TestCatalogIsSortedAndComplete(t *testing.T) {
	list := Catalog()
	for i := 1; i < len(list); i++ {
		if list[i-1].Name >= list[i].Name {
			t.Fatalf("catalog is not sorted at %s", list[i].Name)
		}
	}
	for _, s := range list {
		if s.ListenEnv == "" || len(s.Roles) == 0 {
			t.Errorf("%s is incomplete: %+v", s.Name, s)
		}
		if s.Image() != "ghcr.io/centre-for-dpi/vca-"+s.Name {
			t.Errorf("%s image = %s", s.Name, s.Image())
		}
	}
}

func TestServicesForPicksOneAdapter(t *testing.T) {
	for _, p := range AllPairs() {
		list := ServicesFor(p)
		adapters := 0
		for _, s := range list {
			if s.Dpg != configv1.Dpg_DPG_UNSPECIFIED {
				adapters++
				if s.Dpg != p.Dpg {
					t.Errorf("%s got the adapter of %v", p.Name(), s.Dpg)
				}
			}
		}
		if p.Role == commonv1.Role_ROLE_ADMIN {
			if adapters != 0 {
				t.Errorf("%s runs %d adapters, want 0", p.Name(), adapters)
			}
			continue
		}
		if adapters != 1 {
			t.Errorf("%s runs %d adapters, want 1", p.Name(), adapters)
		}
	}
}

func TestServicesForRoleSets(t *testing.T) {
	issuer := ServicesFor(Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_WALTID})
	if len(issuer) != 9 {
		t.Errorf("the issuer runs %d services, want 9", len(issuer))
	}
	holder := ServicesFor(Pair{Role: commonv1.Role_ROLE_HOLDER, Dpg: configv1.Dpg_DPG_INJI})
	if len(holder) != 2 {
		t.Errorf("the holder runs %d services, want 2", len(holder))
	}
	admin := ServicesFor(Pair{Role: commonv1.Role_ROLE_ADMIN, Dpg: configv1.Dpg_DPG_CREDEBL})
	if len(admin) != 1 || admin[0].Name != "trust-registry" {
		t.Errorf("the admin set = %+v", admin)
	}
}

func TestAssignPortsAreUniqueInAPair(t *testing.T) {
	for _, p := range AllPairs() {
		plan := AssignPorts(p, nil)
		listen := map[int]string{}
		for _, a := range plan {
			if other, ok := listen[a.Listen]; ok {
				t.Errorf("%s: %s and %s both listen on %d", p.Name(), other, a.Service.Name, a.Listen)
			}
			listen[a.Listen] = a.Service.Name
			if a.Listen < 1024 || a.Listen > 65535 {
				t.Errorf("%s: %s listens on %d", p.Name(), a.Service.Name, a.Listen)
			}
		}
	}
}

func TestAssignPortsHostPortsAreGloballyUnique(t *testing.T) {
	seen := map[int]string{}
	for _, p := range AllPairs() {
		for _, a := range AssignPorts(p, nil) {
			key := p.Name() + "/" + a.Service.Name
			if other, ok := seen[a.Host]; ok {
				t.Errorf("host port %d used by %s and %s", a.Host, other, key)
			}
			seen[a.Host] = key
		}
	}
}

func TestAssignPortsUsesTheNamedSettings(t *testing.T) {
	p := Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_WALTID}
	plan := AssignPorts(p, map[string]string{
		"VCA_PORTS_PORTAL":  "9000",
		"VCA_PORTS_AUTH":    "9001",
		"VCA_PORTS_ADAPTER": "9002",
	})
	got := map[string]int{}
	for _, a := range plan {
		got[a.Service.Name] = a.Listen
	}
	if got["issuance"] != 9000 {
		t.Errorf("issuance listens on %d, want 9000", got["issuance"])
	}
	if got["issuer-auth"] != 9001 {
		t.Errorf("issuer-auth listens on %d, want 9001", got["issuer-auth"])
	}
	if got["dpg-adapter-waltid"] != 9002 {
		t.Errorf("the adapter listens on %d, want 9002", got["dpg-adapter-waltid"])
	}
	if got["schema-registry"] < firstServicePort {
		t.Errorf("schema-registry listens on %d", got["schema-registry"])
	}
}

func TestAssignPortsIgnoresABadOverride(t *testing.T) {
	p := Pair{Role: commonv1.Role_ROLE_ADMIN, Dpg: configv1.Dpg_DPG_WALTID}
	for _, bad := range []string{"eighty", "80", "70000"} {
		plan := AssignPorts(p, map[string]string{"VCA_PORTS_PORTAL": bad})
		if plan[0].Listen != 8080 {
			t.Errorf("override %q gave %d, want the default 8080", bad, plan[0].Listen)
		}
	}
}

func TestPortValues(t *testing.T) {
	p := Pair{Role: commonv1.Role_ROLE_HOLDER, Dpg: configv1.Dpg_DPG_INJI}
	plan := AssignPorts(p, nil)
	values := PortValues(plan)
	if values["VCA_WALLET_AUTH_LISTEN"] != ":8080" {
		t.Errorf("the wallet-auth listen address = %q", values["VCA_WALLET_AUTH_LISTEN"])
	}
	if values["VCA_PORTS_PORTAL"] != "8080" {
		t.Errorf("the portal port = %q", values["VCA_PORTS_PORTAL"])
	}
	if values["VCA_HOST_PORT_WALLET_AUTH"] == "" {
		t.Error("the host port is missing")
	}
	if values["VCA_PORTS_ADAPTER"] != "8090" {
		t.Errorf("the adapter port = %q", values["VCA_PORTS_ADAPTER"])
	}
}

func TestEnvName(t *testing.T) {
	cases := map[string]string{
		"verifier-policy": "VERIFIER_POLICY",
		"issuance":        "ISSUANCE",
		"status-token":    "STATUS_TOKEN",
		"a1-b":            "A1_B",
	}
	for in, want := range cases {
		if got := envName(in); got != want {
			t.Errorf("envName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPortalAndAuthService(t *testing.T) {
	if portalService(commonv1.Role_ROLE_UNSPECIFIED) != "" {
		t.Error("an unknown role has a portal")
	}
	if authService(commonv1.Role_ROLE_HOLDER) != "" {
		t.Error("the holder runs a separate auth service")
	}
	for _, r := range Roles() {
		name := portalService(r)
		found := false
		for _, s := range ServicesFor(Pair{Role: r, Dpg: configv1.Dpg_DPG_WALTID}) {
			if s.Name == name {
				found = true
			}
		}
		if !found {
			t.Errorf("role %v has portal %q, which it does not run", r, name)
		}
	}
}
