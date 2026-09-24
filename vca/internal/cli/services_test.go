// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
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
		want, err := strconv.Atoi(string(m[1]))
		if err != nil {
			t.Fatalf("strconv.Atoi: %v", err)
		}
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
	if len(holder) != 3 {
		t.Errorf("the holder runs %d services, want 3", len(holder))
	}
	admin := ServicesFor(Pair{Role: commonv1.Role_ROLE_ADMIN, Dpg: configv1.Dpg_DPG_CREDEBL})
	if len(admin) != 2 || admin[0].Name != "admin" || admin[1].Name != "trust-registry" {
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
	if values["VCA_WALLET_PORTAL_LISTEN"] != ":8080" {
		t.Errorf("the wallet-portal listen address = %q", values["VCA_WALLET_PORTAL_LISTEN"])
	}
	if values["VCA_WALLET_AUTH_LISTEN"] != ":8081" {
		t.Errorf("the wallet-auth listen address = %q", values["VCA_WALLET_AUTH_LISTEN"])
	}
	if values["VCA_PORTS_PORTAL"] != "8080" {
		t.Errorf("the portal port = %q", values["VCA_PORTS_PORTAL"])
	}
	if values["VCA_HOST_PORT_WALLET_PORTAL"] == "" {
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
	if authService(commonv1.Role_ROLE_VERIFIER) != "" {
		t.Error("the verifier runs a separate auth service")
	}
	if authService(commonv1.Role_ROLE_HOLDER) != "wallet-auth" {
		t.Error("the holder runs no auth service")
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

func TestAdminAndWalletPortalAreInTheCatalog(t *testing.T) {
	byName := map[string]Service{}
	for _, s := range Catalog() {
		byName[s.Name] = s
	}
	admin, ok := byName["admin"]
	if !ok {
		t.Fatal("the catalog has no admin service")
	}
	if admin.ExposedPort != 8093 || admin.ListenEnv != "VCA_ADMIN_LISTEN" || !admin.Stateful {
		t.Errorf("admin = %+v", admin)
	}
	if len(admin.Roles) != 1 || admin.Roles[0] != commonv1.Role_ROLE_ADMIN {
		t.Errorf("admin roles = %v", admin.Roles)
	}
	portal, ok := byName["wallet-portal"]
	if !ok {
		t.Fatal("the catalog has no wallet-portal service")
	}
	if portal.ExposedPort != 8092 || portal.ListenEnv != "VCA_WALLET_PORTAL_LISTEN" || !portal.Stateful {
		t.Errorf("wallet-portal = %+v", portal)
	}
	if len(portal.Roles) != 1 || portal.Roles[0] != commonv1.Role_ROLE_HOLDER {
		t.Errorf("wallet-portal roles = %v", portal.Roles)
	}
}

func TestWalletPortalLinks(t *testing.T) {
	p := Pair{Role: commonv1.Role_ROLE_HOLDER, Dpg: configv1.Dpg_DPG_WALTID}
	got := LinkValues(p, map[string]string{"VCA_PUBLIC_URL": "https://wallet.example"})
	want := map[string]string{
		"VCA_WALLET_PORTAL_AUTH_JWKS_URL": "http://holder-waltid-wallet-auth:8081/.well-known/jwks.json",
		"VCA_WALLET_PORTAL_LOGIN_URL":     "https://wallet.example/auth/login?provider=default&return_to=/wallet/",
		"VCA_WALLET_PORTAL_DISCOVERY_URL": "http://verifier-waltid-verifier-discovery:8101",
		"VCA_WALLET_PORTAL_TRUST_URL":     "http://admin-waltid-trust-registry:8100",
		"VCA_WALLET_PORTAL_DPG":           "waltid",
		"VCA_WALLET_PORTAL_DPG_ADAPTERS":  "waltid=http://holder-waltid-dpg-adapter-waltid:8090",
		"VCA_WALLET_PORTAL_STATE_DIR":     "/data",
	}
	for name, value := range want {
		if got[name] != value {
			t.Errorf("%s = %q, want %q", name, got[name], value)
		}
	}
}

func TestAdminLinks(t *testing.T) {
	p := Pair{Role: commonv1.Role_ROLE_ADMIN, Dpg: configv1.Dpg_DPG_INJI}
	got := LinkValues(p, map[string]string{"VCA_PUBLIC_URL": "https://admin.example/"})
	if got["VCA_ADMIN_PUBLIC_URL"] != "https://admin.example" {
		t.Errorf("the public URL = %q", got["VCA_ADMIN_PUBLIC_URL"])
	}
	if got["VCA_ADMIN_TRUST_URL"] != "http://admin-inji-trust-registry:8100" {
		t.Errorf("the trust URL = %q", got["VCA_ADMIN_TRUST_URL"])
	}
	if got["VCA_ADMIN_STATE_DIR"] != "/data" {
		t.Errorf("the state directory = %q", got["VCA_ADMIN_STATE_DIR"])
	}
	// The health probe list names every other service of the DPG.
	list := got["VCA_ADMIN_SERVICES"]
	for _, name := range []string{"trust-registry", "issuance", "wallet-portal", "verifier-results", "dpg-adapter-inji"} {
		if !strings.Contains(list, name+"=http://") {
			t.Errorf("the probe list has no %s:\n%s", name, list)
		}
	}
	if strings.Contains(list, "admin=http://") {
		t.Error("the admin service probes itself")
	}
	if strings.Contains(list, "dpg-adapter-waltid") {
		t.Errorf("the probe list names another DPG:\n%s", list)
	}
}

func TestLinkValuesSkipAnUnknownTarget(t *testing.T) {
	p := Pair{Role: commonv1.Role_ROLE_HOLDER, Dpg: configv1.Dpg_DPG_UNSPECIFIED}
	got := LinkValues(p, nil)
	if _, ok := got["VCA_WALLET_PORTAL_DPG"]; ok {
		t.Error("a pair with no DPG got a DPG name")
	}
	if _, ok := got["VCA_WALLET_PORTAL_DPG_ADAPTERS"]; ok {
		t.Error("a pair with no DPG got an adapter map")
	}
	if _, ok := got["VCA_WALLET_PORTAL_AUTH_JWKS_URL"]; !ok {
		t.Error("the JWKS URL of the same role is missing")
	}
	// No public URL means no VCA_ADMIN_PUBLIC_URL value.
	admin := LinkValues(Pair{Role: commonv1.Role_ROLE_ADMIN, Dpg: configv1.Dpg_DPG_WALTID}, nil)
	if _, ok := admin["VCA_ADMIN_PUBLIC_URL"]; ok {
		t.Error("an empty public URL reached the file")
	}
}

func TestServiceURLAndOwnerPair(t *testing.T) {
	p := Pair{Role: commonv1.Role_ROLE_HOLDER, Dpg: configv1.Dpg_DPG_WALTID}
	if _, ok := serviceURL(p, "no-such-service"); ok {
		t.Error("an unknown service has a URL")
	}
	owner, ok := ownerPair(p, "wallet-auth")
	if !ok || owner != p {
		t.Errorf("owner of wallet-auth = %v, %v", owner, ok)
	}
	owner, ok = ownerPair(p, "issuance")
	if !ok || owner.Role != commonv1.Role_ROLE_ISSUER || owner.Dpg != p.Dpg {
		t.Errorf("owner of issuance = %v, %v", owner, ok)
	}
	if _, ok := ownerPair(p, "no-such-service"); ok {
		t.Error("an unknown service has an owner")
	}
}

func TestDeploymentServicesKeepOneAdapter(t *testing.T) {
	list := deploymentServices(configv1.Dpg_DPG_CREDEBL)
	seen := map[string]bool{}
	adapters := 0
	for _, s := range list {
		if seen[s.Name] {
			t.Errorf("%s appears twice", s.Name)
		}
		seen[s.Name] = true
		if strings.HasPrefix(s.Name, "dpg-adapter-") {
			adapters++
		}
	}
	if adapters != 1 || !seen["dpg-adapter-credebl"] {
		t.Errorf("got %d adapters in %v", adapters, seen)
	}
	// Two adapters of other DPGs and the landing, which no pair owns,
	// stay out.
	want := len(Catalog()) - 2 - len(DeploymentServices())
	if len(list) != want {
		t.Errorf("got %d services, want %d", len(list), want)
	}
}

// TestLinkValuesFeedEveryService is the contract between the .env file
// and the services. Every variable a service requires at start, every
// state path, and every shared secret must reach the container under
// the name the service reads.
func TestLinkValuesFeedEveryService(t *testing.T) {
	values := map[string]string{
		"VCA_PUBLIC_URL":              "https://issuer-waltid.labs.example",
		"VCA_DPG_URL":                 "http://waltid-issuer-api:7002",
		"VCA_SECRETS_SIGNING_KEY":     "base64:QQ==",
		"VCA_SECRETS_SESSION_KEY":     "session",
		"VCA_SECRETS_BOOTSTRAP_TOKEN": "boot",
	}
	issuer := Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_WALTID}
	got := LinkValues(issuer, values)
	want := map[string]string{
		"VCA_ISSUANCE_ADAPTER_URL":              "http://issuer-waltid-dpg-adapter-waltid:8090",
		"VCA_ISSUANCE_SCHEMA_URL":               "http://issuer-waltid-schema-registry:8103",
		"VCA_ISSUANCE_STATUS_URL":               "http://issuer-waltid-status-bitstring:8104",
		"VCA_ISSUANCE_ISSUED_URL":               "http://issuer-waltid-issued-credentials:8101",
		"VCA_ISSUANCE_DATA_SOURCE_URL":          "http://issuer-waltid-data-source:8100",
		"VCA_ISSUANCE_PUBLIC_URL":               "https://issuer-waltid.labs.example",
		"VCA_SCHEMABUILDER_REGISTRY_URL":        "http://issuer-waltid-schema-registry:8103",
		"VCA_SCHEMABUILDER_CATALOG_URL":         "http://issuer-waltid-dpg-adapter-waltid:8090",
		"VCA_SCHEMABUILDER_PORTAL_URL":          "https://issuer-waltid.labs.example/portal/",
		"VCA_SCHEMA_BASE_URL":                   "https://issuer-waltid.labs.example",
		"VCA_SCHEMA_BACKEND_URL":                "http://issuer-waltid-dpg-adapter-waltid:8090",
		"VCA_SCHEMA_BUILDER_URL":                "https://issuer-waltid.labs.example/builder/",
		"VCA_SCHEMA_STORE_FILE":                 "/data/schemas.json",
		"VCA_ISSUED_STATUS_URL":                 "http://issuer-waltid-status-bitstring:8104",
		"VCA_ISSUED_STORE_FILE":                 "/data/issued.json",
		"VCA_DATASOURCE_STORE_FILE":             "/data/sources.json",
		"VCA_ISSUER_AUTH_STATE_DIR":             "/data",
		"VCA_STATUS_BITSTRING_STATE_DIR":        "/data",
		"VCA_STATUS_BITSTRING_BASE_URL":         "https://issuer-waltid.labs.example/status-bitstring",
		"VCA_STATUS_BITSTRING_SIGNING_KEY_FILE": "base64:QQ==",
		"VCA_STATUS_TOKEN_STATE_DIR":            "/data",
		"VCA_STATUS_TOKEN_SIGNING_KEY_FILE":     "base64:QQ==",
		"VCA_WALTID_ISSUER_URL":                 "http://waltid-issuer-api:7002",
	}
	for name, value := range want {
		if got[name] != value {
			t.Errorf("issuer: %s = %q, want %q", name, got[name], value)
		}
	}
	for _, name := range []string{"VCA_WALTID_WALLET_URL", "VCA_WALTID_VERIFIER_URL", "VCA_ADMIN_SIGNING_KEY"} {
		if _, ok := got[name]; ok {
			t.Errorf("issuer: %s belongs to another role", name)
		}
	}

	holder := Pair{Role: commonv1.Role_ROLE_HOLDER, Dpg: configv1.Dpg_DPG_INJI}
	values["VCA_DPG_URL"] = "http://inji-web:3000"
	got = LinkValues(holder, values)
	for name, value := range map[string]string{
		"VCA_INJI_CERTIFY_URL":               "http://inji-web:3000",
		"VCA_INJI_PUBLIC_URL":                "https://issuer-waltid.labs.example",
		"VCA_WALLET_AUTH_HOLDER_BACKEND_URL": "http://holder-inji-dpg-adapter-inji:8090",
		"VCA_WALLET_AUTH_STATE_DIR":          "/data",
	} {
		if got[name] != value {
			t.Errorf("holder: %s = %q, want %q", name, got[name], value)
		}
	}
	if _, ok := got["VCA_INJI_VERIFY_URL"]; ok {
		t.Error("holder: the verify URL belongs to the verifier")
	}

	verifier := Pair{Role: commonv1.Role_ROLE_VERIFIER, Dpg: configv1.Dpg_DPG_CREDEBL}
	values["VCA_DPG_URL"] = "http://credebl-api-gateway:5000"
	got = LinkValues(verifier, values)
	for name, value := range map[string]string{
		"VCA_CREDEBL_API_URL":                 "http://credebl-api-gateway:5000",
		"VCA_VERIFIER_COMBINED_POLICY_URL":    "http://verifier-credebl-verifier-policy:8103",
		"VCA_VERIFIER_COMBINED_RESULTS_URL":   "http://verifier-credebl-verifier-results:8080",
		"VCA_VERIFIER_COMBINED_DISCOVERY_URL": "http://verifier-credebl-verifier-discovery:8101",
		"VCA_DISCOVERY_TRUST_URL":             "http://admin-credebl-trust-registry:8100",
		"VCA_DISCOVERY_BASE_URL":              "https://issuer-waltid.labs.example",
		"VCA_DISCOVERY_PORTAL_PREFIX":         "/discovery",
		"VCA_INGEST_DISCOVERY_URL":            "http://verifier-credebl-verifier-discovery:8101",
		"VCA_INGEST_BASE_URL":                 "https://issuer-waltid.labs.example",
		"VCA_INGEST_SIGNING_KEY_FILE":         "base64:QQ==",
		"VCA_INGEST_STATE_DIR":                "/data",
		"VCA_VERIFIER_POLICY_TRUST_URL":       "http://admin-credebl-trust-registry:8100",
		"VCA_VERIFIER_RESULTS_POLICY_URL":     "http://verifier-credebl-verifier-policy:8103",
		"VCA_VERIFIER_COMBINED_STATE_DIR":     "/data",
		"VCA_VERIFIER_RESULTS_STATE_DIR":      "/data",
	} {
		if got[name] != value {
			t.Errorf("verifier: %s = %q, want %q", name, got[name], value)
		}
	}

	admin := Pair{Role: commonv1.Role_ROLE_ADMIN, Dpg: configv1.Dpg_DPG_WALTID}
	got = LinkValues(admin, values)
	for name, value := range map[string]string{
		"VCA_ADMIN_SIGNING_KEY":      "base64:QQ==",
		"VCA_ADMIN_SESSION_KEY":      "session",
		"VCA_ADMIN_BOOTSTRAP_TOKEN":  "boot",
		"VCA_TRUST_BASE_URL":         "https://issuer-waltid.labs.example/trust-registry",
		"VCA_TRUST_SIGNING_KEY_FILE": "base64:QQ==",
		"VCA_TRUST_STORE_FILE":       "/data/trust.json",
	} {
		if got[name] != value {
			t.Errorf("admin: %s = %q, want %q", name, got[name], value)
		}
	}
	// A missing source leaves the copy out, so a service falls back to
	// its own default instead of reading an empty string.
	got = LinkValues(admin, map[string]string{})
	if _, ok := got["VCA_ADMIN_SIGNING_KEY"]; ok {
		t.Error("an empty secret was copied")
	}
}

// TestEveryStatefulServiceNamesItsStatePath keeps the image and the .env
// in step: a stateful service gets a path under /data from the CLI.
func TestEveryStatefulServiceNamesItsStatePath(t *testing.T) {
	for _, s := range Catalog() {
		if !s.Stateful {
			continue
		}
		found := false
		for _, f := range s.Fixed {
			if strings.HasPrefix(f.Value, "/data") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is stateful but names no path under /data", s.Name)
		}
	}
}

// TestUIServicesAreTheOnesWithPages keeps the UI flag honest: a service
// draws pages when and only when one of its routes names a page.
func TestUIServicesAreTheOnesWithPages(t *testing.T) {
	var ui []string
	for _, s := range Catalog() {
		pages := false
		for _, r := range s.Routes {
			if r.Page != "" {
				pages = true
			}
		}
		if s.UI != pages {
			t.Errorf("%s: UI = %v but has a page route = %v", s.Name, s.UI, pages)
		}
		if s.UI {
			ui = append(ui, s.Name)
		}
	}
	want := []string{"admin", "landing", "schema-builder-ui", "schema-registry", "verifier-discovery", "verifier-ingest", "verifier-results", "wallet-portal"}
	if strings.Join(ui, ",") != strings.Join(want, ",") {
		t.Errorf("UI services = %v, want %v", ui, want)
	}
	got := UIServices()
	if len(got) != len(want) {
		t.Fatalf("UIServices = %d, want %d", len(got), len(want))
	}
	for i, s := range got {
		if s.Name != want[i] {
			t.Errorf("UIServices[%d] = %s, want %s", i, s.Name, want[i])
		}
	}
}

// TestLinkValuesWritePeers is the contract between the .env file and the
// topology package: every service that draws pages, every auth service,
// and the admin get all twelve candidate pairs with their public URL
// and the internal URL of each of their services (ADR-034 decision 1).
func TestLinkValuesWritePeers(t *testing.T) {
	p := Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_WALTID}
	compose := RenderCompose()

	// A domain setup gives every pair its own host name.
	got := LinkValues(p, map[string]string{
		"VCA_PUBLIC_URL": "https://issuer-waltid.labs.example", DomainEnv: "labs.example",
	})
	peers, err := topology.Parse(got[topology.Env])
	if err != nil {
		t.Fatalf("Parse: %v\n%s", err, got[topology.Env])
	}
	if len(peers) != len(AllPairs()) {
		t.Fatalf("got %d peers, want %d", len(peers), len(AllPairs()))
	}
	for i, peer := range peers {
		want := AllPairs()[i]
		if peer.Pair != want.Name() || peer.Role != want.Role || peer.Dpg != want.Dpg {
			t.Errorf("peer %d = %s, want %s", i, peer.Pair, want.Name())
		}
		if peer.PublicURL != "https://"+want.Name()+".labs.example" {
			t.Errorf("%s: public URL = %q", peer.Pair, peer.PublicURL)
		}
		if len(peer.Services) != len(ServicesFor(want)) {
			t.Errorf("%s: %d services, want %d", peer.Pair, len(peer.Services), len(ServicesFor(want)))
		}
		for name, url := range peer.Services {
			host := strings.TrimPrefix(url, "http://")
			host = host[:strings.Index(host, ":")]
			if !strings.Contains(compose, "\n  "+host+":\n") {
				t.Errorf("%s: the service %s points at %s, which the compose file does not render", peer.Pair, name, host)
			}
		}
		if peer.Home() == "" {
			t.Errorf("%s: no home service", peer.Pair)
		}
		if want.Role != commonv1.Role_ROLE_ADMIN && peer.Adapter() == "" {
			t.Errorf("%s: no adapter", peer.Pair)
		}
	}

	// A local setup gives every pair the host port of its home service.
	got = LinkValues(p, map[string]string{"VCA_PUBLIC_URL": LocalPublicURL(p)})
	peers, err = topology.Parse(got[topology.Env])
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for i, peer := range peers {
		if peer.PublicURL != LocalPublicURL(AllPairs()[i]) {
			t.Errorf("%s: public URL = %q, want %q", peer.Pair, peer.PublicURL, LocalPublicURL(AllPairs()[i]))
		}
	}
	if !strings.HasPrefix(peers[0].PublicURL, "http://localhost:") {
		t.Errorf("local public URL = %q", peers[0].PublicURL)
	}

	// The own pair keeps the public URL the operator chose.
	got = LinkValues(p, map[string]string{"VCA_PUBLIC_URL": "https://credentials.example/"})
	peers, err = topology.Parse(got[topology.Env])
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if peers[0].PublicURL != "https://credentials.example" {
		t.Errorf("own public URL = %q", peers[0].PublicURL)
	}
}

// TestPeersHonourThePortOverridesOfEveryPair keeps the internal URLs
// true when a pair moved its portal, auth, or adapter port.
func TestPeersHonourThePortOverridesOfEveryPair(t *testing.T) {
	p := Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_WALTID}
	overrides := PeerOverrides{
		"holder-inji": {"VCA_PORTS_PORTAL": "9090", "VCA_PUBLIC_URL": "https://wallet.example"},
	}
	got := LinkValuesWith(p, map[string]string{"VCA_PUBLIC_URL": LocalPublicURL(p), "VCA_PORTS_ADAPTER": "9500"}, overrides)
	peers, err := topology.Parse(got[topology.Env])
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	byName := map[string]topology.Peer{}
	for _, peer := range peers {
		byName[peer.Pair] = peer
	}
	if byName["holder-inji"].Home() != "http://holder-inji-wallet-portal:9090" {
		t.Errorf("holder-inji home = %q", byName["holder-inji"].Home())
	}
	if byName["holder-inji"].PublicURL != "https://wallet.example" {
		t.Errorf("holder-inji public URL = %q", byName["holder-inji"].PublicURL)
	}
	if byName["issuer-waltid"].Adapter() != "http://issuer-waltid-dpg-adapter-waltid:9500" {
		t.Errorf("own adapter = %q", byName["issuer-waltid"].Adapter())
	}
	if byName["holder-waltid"].Home() != "http://holder-waltid-wallet-portal:8080" {
		t.Errorf("an untouched pair keeps its default: %q", byName["holder-waltid"].Home())
	}
}

// TestPeersReachTheRightServices names the services that read VCA_PEERS.
func TestPeersReachTheRightServices(t *testing.T) {
	want := map[string]bool{
		"admin": true, "schema-builder-ui": true, "schema-registry": true, "verifier-discovery": true,
		"verifier-ingest": true, "verifier-results": true, "wallet-portal": true,
		"issuer-auth": true, "wallet-auth": true, "landing": true,
	}
	for _, s := range Catalog() {
		has := false
		for _, l := range s.Links {
			if l.Kind == LinkPeers {
				has = true
				if l.Env != topology.Env {
					t.Errorf("%s: the peers link writes %s, want %s", s.Name, l.Env, topology.Env)
				}
			}
		}
		if has != want[s.Name] {
			t.Errorf("%s: reads peers = %v, want %v", s.Name, has, want[s.Name])
		}
	}
}

// TestHomeAndAuthServicesAgreeWithTheTopology keeps the CLI routes and
// the topology package on one table.
func TestHomeAndAuthServicesAgreeWithTheTopology(t *testing.T) {
	for _, r := range Roles() {
		if HomeOf(r).Service != topology.HomeService(r) {
			t.Errorf("%v: home %s, topology says %s", r, HomeOf(r).Service, topology.HomeService(r))
		}
		if authService(r) != topology.AuthService(r) {
			t.Errorf("%v: auth %s, topology says %s", r, authService(r), topology.AuthService(r))
		}
	}
}

// TestDeploymentServicesAreNotInPairs is the rule of a deployment scoped
// service (ADR-033 decision 2): it runs once, so no pair lists it, no
// pair assigns it a port, and no role table names its routes. The
// landing is the one such service. It listens on 8080 in the container
// and on the host port 17900.
func TestDeploymentServicesAreNotInPairs(t *testing.T) {
	var scoped []Service
	for _, s := range Catalog() {
		if s.Scope == ScopeDeployment {
			scoped = append(scoped, s)
		}
	}
	if len(scoped) != 1 || scoped[0].Name != "landing" {
		t.Fatalf("deployment scoped services = %+v, want the landing alone", scoped)
	}
	landing := scoped[0]
	if !landing.UI || landing.Stateful || landing.ExposedPort != LandingListenPort || landing.ListenEnv != "VCA_LANDING_LISTEN" {
		t.Errorf("landing = %+v", landing)
	}
	if LandingHostPort != 17900 || LandingListenPort != 8080 {
		t.Errorf("landing ports = %d and %d", LandingHostPort, LandingListenPort)
	}
	if len(landing.Roles) != len(Roles()) {
		t.Errorf("the landing serves %d roles, want every role", len(landing.Roles))
	}
	got := DeploymentServices()
	if len(got) != 1 || got[0].Name != "landing" {
		t.Errorf("DeploymentServices = %+v", got)
	}
	for _, p := range AllPairs() {
		for _, s := range ServicesFor(p) {
			if s.Scope == ScopeDeployment {
				t.Errorf("%s lists the deployment scoped service %s", p.Name(), s.Name)
			}
		}
		for _, a := range AssignPorts(p, nil) {
			if a.Service.Name == "landing" {
				t.Errorf("%s assigns a port to the landing", p.Name())
			}
		}
		for _, sr := range PairRoutes(p, nil) {
			if sr.Service == "landing" {
				t.Errorf("%s routes the landing", p.Name())
			}
		}
	}
	for _, d := range Dpgs() {
		for _, s := range deploymentServices(d) {
			if s.Scope == ScopeDeployment {
				t.Errorf("the admin service map of %v names the landing", d)
			}
		}
	}
	if strings.Contains(RouteTable(), "landing") {
		t.Error("the route table of the roles names the landing")
	}
	if ChartCondition(landing) != "" {
		t.Errorf("the landing chart has the condition %q; it is always on", ChartCondition(landing))
	}
}

// TestLandingValuesHoldThePeersAndTheAddress checks the .env of the
// landing (ADR-033 decision 2, ADR-034 decision 1): the listen address,
// the public URL under the domain or on localhost, every candidate pair
// with the overrides of the pair directories, and the image version.
func TestLandingValuesHoldThePeersAndTheAddress(t *testing.T) {
	overrides := PeerOverrides{
		"holder-inji":   {"VCA_PORTS_PORTAL": "9090", "VCA_PUBLIC_URL": "https://wallet.example"},
		"issuer-waltid": {"VCA_PORTS_ADAPTER": "9500"},
	}
	got := LandingValues("", overrides, "")
	if got["VCA_LANDING_LISTEN"] != ":8080" || got["VCA_LANDING_PUBLIC_URL"] != "http://localhost:17900" || got[VersionEnv] != "latest" {
		t.Errorf("local values = %v", got)
	}
	peers, err := topology.Parse(got[topology.Env])
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(peers) != len(AllPairs()) {
		t.Fatalf("got %d peers, want %d", len(peers), len(AllPairs()))
	}
	byName := map[string]topology.Peer{}
	for _, peer := range peers {
		byName[peer.Pair] = peer
	}
	if byName["holder-inji"].Home() != "http://holder-inji-wallet-portal:9090" || byName["holder-inji"].PublicURL != "https://wallet.example" {
		t.Errorf("holder-inji = %+v", byName["holder-inji"])
	}
	if byName["issuer-waltid"].Adapter() != "http://issuer-waltid-dpg-adapter-waltid:9500" {
		t.Errorf("issuer-waltid adapter = %q", byName["issuer-waltid"].Adapter())
	}
	if byName["verifier-credebl"].PublicURL != LocalPublicURL(Pair{Role: commonv1.Role_ROLE_VERIFIER, Dpg: configv1.Dpg_DPG_CREDEBL}) {
		t.Errorf("an untouched pair gets its localhost address: %q", byName["verifier-credebl"].PublicURL)
	}

	got = LandingValues("labs.example", overrides, "local")
	if got["VCA_LANDING_PUBLIC_URL"] != "https://vca.labs.example" || got[VersionEnv] != "local" {
		t.Errorf("domain values = %v", got)
	}
	peers, err = topology.Parse(got[topology.Env])
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, peer := range peers {
		if peer.PublicURL != "https://"+peer.Pair+".labs.example" {
			t.Errorf("%s: public URL = %q", peer.Pair, peer.PublicURL)
		}
	}
	if LandingPublicURL("") != "http://localhost:17900" || LandingPublicURL("labs.example") != "https://vca.labs.example" {
		t.Error("LandingPublicURL")
	}
}
