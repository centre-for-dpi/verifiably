// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1/adminv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/combined/v1/combinedv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1/datasourcev1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1/discoveryv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1/ingestv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1/issuancev1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1/issuedv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/issuerauth/v1/issuerauthv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1/policyv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1/resultsv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1/schemav1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/schemabuilder/v1/schemabuilderv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1/statusv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/verifierauth/v1/verifierauthv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/walletauth/v1/walletauthv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1/walletportalv1connect"
)

// TestRoutesDoNotCollideInAPair is the rule of the route table: one host
// name per pair, so no two services of a pair share a path matcher.
func TestRoutesDoNotCollideInAPair(t *testing.T) {
	for _, p := range AllPairs() {
		seen := map[string]string{}
		for _, sr := range PairRoutes(p, nil) {
			if other, ok := seen[sr.Route.Match]; ok && other != sr.Service {
				t.Errorf("%s: %s and %s both route %s", p.Name(), other, sr.Service, sr.Route.Match)
			}
			seen[sr.Route.Match] = sr.Service
		}
		if _, ok := seen["/"]; ok {
			t.Errorf("%s: a service routes the root, which the home redirect owns", p.Name())
		}
	}
}

func TestEveryServiceHasAWellFormedRoute(t *testing.T) {
	for _, s := range Catalog() {
		if len(s.Routes) == 0 {
			t.Errorf("%s has no route", s.Name)
		}
		for _, r := range s.Routes {
			if !strings.HasPrefix(r.Match, "/") {
				t.Errorf("%s: route %q does not start with a slash", s.Name, r.Match)
			}
			if strings.ContainsAny(r.Match, " \t{}") {
				t.Errorf("%s: route %q holds a space or a brace", s.Name, r.Match)
			}
			if r.Strip && !strings.HasSuffix(r.Match, "/*") {
				t.Errorf("%s: strip route %q is not a prefix", s.Name, r.Match)
			}
			if r.Page != "" && !strings.HasSuffix(r.Match, "/*") {
				t.Errorf("%s: page route %q is not a prefix", s.Name, r.Match)
			}
		}
	}
	for _, p := range AllPairs() {
		for _, s := range ServicesFor(p) {
			if len(s.Routes) == 0 {
				t.Errorf("%s: %s has no route", p.Name(), s.Name)
			}
		}
	}
}

// TestConnectRoutesMatchTheGeneratedNames keeps the route table equal
// to the service names of the generated Connect code.
func TestConnectRoutesMatchTheGeneratedNames(t *testing.T) {
	names := map[string]bool{}
	for _, n := range []string{
		adminv1connect.AdminServiceName,
		backendv1connect.CapabilityServiceName, backendv1connect.IssuerBackendServiceName,
		backendv1connect.HolderBackendServiceName, backendv1connect.VerifierBackendServiceName,
		backendv1connect.CatalogBackendServiceName,
		combinedv1connect.CombinedServiceName, datasourcev1connect.DataSourceServiceName,
		discoveryv1connect.DiscoveryServiceName, ingestv1connect.IngestServiceName,
		issuancev1connect.IssuanceServiceName, issuedv1connect.IssuedServiceName,
		issuerauthv1connect.IssuerAuthServiceName, policyv1connect.PolicyServiceName, verifierauthv1connect.VerifierAuthServiceName,
		resultsv1connect.ResultsServiceName, schemav1connect.SchemaServiceName,
		schemabuilderv1connect.SchemaBuilderServiceName, statusv1connect.StatusServiceName,
		trustv1connect.TrustServiceName, walletauthv1connect.WalletAuthServiceName,
		walletportalv1connect.WalletPortalServiceName,
	} {
		names[n] = true
	}
	for _, s := range Catalog() {
		for _, r := range s.Routes {
			if !strings.HasPrefix(r.Match, "/vca.") {
				continue
			}
			name := strings.TrimSuffix(strings.TrimPrefix(r.Match, "/"), "/*")
			if !names[name] {
				t.Errorf("%s: %q is not a generated Connect service", s.Name, r.Match)
			}
		}
	}
	// The status services and the trust registry sit behind a prefix, so
	// their Connect names do not appear at the root.
	for _, s := range Catalog() {
		switch s.Name {
		case "status-bitstring", "status-token", "trust-registry":
			if len(s.Routes) != 1 || !s.Routes[0].Strip || s.Routes[0].Match != "/"+s.Name+"/*" {
				t.Errorf("%s routes = %+v", s.Name, s.Routes)
			}
		}
	}
}

func TestHomeOfEveryRoleIsARoutedPage(t *testing.T) {
	if HomeOf(commonv1.Role_ROLE_UNSPECIFIED) != (Home{}) {
		t.Error("an unknown role has a home")
	}
	// ADR-044 decision 1 moves the issuer home to issuance at /issuer/.
	want := map[commonv1.Role]Home{
		commonv1.Role_ROLE_ISSUER:   {Service: "issuance", Path: "/issuer/"},
		commonv1.Role_ROLE_HOLDER:   {Service: "wallet-portal", Path: "/wallet/"},
		commonv1.Role_ROLE_VERIFIER: {Service: "verifier-results", Path: "/portal/"},
		commonv1.Role_ROLE_ADMIN:    {Service: "admin", Path: "/admin/"},
	}
	for _, r := range Roles() {
		home := HomeOf(r)
		if home != want[r] {
			t.Errorf("HomeOf(%s) = %+v, want %+v", r, home, want[r])
		}
		p := Pair{Role: r, Dpg: configv1.Dpg_DPG_WALTID}
		found := false
		for _, sr := range PairRoutes(p, nil) {
			if sr.Service == home.Service && sr.Route.Path() == home.Path && sr.Route.Page != "" {
				found = true
			}
			// Only the home service routes the shared assets.
			if sr.Route.Match == "/static/*" && sr.Service != home.Service {
				t.Errorf("%s: %s routes /static/*", p.Name(), sr.Service)
			}
		}
		if !found {
			t.Errorf("%s: the home %+v is not a page route", p.Name(), home)
		}
		if !strings.HasSuffix(home.Path, "/") {
			t.Errorf("%s: home path %q has no trailing slash", p.Name(), home.Path)
		}
	}
}

// TestAuthRoutesGoToTheAuthService is rule b of the route table.
func TestAuthRoutesGoToTheAuthService(t *testing.T) {
	want := map[commonv1.Role]string{
		commonv1.Role_ROLE_ISSUER:   "issuer-auth",
		commonv1.Role_ROLE_HOLDER:   "wallet-auth",
		commonv1.Role_ROLE_ADMIN:    "admin",
		commonv1.Role_ROLE_VERIFIER: "verifier-auth",
	}
	for role, auth := range want {
		p := Pair{Role: role, Dpg: configv1.Dpg_DPG_INJI}
		found := map[string]bool{}
		for _, sr := range PairRoutes(p, nil) {
			switch sr.Route.Match {
			case "/auth/*", "/.well-known/jwks.json", "/token":
				found[sr.Route.Match] = true
				if sr.Service != auth {
					t.Errorf("%s: %s routes %s", p.Name(), sr.Service, sr.Route.Match)
				}
			}
		}
		if !found["/auth/*"] || !found["/.well-known/jwks.json"] {
			t.Errorf("%s: the auth routes are %v", p.Name(), found)
		}
	}
	// The verifier pair routes the token endpoint and both Connect
	// services of its auth service (ADR-036 decision 1).
	verifier := Pair{Role: commonv1.Role_ROLE_VERIFIER, Dpg: configv1.Dpg_DPG_WALTID}
	routes := map[string]string{}
	for _, sr := range PairRoutes(verifier, nil) {
		routes[sr.Route.Match] = sr.Service
	}
	for _, match := range []string{"/token", "/vca.verifierauth.v1.VerifierAuthService/*", "/vca.admin.v1.AdminService/*"} {
		if routes[match] != "verifier-auth" {
			t.Errorf("verifier: %s routes %q", match, routes[match])
		}
	}
	// wallet-auth mounts the login endpoints at the root, so the proxy
	// removes /auth. issuer-auth and admin mount them under /auth.
	for _, s := range Catalog() {
		for _, r := range s.Routes {
			if r.Match == "/auth/*" && r.Strip != (s.Name == "wallet-auth") {
				t.Errorf("%s: /auth/* strip = %v", s.Name, r.Strip)
			}
		}
	}
}

func TestPagesListsTheHomeFirst(t *testing.T) {
	verifier := Pair{Role: commonv1.Role_ROLE_VERIFIER, Dpg: configv1.Dpg_DPG_CREDEBL}
	pages := Pages(verifier, "https://verifier.example/")
	if len(pages) != 5 || pages[0].URL != "https://verifier.example/portal/" || pages[0].Service != "verifier-results" {
		t.Errorf("pages = %+v", pages)
	}
	urls := map[string]bool{}
	for _, page := range pages {
		urls[page.URL] = true
	}
	for _, want := range []string{
		"https://verifier.example/verify/", "https://verifier.example/discovery/", "https://verifier.example/scan/",
		"https://verifier.example/auth/",
	} {
		if !urls[want] {
			t.Errorf("pages have no %s: %+v", want, pages)
		}
	}
	admin := Pair{Role: commonv1.Role_ROLE_ADMIN, Dpg: configv1.Dpg_DPG_WALTID}
	if got := Pages(admin, "https://admin.example"); len(got) != 1 || got[0].Title != "Admin portal" {
		t.Errorf("admin pages = %+v", got)
	}
}

func TestRouteTableHoldsEveryRoleAndTheDocHoldsIt(t *testing.T) {
	table := RouteTable()
	for _, r := range Roles() {
		if !strings.Contains(table, "The `"+ShortName(r.String())+"` role.") {
			t.Errorf("the table has no %v role:\n%s", r, table)
		}
	}
	for _, want := range []string{
		"| `/portal/*` | `schema-registry` | A page: Schemas. |",
		"| `/status-token/*` | `status-token` | The service sees the path without `/status-token`. |",
		"| `/` | `wallet-portal` | Sends the browser to `/wallet/`. |",
		"| Every other path | `admin` | |",
	} {
		if !strings.Contains(table, want) {
			t.Errorf("the table has no %q:\n%s", want, table)
		}
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "getting-started.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), table) {
		t.Errorf("docs/getting-started.md does not hold the route table:\n%s", table)
	}
}

func TestPairRoutesHonourAHostPortOverride(t *testing.T) {
	values := map[string]string{"VCA_HOST_PORT_ISSUER_AUTH": "28004"}
	for _, sr := range PairRoutes(issuerPair(), values) {
		if sr.Service == "issuer-auth" && sr.Host != 28004 {
			t.Errorf("issuer-auth host = %d", sr.Host)
		}
		if sr.Service == "schema-registry" && sr.Host != 18006 {
			t.Errorf("schema-registry host = %d", sr.Host)
		}
	}
}

// TestCaddyfileHasNoCollidingHandle parses every rendered Caddyfile and
// checks that each handle names one path once.
func TestCaddyfileEveryPairRendersEveryRoute(t *testing.T) {
	for _, p := range AllPairs() {
		got := Caddyfile(p, map[string]string{"VCA_PUBLIC_URL": "https://" + p.Name() + ".example"})
		for _, sr := range PairRoutes(p, nil) {
			directive := "handle"
			if sr.Route.Strip {
				directive = "handle_path"
			}
			line := "\t" + directive + " " + sr.Route.Match + " {\n"
			if strings.Count(got, line) != 1 {
				t.Errorf("%s: %q appears %d times", p.Name(), line, strings.Count(got, line))
			}
		}
		home := HomeOf(p.Role)
		if !strings.Contains(got, "\t\tredir * "+home.Path+" 302\n") {
			t.Errorf("%s: no root redirect to %s:\n%s", p.Name(), home.Path, got)
		}
	}
}

func TestBindAddress(t *testing.T) {
	cases := map[string]string{
		"https://issuer.example":  LoopbackAddress,
		"https://issuer.example/": LoopbackAddress,
		"http://10.0.0.5:18006":   LoopbackAddress,
		"http://localhost:18006":  "",
		"http://127.0.0.1:18006":  "",
		"":                        "",
		"not a url":               "",
	}
	for public, want := range cases {
		got, ok := BindAddress(map[string]string{"VCA_PUBLIC_URL": public})
		if got != want || ok != (want != "") {
			t.Errorf("%q: got %q, %v", public, got, ok)
		}
	}
}

func TestBuildPlanWritesTheBindAddressForAPublicHost(t *testing.T) {
	flags := baseFlags()
	flags["VCA_PUBLIC_URL"] = "https://issuer-waltid.labs.example"
	plan, err := BuildPlan(SetupRequest{Pair: issuerPair(), Flags: flags, Random: rand.Reader})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	env := string(plan.Files[0].Data)
	if !strings.Contains(env, "\n"+BindEnv+"=127.0.0.1\n") {
		t.Errorf("a public host got no bind address:\n%s", env)
	}
	// A laptop keeps the compose default, so the ports answer on every
	// interface.
	flags["VCA_PUBLIC_URL"] = "http://localhost:18006"
	plan, err = BuildPlan(SetupRequest{Pair: issuerPair(), Flags: flags, Random: rand.Reader})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if env := string(plan.Files[0].Data); strings.Contains(env, BindEnv+"=") {
		t.Errorf("a local host got a bind address:\n%s", env)
	}
}

// TestEveryPublishedPortBindsToVcaBind covers the generated compose
// file and the three hand written DPG stack files.
func TestEveryPublishedPortBindsToVcaBind(t *testing.T) {
	files := map[string]string{ComposeFile: RenderCompose()}
	for _, name := range DpgStackFiles() {
		data, err := os.ReadFile(filepath.Join(repoRoot(), "deploy", "vca", name)) // #nosec G304 -- a fixed test path
		if err != nil {
			t.Fatal(err)
		}
		files[name] = string(data)
	}
	for name, text := range files {
		var doc composeDoc
		if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for svcName, svc := range doc.Services {
			for _, port := range svc.Ports {
				if !strings.HasPrefix(port, "${"+BindEnv+":-0.0.0.0}:") {
					t.Errorf("%s: %s publishes %q without %s", name, svcName, port, BindEnv)
				}
			}
		}
	}
}

// TestDpgStacksMountTheRealmDirectory keeps the Keycloak import mount
// on the stack directory that holds the four role realms, and the
// administrator password in the .env of that directory
// (ADR-035 decisions 1 and 7). No default password ships.
func TestDpgStacksMountTheRealmDirectory(t *testing.T) {
	for _, d := range Dpgs() {
		name := ShortName(d.String())
		data, err := os.ReadFile(filepath.Join(repoRoot(), "deploy", "vca", "dpg", name+".yaml")) // #nosec G304 -- a fixed test path
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		for _, want := range []string{
			"- ../" + KeycloakDir(d) + ":/opt/keycloak/data/import:ro",
			"- path: ../" + KeycloakEnvFile(d) + "\n        required: true",
		} {
			if !strings.Contains(text, want) {
				t.Errorf("dpg/%s.yaml does not hold %q", name, want)
			}
		}
		for _, banned := range []string{"_REALM_DIR", KeycloakAdminPasswordEnv + ":", KeycloakAdminEnv + ":", "-admin}"} {
			if strings.Contains(text, banned) {
				t.Errorf("dpg/%s.yaml still holds %q", name, banned)
			}
		}
	}
}

// TestIssuancePagesAreRouted checks that the issuance service serves the
// issuer home and its pages, and that it took the shared assets over
// from the schema registry (ADR-044 decision 1).
func TestIssuancePagesAreRouted(t *testing.T) {
	p := Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_WALTID}
	pages := map[string]bool{}
	assets := ""
	for _, sr := range PairRoutes(p, nil) {
		if sr.Route.Match == "/static/*" {
			assets = sr.Service
		}
		if sr.Service == "issuance" && sr.Route.Page != "" {
			pages[sr.Route.Match] = true
		}
	}
	for _, match := range []string{"/issuer/*", "/identity/*", "/issue/*", "/notifications/*", "/help/*"} {
		if !pages[match] {
			t.Errorf("issuance does not serve the page %s: %v", match, pages)
		}
	}
	if assets != "issuance" {
		t.Errorf("/static/* goes to %q, want issuance", assets)
	}
	for _, s := range Catalog() {
		if s.Name == "issuance" && !s.UI {
			t.Error("issuance draws pages, so it must read the theme file")
		}
	}
}
