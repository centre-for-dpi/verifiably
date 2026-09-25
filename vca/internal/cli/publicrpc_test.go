// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1/adminv1connect"
	_ "github.com/centre-for-dpi/vc-adapters/gen/vca/audit/v1/auditv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/issuerauth/v1/issuerauthv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/verifierauth/v1/verifierauthv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/walletauth/v1/walletauthv1connect"
)

// checkedRPC is the allowlist of ADR-047 decision 1. Each key is
// "<service> <Connect service>": a Connect service that the reverse
// proxy may publish on the host name of a pair. Each value names the
// test, as "<file under vca>:<test name>", that calls every RPC of the
// service with no credential and sees it refused. A service that is
// not here stays on the compose network.
var checkedRPC = map[string]string{
	"admin " + adminv1connect.AdminServiceName: "services/admin/internal/app/public_test.go:TestAnonymousRPCsAreRefused",

	"issuer-auth " + adminv1connect.AdminServiceName:                 "services/issuer-auth/internal/server/public_test.go:TestAnonymousRPCsAreRefused",
	"issuer-auth " + issuerauthv1connect.IssuerAuthServiceName:       "services/issuer-auth/internal/server/public_test.go:TestAnonymousRPCsAreRefused",
	"verifier-auth " + adminv1connect.AdminServiceName:               "services/verifier-auth/internal/server/public_test.go:TestAnonymousRPCsAreRefused",
	"verifier-auth " + verifierauthv1connect.VerifierAuthServiceName: "services/verifier-auth/internal/server/public_test.go:TestAnonymousRPCsAreRefused",
	"wallet-auth " + adminv1connect.AdminServiceName:                 "services/wallet-auth/internal/server/public_test.go:TestAnonymousRPCsAreRefused",
	"wallet-auth " + walletauthv1connect.WalletAuthServiceName:       "services/wallet-auth/internal/server/public_test.go:TestAnonymousRPCsAreRefused",
}

// rpcOf returns the Connect service a route publishes, or "" for a
// plain HTTP route. The path the service sees counts, so a strip route
// that ends on a Connect path counts too.
func rpcOf(r Route) string {
	path := strings.TrimPrefix(r.Match, r.StripPrefix())
	name, _, _ := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	if !strings.HasPrefix(name, "vca.") {
		return ""
	}
	return name
}

// TestNoUnguardedRPCIsPublic is ADR-047 decision 1: a public route that
// names a Connect service must name one of the allowlist, and every
// entry of the allowlist names a test that exists.
func TestNoUnguardedRPCIsPublic(t *testing.T) {
	published := map[string]bool{}
	for _, p := range AllPairs() {
		for _, sr := range PairRoutes(p, nil) {
			name := rpcOf(sr.Route)
			if name == "" {
				if strings.Contains(sr.Route.Match, "/vca.") {
					t.Errorf("%s: %s routes %s, which holds a Connect path", p.Name(), sr.Service, sr.Route.Match)
				}
				continue
			}
			key := sr.Service + " " + name
			if _, ok := checkedRPC[key]; !ok {
				t.Errorf("%s: %s publishes %s, which has no caller check on the allowlist (ADR-047)", p.Name(), sr.Service, name)
			}
			published[key] = true
		}
	}
	for key, proof := range checkedRPC {
		if !published[key] {
			t.Errorf("the allowlist holds %s, which no pair publishes", key)
		}
		file, test, ok := strings.Cut(proof, ":")
		if !ok {
			t.Errorf("%s: proof %q is not <file>:<test>", key, proof)
			continue
		}
		data, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(file))) // #nosec G304 -- a fixed test path
		if err != nil {
			t.Errorf("%s: %v", key, err)
			continue
		}
		if !strings.Contains(string(data), "func "+test+"(t *testing.T)") {
			t.Errorf("%s: %s has no %s", key, file, test)
		}
	}
}

// TestPlainRoutesPublishNoConnectService checks the prefix services:
// the proxy publishes the status lists, the trust lists, and their key
// sets, and never the Connect service behind the same prefix.
func TestPlainRoutesPublishNoConnectService(t *testing.T) {
	want := map[string][]string{
		"status-bitstring": {"/status-bitstring/status/*", "/status-bitstring/.well-known/jwks.json"},
		"status-token":     {"/status-token/status/*", "/status-token/.well-known/jwks.json"},
		"trust-registry": {
			"/trust-registry/trust-list/*", "/trust-registry/.well-known/*",
			"/trust-registry/dedi/*", "/trust-registry/trust/*",
		},
	}
	for _, s := range Catalog() {
		matches, ok := want[s.Name]
		if !ok {
			continue
		}
		var got []string
		for _, r := range s.Routes {
			if !r.Strip || r.StripPrefix() != "/"+s.Name {
				t.Errorf("%s: route %s does not strip /%s", s.Name, r.Match, s.Name)
			}
			got = append(got, r.Match)
		}
		if strings.Join(got, " ") != strings.Join(matches, " ") {
			t.Errorf("%s routes %v, want %v", s.Name, got, matches)
		}
	}
	// A service with no public caller keeps no route at all.
	for _, s := range Catalog() {
		switch s.Name {
		case "verifier-combined", "verifier-policy", "dpg-adapter-waltid", "dpg-adapter-credebl":
			if len(s.Routes) != 0 {
				t.Errorf("%s is internal but routes %+v", s.Name, s.Routes)
			}
		case "data-source":
			// The bulk issuance pages are public behind the staff guard;
			// the DataSourceService stays on the compose network.
			if len(s.Routes) != 1 || s.Routes[0].Match != "/sources/*" || s.Routes[0].Page == "" {
				t.Errorf("data-source routes %+v, want its page only", s.Routes)
			}
		}
	}
}

// TestCaddyfileRefusesEveryOtherRPC is ADR-047 decision 2. The last
// handle block sends every unnamed path to the home service, so the
// Caddyfile refuses every other Connect path before it gets there. A
// strip route that takes a whole prefix gets the same refusal under
// that prefix.
func TestCaddyfileRefusesEveryOtherRPC(t *testing.T) {
	for _, p := range AllPairs() {
		got := Caddyfile(p, map[string]string{"VCA_PUBLIC_URL": "https://" + p.Name() + ".example"})
		refused := RefusedRoutes(p)
		if len(refused) == 0 || refused[0] != "/vca.*" {
			t.Errorf("%s: refused %v", p.Name(), refused)
		}
		for _, match := range refused {
			block := "\thandle " + match + " {\n\t\trespond 404\n\t}\n"
			if strings.Count(got, block) != 1 {
				t.Errorf("%s: the Caddyfile has %d %q:\n%s", p.Name(), strings.Count(got, block), block, got)
			}
			if strings.Index(got, block) > strings.Index(got, "\thandle / {") {
				t.Errorf("%s: the refusal of %s comes after the home routes", p.Name(), match)
			}
		}
		for _, sr := range PairRoutes(p, nil) {
			prefix := sr.Route.StripPrefix()
			if prefix == "" || sr.Route.Match != prefix+"/*" {
				continue
			}
			if !strings.Contains(got, "\thandle "+prefix+"/vca.* {\n\t\trespond 404\n") {
				t.Errorf("%s: %s takes %s, but the Caddyfile does not refuse %s/vca.*", p.Name(), sr.Service, sr.Route.Match, prefix)
			}
		}
	}
	holder := Pair{Role: commonv1.Role_ROLE_HOLDER, Dpg: configv1.Dpg_DPG_INJI}
	if got := RefusedRoutes(holder); strings.Join(got, " ") != "/vca.* /auth/vca.*" {
		t.Errorf("holder refused %v", got)
	}
}

// connectServices lists every Connect service of the generated code.
func connectServices() []string {
	var out []string
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if !strings.HasPrefix(string(fd.Package()), "vca.") {
			return true
		}
		for i := 0; i < fd.Services().Len(); i++ {
			out = append(out, string(fd.Services().Get(i).FullName()))
		}
		return true
	})
	sort.Strings(out)
	return out
}

// TestDeployDocClassifiesEveryRPC keeps the table "What the proxy
// publishes" of docs/deploy.md in step with the allowlist: one row per
// Connect service, and a public row only for an allowlisted service.
func TestDeployDocClassifiesEveryRPC(t *testing.T) {
	doc := readText(t, filepath.Join(docsDir(), "deploy.md"))
	_, section, ok := strings.Cut(doc, "\n## What the proxy publishes\n")
	if !ok {
		t.Fatal("docs/deploy.md has no section \"What the proxy publishes\"")
	}
	if end := strings.Index(section, "\n## "); end >= 0 {
		section = section[:end]
	}
	rows := map[string]bool{}
	public := map[string]bool{}
	for _, line := range strings.Split(section, "\n") {
		cells := strings.Split(line, "|")
		if len(cells) < 5 || !strings.HasPrefix(strings.TrimSpace(cells[1]), "`vca.") {
			continue
		}
		name := strings.Trim(strings.TrimSpace(cells[1]), "`")
		rows[name] = true
		reach := strings.TrimSpace(cells[3])
		if reach != "Public" && reach != "Compose network" {
			t.Errorf("%s: reach %q, want Public or Compose network", name, reach)
		}
		for _, server := range strings.Split(cells[2], ",") {
			server = strings.Trim(strings.TrimSpace(server), "`")
			if reach == "Public" {
				public[server+" "+name] = true
				if _, ok := checkedRPC[server+" "+name]; !ok {
					t.Errorf("the doc says %s on %s is public, but the allowlist does not hold it", name, server)
				}
			}
		}
	}
	services := connectServices()
	if len(services) < 20 {
		t.Fatalf("the registry holds only %v", services)
	}
	for _, name := range services {
		if !rows[name] {
			t.Errorf("docs/deploy.md has no row for %s", name)
		}
	}
	for key := range checkedRPC {
		if !public[key] {
			t.Errorf("docs/deploy.md does not name %s as public", key)
		}
	}
}
