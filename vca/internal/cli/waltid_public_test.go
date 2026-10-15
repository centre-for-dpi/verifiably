// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
)

// TestSetupWritesTheWaltidWalletFacingAddresses: the walt.id issuer API
// names itself in every credential offer, and the verifier APIs in
// every presentation request, so a wallet outside the host needs their
// public addresses. Setup writes the base URL of each into the .env of
// the pair that runs it, and the Caddyfile of that pair publishes the
// host under a base domain. A local deployment names the host port.
func TestSetupWritesTheWaltidWalletFacingAddresses(t *testing.T) {
	local := planEnv(t, SetupRequest{Pair: waltidPair(commonv1.Role_ROLE_ISSUER)})
	if local[WaltidIssuerBaseURLEnv] != "http://localhost:17002" {
		t.Errorf("issuer local: %q", local[WaltidIssuerBaseURLEnv])
	}
	want := map[commonv1.Role]map[string]string{
		commonv1.Role_ROLE_ISSUER: {WaltidIssuerBaseURLEnv: "https://waltid-issuer-api.labs.example"},
		commonv1.Role_ROLE_VERIFIER: {
			WaltidVerifierBaseURLEnv:  "https://waltid-verifier-api.labs.example",
			WaltidVerifier2BaseURLEnv: "https://waltid-verifier-api2.labs.example",
		},
	}
	sites := map[string]string{
		"waltid-issuer-api.labs.example":    "17002",
		"waltid-verifier-api.labs.example":  "17003",
		"waltid-verifier-api2.labs.example": "17004",
	}
	for role, vars := range want {
		p := waltidPair(role)
		plan := planOf(t, SetupRequest{Pair: p, Domain: "labs.example"})
		env, err := ParseDotenv(strings.NewReader(planFile(t, plan, EnvFileName)))
		if err != nil {
			t.Fatal(err)
		}
		for name, value := range vars {
			if env[name] != value {
				t.Errorf("%s: %s = %q, want %q", p.Name(), name, env[name], value)
			}
		}
		caddy := planFile(t, plan, CaddyFile)
		for host, port := range sites {
			site := host + " {\n\treverse_proxy 127.0.0.1:" + port + "\n}\n"
			owns := (role == commonv1.Role_ROLE_ISSUER) == strings.HasPrefix(host, "waltid-issuer-")
			if owns != strings.Contains(caddy, site) {
				t.Errorf("%s: the Caddyfile and the site %q:\n%s", p.Name(), site, caddy)
			}
		}
	}
	for _, role := range []commonv1.Role{commonv1.Role_ROLE_HOLDER, commonv1.Role_ROLE_ADMIN} {
		env := planEnv(t, SetupRequest{Pair: waltidPair(role), Domain: "labs.example"})
		for _, name := range []string{WaltidIssuerBaseURLEnv, WaltidVerifierBaseURLEnv, WaltidVerifier2BaseURLEnv} {
			if _, ok := env[name]; ok {
				t.Errorf("%s runs no %s", waltidPair(role).Name(), name)
			}
		}
	}
}
