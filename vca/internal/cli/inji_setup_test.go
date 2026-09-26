// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"strings"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// injiPair returns the Inji pair of a role.
func injiPair(role commonv1.Role) Pair { return Pair{Role: role, Dpg: configv1.Dpg_DPG_INJI} }

// planEnv runs a setup plan and returns the values of its .env file.
func planEnv(t *testing.T, req SetupRequest) map[string]string {
	t.Helper()
	if req.Flags == nil {
		req.Flags = baseFlags()
	}
	req.Random = rand.Reader
	plan, err := BuildPlan(req)
	if err != nil {
		t.Fatalf("%s: BuildPlan: %v", req.Pair.Name(), err)
	}
	values, err := ParseDotenv(strings.NewReader(string(plan.Files[0].Data)))
	if err != nil {
		t.Fatal(err)
	}
	return values
}

// TestInjiEsignetAddressFollowsTheDeployment is P6-I7f. The browser
// opens the eSignet login page at the address its tokens carry. A local
// deployment reaches the page on its host port. A base domain puts it on
// the host of the Inji issuer pair, which publishes it, and every Inji
// pair that runs eSignet names that one address, so each deploy starts
// eSignet the same way. The issuer pair names it as the authorization
// server of an authorization code offer.
func TestInjiEsignetAddressFollowsTheDeployment(t *testing.T) {
	issuer, holder := injiPair(commonv1.Role_ROLE_ISSUER), injiPair(commonv1.Role_ROLE_HOLDER)
	for _, tc := range []struct {
		name   string
		req    SetupRequest
		want   string
		server bool
	}{
		{name: "local issuer", req: SetupRequest{Pair: issuer}, want: "http://localhost:17089", server: true},
		{name: "local holder", req: SetupRequest{Pair: holder}, want: "http://localhost:17089"},
		{name: "domain issuer", req: SetupRequest{Pair: issuer, Domain: "labs.example"}, want: "https://issuer-inji.labs.example", server: true},
		{name: "domain holder", req: SetupRequest{Pair: holder, Domain: "labs.example"}, want: "https://issuer-inji.labs.example"},
		{name: "holder beside an issuer of its own name", req: SetupRequest{Pair: holder, Domain: "labs.example",
			Peers: PeerOverrides{issuer.Name(): {"VCA_PUBLIC_URL": "https://issue.gov.example"}}}, want: "https://issue.gov.example"},
		{name: "issuer on a host of its own", req: SetupRequest{Pair: issuer,
			Flags: withFlag(baseFlags(), "VCA_PUBLIC_URL", "https://issue.gov.example")}, want: "https://issue.gov.example", server: true},
		// A holder alone has no issuer host to lean on, so the browser
		// opens the host port of the page.
		{name: "holder alone on a public host", req: SetupRequest{Pair: holder,
			Flags: withFlag(baseFlags(), "VCA_PUBLIC_URL", "https://wallet.gov.example")}, want: "http://wallet.gov.example:17089"},
	} {
		env := planEnv(t, tc.req)
		if env["INJI_ESIGNET_PUBLIC_URL"] != tc.want {
			t.Errorf("%s: INJI_ESIGNET_PUBLIC_URL = %q, want %q", tc.name, env["INJI_ESIGNET_PUBLIC_URL"], tc.want)
		}
		server, ok := env["VCA_INJI_AUTHORIZATION_SERVER"]
		if tc.server && server != tc.want {
			t.Errorf("%s: VCA_INJI_AUTHORIZATION_SERVER = %q, want %q", tc.name, server, tc.want)
		}
		if !tc.server && ok {
			t.Errorf("%s: the pair names an authorization server", tc.name)
		}
	}
	// An operator value wins.
	flags := withFlag(baseFlags(), "VCA_INJI_AUTHORIZATION_SERVER", "https://idp.gov.example")
	if env := planEnv(t, SetupRequest{Pair: issuer, Flags: flags}); env["VCA_INJI_AUTHORIZATION_SERVER"] != "https://idp.gov.example" {
		t.Errorf("the operator value was lost: %q", env["VCA_INJI_AUTHORIZATION_SERVER"])
	}
	for _, p := range AllPairs() {
		if p == issuer || p == holder {
			continue
		}
		if _, ok := planEnv(t, SetupRequest{Pair: p})["INJI_ESIGNET_PUBLIC_URL"]; ok {
			t.Errorf("%s runs no eSignet but names its address", p.Name())
		}
	}
}

// withFlag returns the flags with one more value.
func withFlag(flags map[string]string, key, value string) map[string]string {
	flags[key] = value
	return flags
}
