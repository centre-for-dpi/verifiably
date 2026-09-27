// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"strings"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// TestIssuerLinksBothStatusServices: an SD-JWT VC carries a Token
// Status List entry, which status-token keeps, and every other
// credential a Bitstring entry, which status-bitstring keeps. The
// bitstring service refuses a token list, so the issuance and the
// issued credentials services of every issuer pair reach both.
func TestIssuerLinksBothStatusServices(t *testing.T) {
	for _, d := range Dpgs() {
		p := Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: d}
		flags := baseFlags()
		if d == configv1.Dpg_DPG_CREDEBL {
			flags = credeblFlags()
		}
		plan, err := BuildPlan(SetupRequest{Pair: p, Flags: flags, Random: rand.Reader})
		if err != nil {
			t.Fatal(err)
		}
		env, err := ParseDotenv(strings.NewReader(planFile(t, plan, EnvFileName)))
		if err != nil {
			t.Fatal(err)
		}
		for key, service := range map[string]string{
			"VCA_ISSUANCE_STATUS_URL": "status-bitstring", "VCA_ISSUANCE_STATUS_TOKEN_URL": "status-token",
			"VCA_ISSUED_STATUS_URL": "status-bitstring", "VCA_ISSUED_STATUS_TOKEN_URL": "status-token",
		} {
			if want := "http://" + p.Name() + "-" + service + ":"; !strings.HasPrefix(env[key], want) {
				t.Errorf("%s: %s = %q, want %s...", p.Name(), key, env[key], want)
			}
		}
	}
}
