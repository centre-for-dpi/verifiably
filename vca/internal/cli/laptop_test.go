// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// laptopReads are the settings that let the pairs of one laptop read
// each other over plain http on the loopback address.
var laptopReads = map[string]commonv1.Role{
	"VCA_WALLET_PORTAL_REQUEST_HOSTS":     commonv1.Role_ROLE_HOLDER,
	"VCA_DISCOVERY_ALLOW_PLAIN_HTTP":      commonv1.Role_ROLE_VERIFIER,
	"VCA_DISCOVERY_ALLOW_PRIVATE_NETWORK": commonv1.Role_ROLE_VERIFIER,
}

// TestLaptopSetupOpensTheLocalReads: a deployment on localhost runs
// every pair on one machine. Setup lets the wallet read the requests
// of a local verifier, and the discovery service read the local issuer
// pairs over plain http. A public host keeps both guards strict.
func TestLaptopSetupOpensTheLocalReads(t *testing.T) {
	want := map[string]string{
		"VCA_WALLET_PORTAL_REQUEST_HOSTS":     "localhost,127.0.0.1",
		"VCA_DISCOVERY_ALLOW_PLAIN_HTTP":      "true",
		"VCA_DISCOVERY_ALLOW_PRIVATE_NETWORK": "true",
	}
	for name, role := range laptopReads {
		pair := Pair{Role: role, Dpg: configv1.Dpg_DPG_WALTID}
		local := planEnv(t, SetupRequest{Pair: pair})
		if got := local[name]; got != want[name] {
			t.Errorf("%s on localhost: %s = %q, want %q", pair.Name(), name, got, want[name])
		}
		flags := baseFlags()
		flags["VCA_PUBLIC_URL"] = "https://" + pair.Name() + ".labs.example"
		public := planEnv(t, SetupRequest{Pair: pair, Flags: flags})
		if got, ok := public[name]; ok {
			t.Errorf("%s on a public host: %s = %q, want no line", pair.Name(), name, got)
		}
	}
	issuer := planEnv(t, SetupRequest{Pair: Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_WALTID}})
	for name := range laptopReads {
		if _, ok := issuer[name]; ok {
			t.Errorf("the issuer pair got %s, which none of its services reads", name)
		}
	}
}

// TestSetupNamesTheIssuingAdapter: the issued record names the adapter
// that issued each credential, not the fallback "dpg".
func TestSetupNamesTheIssuingAdapter(t *testing.T) {
	for _, dpg := range Dpgs() {
		pair := Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: dpg}
		env := planEnv(t, SetupRequest{Pair: pair})
		if got, want := env["VCA_ISSUANCE_ADAPTER_NAME"], "dpg-adapter-"+ShortName(dpg.String()); got != want {
			t.Errorf("%s: VCA_ISSUANCE_ADAPTER_NAME = %q, want %q", pair.Name(), got, want)
		}
	}
}
