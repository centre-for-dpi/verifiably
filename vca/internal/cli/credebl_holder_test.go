// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"strings"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// TestCredeblHolderPairReachesTheAgent is ADR-062 decision 7: setup
// gives the adapter of a CREDEBL holder pair the admin address and the
// generated API key of the shared agent, which turn the holder wallet
// on. A pair of another role gets neither.
func TestCredeblHolderPairReachesTheAgent(t *testing.T) {
	for role, want := range map[commonv1.Role]bool{commonv1.Role_ROLE_HOLDER: true, commonv1.Role_ROLE_ISSUER: false, commonv1.Role_ROLE_VERIFIER: false} {
		plan, err := BuildPlan(SetupRequest{Pair: credeblPair(role), Flags: credeblFlags(), Random: rand.Reader})
		if err != nil {
			t.Fatal(err)
		}
		stack, err := ParseDotenv(strings.NewReader(string(sharedFile(t, plan, StackEnvFile(configv1.Dpg_DPG_CREDEBL)).Data)))
		if err != nil {
			t.Fatal(err)
		}
		env, err := ParseDotenv(strings.NewReader(planFile(t, plan, EnvFileName)))
		if err != nil {
			t.Fatal(err)
		}
		key, address := env[CredeblAdapterAgentKeyEnv], env[CredeblAdapterAgentURLEnv]
		if want && (key != stack[SharedAgentAPIKeyEnv] || key == "" || address != "http://"+SharedAgentHost+":8001") {
			t.Errorf("%v: key %q, address %q", role, key, address)
		}
		if !want && (key != "" || address != "") {
			t.Errorf("%v: the pair holds the agent: %q %q", role, key, address)
		}
	}
}

// TestCredeblAdapterKeepsItsState: the adapter keeps the tenant of each
// holder, and the verifier id, in a file on its data volume, so a
// restart opens the same wallets.
func TestCredeblAdapterKeepsItsState(t *testing.T) {
	for _, s := range Catalog() {
		if s.Name != "dpg-adapter-credebl" {
			continue
		}
		found := false
		for _, f := range s.Fixed {
			found = found || (f.Env == "VCA_CREDEBL_STORE_FILE" && strings.HasPrefix(f.Value, "/data/"))
		}
		if !s.Stateful || !found {
			t.Errorf("the adapter keeps no state: %+v", s)
		}
		return
	}
	t.Fatal("the catalogue has no CREDEBL adapter")
}
