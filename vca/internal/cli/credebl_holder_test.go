// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"strings"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// TestCredeblHolderPairReachesTheAgent is ADR-062 decision 7 as the
// amendment of 2026-10-04 changes it: setup gives the adapter of every
// CREDEBL pair the admin address and the generated API key of the
// shared agent. The agent of an issuer and a verifier pair resolves
// ledger DIDs only, so only the holder pair serves a wallet.
func TestCredeblHolderPairReachesTheAgent(t *testing.T) {
	for _, role := range []commonv1.Role{commonv1.Role_ROLE_HOLDER, commonv1.Role_ROLE_ISSUER, commonv1.Role_ROLE_VERIFIER} {
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
		if key != stack[SharedAgentAPIKeyEnv] || key == "" || address != "http://"+SharedAgentHost+":8001" {
			t.Errorf("%v: key %q, address %q", role, key, address)
		}
		resolverOnly := env[CredeblAdapterAgentResolverOnlyEnv] == "true"
		if resolverOnly == (role == commonv1.Role_ROLE_HOLDER) {
			t.Errorf("%v: resolver only = %v", role, resolverOnly)
		}
	}
	// A pair of another DPG gets nothing.
	if got := CredeblAdapterValues(Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_WALTID}, map[string]string{SharedAgentAPIKeyEnv: "k"}); got != nil {
		t.Errorf("a pair of another DPG got %v", got)
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
