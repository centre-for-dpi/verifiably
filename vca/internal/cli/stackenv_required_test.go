// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// TestStackEnvNamesEveryRequiredVariableOfItsStackFile pins the contract
// between a stack file and its .env: the main compose file includes
// every stack file with that .env, and docker compose config interpolates
// every included file whatever profile runs. So every ${NAME?...} and
// ${NAME:?...} of a stack file must be a key of the .env that setup
// writes for the stack, else the deploy of any pair fails on it.
func TestStackEnvNamesEveryRequiredVariableOfItsStackFile(t *testing.T) {
	t.Parallel()
	required := regexp.MustCompile(`\$\{([A-Z0-9_]+):?\?`)
	for _, d := range StackDpgs() {
		file := filepath.Join("..", "..", "..", "deploy", "vca", "dpg", ShortName(d.String())+".yaml")
		text, err := os.ReadFile(file) // #nosec G304 -- the test reads the stack files of its own checkout
		if err != nil {
			t.Fatal(err)
		}
		env, err := StackEnv(d, nil, rand.Reader, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		keys := map[string]bool{}
		for _, line := range strings.Split(env, "\n") {
			if name, _, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(line, "#") {
				keys[name] = true
			}
		}
		for _, m := range required.FindAllStringSubmatch(string(text), -1) {
			if !keys[m[1]] {
				t.Errorf("%s requires %s, which the .env of the %s stack does not name", file, m[1], ShortName(d.String()))
			}
		}
	}
}

// TestInjiStackEnvCarriesThePluginOfTheIssuerPair pins how the eSignet
// plugin reaches the stack .env (ADR-053): an Inji issuer pair with
// eSignet names its plugin, a pair that runs eSignet without one clears
// it, and a verifier pair keeps whatever the others wrote.
func TestInjiStackEnvCarriesThePluginOfTheIssuerPair(t *testing.T) {
	t.Parallel()
	issuer := Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_INJI}
	verifier := Pair{Role: commonv1.Role_ROLE_VERIFIER, Dpg: configv1.Dpg_DPG_INJI}
	if got := StackSettings(issuer, nil, "mock-free-plugin.jar"); got[configv1.Dpg_DPG_INJI][EsignetPluginEnv] != "mock-free-plugin.jar" {
		t.Errorf("issuer with eSignet: %v", got)
	}
	if got := StackSettings(issuer, nil, ""); got[configv1.Dpg_DPG_INJI] == nil || got[configv1.Dpg_DPG_INJI][EsignetPluginEnv] != "" {
		t.Errorf("issuer without eSignet must clear the plugin: %v", got)
	}
	if _, ok := StackSettings(issuer, nil, "")[configv1.Dpg_DPG_INJI][EsignetPluginEnv]; !ok {
		t.Error("issuer without eSignet must still name the key")
	}
	if got := StackSettings(verifier, nil, ""); got != nil {
		t.Errorf("a verifier pair must not touch the plugin: %v", got)
	}
	env, err := StackEnv(configv1.Dpg_DPG_INJI, map[string]string{EsignetPluginEnv: "kept.jar"}, rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(env, EsignetPluginEnv+"=kept.jar\n") {
		t.Errorf("a later run drops the plugin:\n%s", env)
	}
}
