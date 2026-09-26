// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// Plan section 3.8 and ADR-055 decision 4: the CREDEBL platform admin
// comes from a setting with no default, and setup generates the secrets
// of the CREDEBL seed.

func credeblPair(role commonv1.Role) Pair { return Pair{Role: role, Dpg: configv1.Dpg_DPG_CREDEBL} }

// credeblFlags are the base flags with the platform admin of setup.
func credeblFlags() map[string]string {
	flags := baseFlags()
	flags[PlatformAdminEmailSetting] = credeblAdmin
	return flags
}

func TestSetupWritesTheCredeblEnv(t *testing.T) {
	plan, err := BuildPlan(SetupRequest{Pair: credeblPair(commonv1.Role_ROLE_ISSUER), Flags: credeblFlags(), Random: rand.Reader})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	f := sharedFile(t, plan, StackEnvFile(configv1.Dpg_DPG_CREDEBL))
	if f.Mode != 0o600 {
		t.Errorf("the CREDEBL .env has mode %04o", f.Mode)
	}
	root := t.TempDir()
	if _, werr := WritePlan(root, plan); werr != nil {
		t.Fatal(werr)
	}
	values, err := ReadStackEnv(root, configv1.Dpg_DPG_CREDEBL)
	if err != nil {
		t.Fatal(err)
	}
	if values[PlatformAdminEmailEnv] != credeblAdmin {
		t.Errorf("%s = %q", PlatformAdminEmailEnv, values[PlatformAdminEmailEnv])
	}
	for _, name := range []string{"CRYPTO_PRIVATE_KEY", "PLATFORM_WALLET_PASSWORD", "PLATFORM_SEED"} {
		if v := values[name]; len(v) != stackSecretLength {
			t.Errorf("%s = %q, want %d generated characters", name, v, stackSecretLength)
		}
	}
	for _, tok := range mockTokens {
		if strings.Contains(string(f.Data), tok) {
			t.Errorf("the CREDEBL .env names %q", tok)
		}
	}
	// A run of another stack keeps the platform admin and the secrets.
	stacks, err := ReadStackEnvs(root)
	if err != nil {
		t.Fatal(err)
	}
	later, err := BuildPlan(SetupRequest{Pair: waltidPair(commonv1.Role_ROLE_ISSUER), Flags: baseFlags(), Random: rand.Reader, Stacks: stacks})
	if err != nil {
		t.Fatal(err)
	}
	// The walt.id pair gets the declared setting of CREDEBL from the
	// shared flags, and its .env leaves it out.
	if env := planFile(t, later, EnvFileName); strings.Contains(env, PlatformAdminEmailSetting) {
		t.Errorf("the walt.id .env carries %s:\n%s", PlatformAdminEmailSetting, env)
	}
	if got := sharedFile(t, later, StackEnvFile(configv1.Dpg_DPG_CREDEBL)); string(got.Data) != string(f.Data) {
		t.Errorf("a walt.id run changed the CREDEBL .env:\n%s\nwant\n%s", got.Data, f.Data)
	}
	// A CREDEBL pair without the platform admin stops with the name of
	// the setting. No placeholder fills it.
	without := baseFlags()
	delete(without, PlatformAdminEmailSetting)
	for _, role := range []commonv1.Role{commonv1.Role_ROLE_ISSUER, commonv1.Role_ROLE_HOLDER, commonv1.Role_ROLE_VERIFIER} {
		_, err := BuildPlan(SetupRequest{Pair: credeblPair(role), Flags: without, Random: rand.Reader})
		var missing *MissingValuesError
		if !errors.As(err, &missing) || !strings.Contains(err.Error(), PlatformAdminEmailSetting) {
			t.Errorf("%s: err = %v, want the missing platform admin", role, err)
		}
	}
	bad := credeblFlags()
	bad[PlatformAdminEmailSetting] = "not an address"
	if _, err := BuildPlan(SetupRequest{Pair: credeblPair(commonv1.Role_ROLE_ISSUER), Flags: bad, Random: rand.Reader}); err == nil {
		t.Error("a value that is no email address passed")
	}
}

func TestCredeblStackReadsTheStackEnv(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(), "deploy", "vca", "dpg", "credebl.yaml")) // #nosec G304 -- a fixed test path
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services map[string]struct {
			EnvFile []struct {
				Path     string `yaml:"path"`
				Required bool   `yaml:"required"`
			} `yaml:"env_file"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"credebl-api-gateway", "credebl-agent-provisioning"} {
		files := doc.Services[name].EnvFile
		if len(files) != 1 || files[0].Path != "../"+StackEnvFile(configv1.Dpg_DPG_CREDEBL) || !files[0].Required {
			t.Errorf("%s reads %v, want the CREDEBL stack .env", name, files)
		}
	}
}
