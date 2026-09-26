// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
)

// esignetFiles writes a properties file and a plugin jar of an operator
// into a temporary folder and returns their paths.
func esignetFiles(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	props := filepath.Join(dir, "authenticator.properties")
	if err := os.WriteFile(props, []byte("mosip.esignet.integration.authenticator=IdaAuthenticatorImpl\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	jar := filepath.Join(dir, "registry-authenticator.jar")
	if err := os.WriteFile(jar, []byte("PK\x03\x04 jar"), 0o600); err != nil {
		t.Fatal(err)
	}
	return props, jar
}

// sharedFile returns one shared file of a plan by name.
func sharedPlanFile(plan Plan, name string) (File, bool) {
	for _, f := range plan.Shared {
		if f.Name == name {
			return f, true
		}
	}
	return File{}, false
}

// TestSetupAsksTheAuthenticatorAndMountsTheFile is ADR-053 decisions 1
// and 3 at setup time. The default runs no eSignet. A real
// authenticator names the plugin jar of the image, copies the
// properties of the operator with mode 0600, and tells the adapter
// where eSignet runs. A custom authenticator copies its jar too. A
// missing file stops the run with its path.
func TestSetupAsksTheAuthenticatorAndMountsTheFile(t *testing.T) {
	issuer, holder := injiPair(commonv1.Role_ROLE_ISSUER), injiPair(commonv1.Role_ROLE_HOLDER)
	props, jar := esignetFiles(t)
	propsName := filepath.Join(EsignetDir, EsignetPropertiesFile)

	env := planEnv(t, SetupRequest{Pair: issuer})
	if env[EsignetAuthenticatorEnv] != EsignetNone || env[EsignetPluginEnv] != "" {
		t.Fatalf("the default = %q plugin %q, want none and an empty plugin", env[EsignetAuthenticatorEnv], env[EsignetPluginEnv])
	}
	if _, ok := env[EsignetPluginEnv]; !ok {
		t.Error("the default leaves the plugin variable unset; compose reads it for every Inji pair")
	}
	for _, name := range []string{EsignetURLEnv, EsignetPublicURLEnv} {
		if _, ok := env[name]; ok {
			t.Errorf("a pair without eSignet names %s", name)
		}
	}
	if plan := planOf(t, SetupRequest{Pair: issuer}); len(plan.Shared) > 0 {
		if _, ok := sharedPlanFile(plan, propsName); ok {
			t.Error("a pair without eSignet writes the plugin properties")
		}
	}

	for authenticator, plugin := range map[string]string{"mosip-ida": "mosip-identity-plugin.jar", "sunbird-rc": "sunbird-rc-plugin.jar"} {
		flags := withFlag(withFlag(baseFlags(), EsignetAuthenticatorEnv, authenticator), EsignetPropertiesEnv, props)
		for _, p := range []Pair{issuer, holder} {
			req := SetupRequest{Pair: p, Flags: flags}
			got := planEnv(t, req)
			if got[EsignetPluginEnv] != plugin || got[EsignetURLEnv] != EsignetInternalURL || got[EsignetPublicURLEnv] == "" {
				t.Errorf("%s %s: plugin %q, url %q, public %q", p.Name(), authenticator, got[EsignetPluginEnv], got[EsignetURLEnv], got[EsignetPublicURLEnv])
			}
			f, ok := sharedPlanFile(planOf(t, SetupRequest{Pair: p, Flags: flags}), propsName)
			if !ok || f.Mode != 0o600 || !bytes.Contains(f.Data, []byte("IdaAuthenticatorImpl")) {
				t.Errorf("%s %s: the properties file = %v %v", p.Name(), authenticator, ok, f.Mode)
			}
		}
	}

	custom := withFlag(withFlag(withFlag(baseFlags(), EsignetAuthenticatorEnv, "custom"), EsignetPropertiesEnv, props), EsignetPluginFileEnv, jar)
	plan := planOf(t, SetupRequest{Pair: issuer, Flags: custom})
	env = planEnv(t, SetupRequest{Pair: issuer, Flags: custom})
	if env[EsignetPluginEnv] != EsignetCustomPluginDir+"/registry-authenticator.jar" {
		t.Errorf("the custom plugin = %q", env[EsignetPluginEnv])
	}
	if f, ok := sharedPlanFile(plan, filepath.Join(EsignetDir, EsignetCustomPluginDir, "registry-authenticator.jar")); !ok || f.Mode != 0o600 {
		t.Errorf("the custom jar was not copied: %v", ok)
	}

	missing := filepath.Join(t.TempDir(), "absent.properties")
	for name, flags := range map[string]map[string]string{
		"a missing properties file": withFlag(withFlag(baseFlags(), EsignetAuthenticatorEnv, "mosip-ida"), EsignetPropertiesEnv, missing),
		"no properties file":        withFlag(baseFlags(), EsignetAuthenticatorEnv, "sunbird-rc"),
		"no custom plugin":          withFlag(withFlag(baseFlags(), EsignetAuthenticatorEnv, "custom"), EsignetPropertiesEnv, props),
		"a custom plugin not a jar": withFlag(withFlag(withFlag(baseFlags(), EsignetAuthenticatorEnv, "custom"), EsignetPropertiesEnv, props), EsignetPluginFileEnv, props),
	} {
		_, err := BuildPlan(SetupRequest{Pair: issuer, Flags: flags, Random: rand.Reader})
		if err == nil {
			t.Errorf("%s: the plan passed", name)
			continue
		}
		if name == "a missing properties file" && !strings.Contains(err.Error(), missing) {
			t.Errorf("%s: the error %q does not name the path", name, err)
		}
	}
	_, err := BuildPlan(SetupRequest{Pair: issuer, Flags: withFlag(baseFlags(), EsignetAuthenticatorEnv, "mock"), Random: rand.Reader})
	var invalid *InvalidValuesError
	if !errors.As(err, &invalid) {
		t.Errorf("the mock authenticator: %v, want a bad value", err)
	}

	// Every Inji pair sets the plugin variable, so compose reads the
	// stack file for any of them. The verifier never names eSignet.
	verifier := planEnv(t, SetupRequest{Pair: injiPair(commonv1.Role_ROLE_VERIFIER)})
	if v, ok := verifier[EsignetPluginEnv]; !ok || v != "" {
		t.Errorf("the verifier plugin = %q %v, want set and empty", v, ok)
	}
}

// TestDeployAddsTheEsignetProfile is ADR-053 decision 1 at deploy time:
// the compose run of a pair adds the profile esignet-inji only when the
// .env of the pair names a real authenticator.
func TestDeployAddsTheEsignetProfile(t *testing.T) {
	root := t.TempDir()
	issuer := injiPair(commonv1.Role_ROLE_ISSUER)
	write := func(authenticator string) {
		t.Helper()
		path := EnvPath(root, issuer)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(EsignetAuthenticatorEnv+"="+authenticator+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	profiles := func() []string {
		var out []string
		args := ComposeArgs(root, issuer, []string{"up", "-d"})
		for i, a := range args {
			if a == "--profile" {
				out = append(out, args[i+1])
			}
		}
		return out
	}
	if got := profiles(); !slices.Equal(got, []string{"issuer-inji"}) {
		t.Fatalf("without a .env: %v", got)
	}
	write("mosip-ida")
	if got := profiles(); !slices.Equal(got, []string{"issuer-inji", EsignetProfile}) {
		t.Fatalf("with mosip-ida: %v", got)
	}
	write("none")
	if got := profiles(); !slices.Equal(got, []string{"issuer-inji"}) {
		t.Fatalf("with none: %v", got)
	}
	write("custom")
	if got := ComposeArgs(root, injiPair(commonv1.Role_ROLE_VERIFIER), []string{"up"}); slices.Contains(got, EsignetProfile) {
		t.Fatalf("a verifier pair added the profile: %v", got)
	}
}

// TestBootstrapInjiSkipsEsignetWithoutAnAuthenticator is ADR-053
// decision 4: with none, bootstrap asks no eSignet. The holder still
// writes the Mimoto key store, because Inji Web signs its token
// requests at the holder authorization server with that key.
func TestBootstrapInjiSkipsEsignetWithoutAnAuthenticator(t *testing.T) {
	kc := &keycloakState{}
	keycloak := fakeKeycloak(t, kc)
	defer keycloak.Close()
	for _, role := range []commonv1.Role{commonv1.Role_ROLE_ISSUER, commonv1.Role_ROLE_HOLDER} {
		es := &esignetFake{}
		esignet := fakeEsignet(t, es)
		var out bytes.Buffer
		opts := injiRoleOptions(t, role, keycloak.URL, &out)
		opts.Values[EnvBootstrapEsignetURL] = esignet.URL
		opts.Values[EsignetAuthenticatorEnv] = EsignetNone
		opts.Values["VCA_INJI_WEB_URL"] = "https://wallet.example"
		got, err := Bootstrap(context.Background(), opts)
		if err != nil {
			t.Fatalf("%v: Bootstrap: %v", role, err)
		}
		if len(es.creates)+len(es.updates) != 0 {
			t.Errorf("%v: the run called eSignet %d times", role, len(es.creates)+len(es.updates))
		}
		if strings.Contains(strings.Join(got.Steps, "\n"), "eSignet client") {
			t.Errorf("%v: a step names the eSignet client:\n%s", role, strings.Join(got.Steps, "\n"))
		}
		store := filepath.Join(filepath.Dir(opts.Dir), MimotoDir, MimotoKeystoreFile)
		if _, err := os.Stat(store); (err == nil) != (role == commonv1.Role_ROLE_HOLDER) {
			t.Errorf("%v: the Mimoto key store exists = %v", role, err == nil)
		}
	}
}
