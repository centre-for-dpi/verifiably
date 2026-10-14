// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// TestKeycloakEnvPinsTheBrowserFacingHostname: the services fetch the
// discovery document on the compose network, and a Keycloak with no
// fixed hostname names its container in the issuer and the
// authorization endpoint, which no browser reaches. The .env of the
// Keycloak pins VCA_OIDC_PUBLIC_URL as the hostname and keeps the
// backchannel dynamic. The stack files require nothing for it.
func TestKeycloakEnvPinsTheBrowserFacingHostname(t *testing.T) {
	t.Parallel()
	env, err := KeycloakEnv(configv1.Dpg_DPG_WALTID, "https://waltid-keycloak.example.org/", nil, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"KC_HOSTNAME=https://waltid-keycloak.example.org\n", "KC_HOSTNAME_BACKCHANNEL_DYNAMIC=true\n"} {
		if !strings.Contains(env, want) {
			t.Errorf("the Keycloak .env lacks %q:\n%s", want, env)
		}
	}
	none, err := KeycloakEnv(configv1.Dpg_DPG_WALTID, "", nil, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(none, "KC_HOSTNAME") {
		t.Errorf("no address pinned a hostname:\n%s", none)
	}
	files, err := KeycloakFiles(Pair{Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_INJI}, map[string]string{"VCA_PUBLIC_URL": "http://localhost:18100", EnvOidcPublicURL: "http://localhost:17080"}, nil, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range files {
		if f.Name == KeycloakEnvFile(configv1.Dpg_DPG_INJI) {
			found = strings.Contains(string(f.Data), "KC_HOSTNAME=http://localhost:17080\n")
		}
	}
	if !found {
		t.Error("the Keycloak files of a pair do not pin VCA_OIDC_PUBLIC_URL")
	}
	for _, d := range StackDpgs() {
		name := ShortName(d.String()) + ".yaml"
		text, err := os.ReadFile(filepath.Join(repoRoot(), "deploy", "vca", "dpg", name)) // #nosec G304 -- a fixed test path
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(text), "KC_HOSTNAME:") {
			t.Errorf("%s sets the hostname itself; the .env of the Keycloak does", name)
		}
	}
}
