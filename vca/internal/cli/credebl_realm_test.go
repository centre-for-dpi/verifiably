// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// P6-C0b: the CREDEBL platform signs its users in at a realm of the
// Keycloak of the stack, with a management client and an admin client.
// Setup writes that realm with generated secrets, and the realms of the
// VCA roles stay as they are.

// platformRealmDoc is the part of the platform realm the tests read.
type platformRealmDoc struct {
	Realm               string `json:"realm"`
	Enabled             bool   `json:"enabled"`
	RegistrationAllowed bool   `json:"registrationAllowed"`
	Roles               struct {
		Realm []struct {
			Name string `json:"name"`
		} `json:"realm"`
	} `json:"roles"`
	Clients []struct {
		ClientID                  string `json:"clientId"`
		Secret                    string `json:"secret"`
		PublicClient              bool   `json:"publicClient"`
		StandardFlowEnabled       bool   `json:"standardFlowEnabled"`
		DirectAccessGrantsEnabled bool   `json:"directAccessGrantsEnabled"`
		ServiceAccountsEnabled    bool   `json:"serviceAccountsEnabled"`
	} `json:"clients"`
	Users []struct {
		Username               string              `json:"username"`
		ServiceAccountClientID string              `json:"serviceAccountClientId"`
		ClientRoles            map[string][]string `json:"clientRoles"`
	} `json:"users"`
}

func TestSetupWritesTheCredeblPlatformRealm(t *testing.T) {
	plan, err := BuildPlan(SetupRequest{Pair: credeblPair(commonv1.Role_ROLE_ISSUER), Flags: credeblFlags(), Random: rand.Reader})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	f := sharedFile(t, plan, CredeblPlatformRealmFile)
	if f.Mode != 0o644 {
		t.Errorf("the platform realm has mode %04o", f.Mode)
	}
	var doc platformRealmDoc
	if jerr := json.Unmarshal(f.Data, &doc); jerr != nil {
		t.Fatalf("the platform realm is no JSON: %v", jerr)
	}
	if doc.Realm != CredeblPlatformRealm || !doc.Enabled || doc.RegistrationAllowed {
		t.Errorf("realm = %s, enabled %v, registration %v", doc.Realm, doc.Enabled, doc.RegistrationAllowed)
	}
	var roles []string
	for _, r := range doc.Roles.Realm {
		roles = append(roles, r.Name)
	}
	if !slices.Contains(roles, "mb-user") {
		t.Errorf("realm roles = %v, want mb-user, which the platform gives each user", roles)
	}
	// The file holds a placeholder of each secret. Keycloak reads the
	// value from its environment at the import, so the file has mode 0644
	// and no secret.
	want := map[string]string{
		CredeblAdminClientID:      "${" + CredeblAdminClientSecretEnv + "}",
		CredeblManagementClientID: "${" + CredeblManagementClientSecretEnv + "}",
	}
	if len(doc.Clients) != len(want) {
		t.Fatalf("clients = %+v", doc.Clients)
	}
	for _, c := range doc.Clients {
		if want[c.ClientID] == "" || c.Secret != want[c.ClientID] {
			t.Errorf("client %s has the secret %q", c.ClientID, c.Secret)
		}
		if c.PublicClient || c.StandardFlowEnabled || !c.DirectAccessGrantsEnabled || !c.ServiceAccountsEnabled {
			t.Errorf("client %s: %+v", c.ClientID, c)
		}
	}
	for _, u := range doc.Users {
		roles := u.ClientRoles["realm-management"]
		for _, need := range []string{"manage-users", "view-users", "query-users", "manage-clients", "view-clients"} {
			if !slices.Contains(roles, need) {
				t.Errorf("the service account of %s lacks %s: %v", u.ServiceAccountClientID, need, roles)
			}
		}
		delete(want, u.ServiceAccountClientID)
	}
	if len(want) != 0 {
		t.Errorf("no service account for %v", want)
	}
	stack, err := ParseDotenv(bytes.NewReader(sharedFile(t, plan, StackEnvFile(configv1.Dpg_DPG_CREDEBL)).Data))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{CredeblAdminClientSecretEnv, CredeblManagementClientSecretEnv} {
		value := stack[name]
		if len(value) != stackSecretLength {
			t.Errorf("%s = %q, want %d generated characters", name, value, stackSecretLength)
		}
		if strings.Contains(string(f.Data), value) {
			t.Errorf("the realm file holds the value of %s", name)
		}
	}
	// The realm of the VCA role stays as the provider agnostic realm
	// of ADR-035 makes it.
	own, err := KeycloakRealm(credeblPair(commonv1.Role_ROLE_ISSUER), Values(plan.Resolutions))
	if err != nil {
		t.Fatal(err)
	}
	if got := sharedFile(t, plan, RealmFileOf(credeblPair(commonv1.Role_ROLE_ISSUER))); !bytes.Equal(got.Data, append(own, '\n')) {
		t.Errorf("the realm of the issuer role changed:\n%s", got.Data)
	}
	// A pair of another stack gets no platform realm.
	waltid, err := BuildPlan(SetupRequest{Pair: waltidPair(commonv1.Role_ROLE_ISSUER), Flags: baseFlags(), Random: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range waltid.Shared {
		if strings.Contains(s.Name, "credebl-platform") {
			t.Errorf("a walt.id run writes %s", s.Name)
		}
	}
}

// TestCredeblStackNamesThePlatformRealm is P6-C0b: every platform
// service reads the realm and the two clients, with the secrets of the
// stack .env, and the Keycloak of the stack gets the secrets for the
// placeholders of the realm file.
func TestCredeblStackNamesThePlatformRealm(t *testing.T) {
	doc, _ := readCredeblStack(t)
	want := map[string]string{
		"KEYCLOAK_REALM":                    CredeblPlatformRealm,
		"KEYCLOAK_MANAGEMENT_CLIENT_ID":     CredeblManagementClientID,
		"KEYCLOAK_MANAGEMENT_CLIENT_SECRET": "${" + CredeblManagementClientSecretEnv + ":?set by vca setup}",
		"ADMIN_KEYCLOAK_ID":                 CredeblAdminClientID,
		"ADMIN_KEYCLOAK_SECRET":             "${" + CredeblAdminClientSecretEnv + ":?set by vca setup}",
	}
	for name, svc := range doc.Services {
		if !strings.HasPrefix(svc.Image, "ghcr.io/credebl/") || name == "credebl-agent" || name == "credebl-schema-file-server" {
			continue
		}
		for key, value := range want {
			if svc.Environment[key] != value {
				t.Errorf("%s %s = %q, want %q", name, key, svc.Environment[key], value)
			}
		}
	}
	keycloak := doc.Services["credebl-keycloak"]
	for _, name := range []string{CredeblAdminClientSecretEnv, CredeblManagementClientSecretEnv} {
		if keycloak.Environment[name] != "${"+name+":?set by vca setup}" {
			t.Errorf("credebl-keycloak %s = %q", name, keycloak.Environment[name])
		}
	}
}

// TestBootstrapCredeblCreatesThePlatformRealm is P6-C0b: on a Keycloak
// that started before the realm file existed, the bootstrap run creates
// the platform realm with the secrets of the stack .env before the
// initialisation, which makes the Keycloak user of the platform admin.
// A second run finds it and sets the client secrets again. The realms of
// the VCA roles stay untouched.
func TestBootstrapCredeblCreatesThePlatformRealm(t *testing.T) {
	state := &credeblState{}
	server := fakeCredebl(t, state)
	defer server.Close()
	var out bytes.Buffer
	opts := credeblOptions(t, server.URL, &out)
	var order []string
	opts.Run = func(context.Context, string, []string) error {
		order = append(order, "initialisation")
		return nil
	}
	state.onRealm = func() { order = append(order, "realm") }
	stack, err := ReadStackEnv(filepath.Dir(opts.Dir), configv1.Dpg_DPG_CREDEBL)
	if err != nil {
		t.Fatal(err)
	}
	if _, berr := BootstrapCredebl(context.Background(), opts); berr != nil {
		t.Fatalf("BootstrapCredebl: %v", berr)
	}
	if len(order) != 2 || order[0] != "realm" || order[1] != "initialisation" {
		t.Errorf("order = %v, want the realm before the initialisation", order)
	}
	if state.adminToken != credeblKeycloakAdminPassword {
		t.Errorf("the run signed in to Keycloak with %q", state.adminToken)
	}
	var doc platformRealmDoc
	if jerr := json.Unmarshal(state.realm, &doc); jerr != nil {
		t.Fatalf("the created realm: %v", jerr)
	}
	secrets := map[string]string{
		CredeblAdminClientID:      stack[CredeblAdminClientSecretEnv],
		CredeblManagementClientID: stack[CredeblManagementClientSecretEnv],
	}
	for _, c := range doc.Clients {
		if c.Secret == "" || c.Secret != secrets[c.ClientID] {
			t.Errorf("client %s got the secret %q", c.ClientID, c.Secret)
		}
	}
	if !strings.Contains(out.String(), "realm "+CredeblPlatformRealm+" created") {
		t.Errorf("out = %s", out.String())
	}
	out.Reset()
	if _, berr := BootstrapCredebl(context.Background(), opts); berr != nil {
		t.Fatalf("second BootstrapCredebl: %v", berr)
	}
	if state.realmPosts != 1 || len(state.clientPuts) != 2 {
		t.Errorf("posts %d, client updates %v", state.realmPosts, state.clientPuts)
	}
	for _, p := range state.clientPuts {
		var c struct {
			ClientID string `json:"clientId"`
			Secret   string `json:"secret"`
		}
		if jerr := json.Unmarshal(p, &c); jerr != nil || c.Secret != secrets[c.ClientID] {
			t.Errorf("client update %s: %v", p, jerr)
		}
	}
	if !strings.Contains(out.String(), "realm "+CredeblPlatformRealm+" present") {
		t.Errorf("out = %s", out.String())
	}
	for _, path := range state.keycloakPaths {
		if strings.Contains(path, "/vca-") {
			t.Errorf("the run touched a VCA realm: %s", path)
		}
	}
	// A deployment whose Keycloak has no .env stops with its name.
	bare := credeblOptions(t, server.URL, &out)
	if rerr := removeKeycloakEnv(bare); rerr != nil {
		t.Fatal(rerr)
	}
	if _, berr := BootstrapCredebl(context.Background(), bare); berr == nil || !strings.Contains(berr.Error(), KeycloakAdminPasswordEnv) {
		t.Errorf("err = %v, want the name of %s", berr, KeycloakAdminPasswordEnv)
	}
}
