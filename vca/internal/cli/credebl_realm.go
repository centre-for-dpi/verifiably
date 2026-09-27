// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// The realm of the CREDEBL platform in the Keycloak of the stack
// (P6-C0b). The platform signs its users in at KEYCLOAK_REALM with the
// password grant of the admin client, and it manages users and the
// client of each organisation with the management client. Both clients
// hold a generated secret of the stack .env. The realm belongs to the
// platform. The realms of the VCA roles stay as ADR-035 makes them, and
// no VCA service signs in here.
const (
	// CredeblPlatformRealm is the realm the platform reads as
	// KEYCLOAK_REALM.
	CredeblPlatformRealm = "credebl-platform" //nolint:gosec // G101: a name, not a credential.
	// CredeblAdminClientID is the client of ADMIN_KEYCLOAK_ID. The
	// initialisation makes the Keycloak user of the platform admin with
	// its token, and the sign in of the platform admin uses it.
	CredeblAdminClientID = "adminClient"
	// CredeblManagementClientID is the client of
	// KEYCLOAK_MANAGEMENT_CLIENT_ID.
	CredeblManagementClientID = "credeblClient" //nolint:gosec // G101: a name, not a credential.
	// CredeblAdminClientSecretEnv holds the generated secret of the
	// admin client in the stack .env.
	CredeblAdminClientSecretEnv = "CREDEBL_ADMIN_KEYCLOAK_SECRET" //nolint:gosec // G101: this is a variable name, not a credential.
	// CredeblManagementClientSecretEnv holds the generated secret of the
	// management client in the stack .env.
	CredeblManagementClientSecretEnv = "CREDEBL_KEYCLOAK_MANAGEMENT_CLIENT_SECRET" //nolint:gosec // G101: this is a variable name, not a credential.
	// CredeblKeycloakURLSetting overrides the address the bootstrap run
	// reaches the Keycloak of the stack on. Empty means 127.0.0.1 and
	// the host port of that Keycloak.
	CredeblKeycloakURLSetting = "VCA_CREDEBL_KEYCLOAK_ADMIN_URL" //nolint:gosec // G101: a name, not a credential.
)

// CredeblPlatformRealmFile is the path of the platform realm under the
// deploy root, beside the realms of the VCA roles. Keycloak imports it
// at its first start.
var CredeblPlatformRealmFile = KeycloakDir(configv1.Dpg_DPG_CREDEBL) + "/" + CredeblPlatformRealm + "-realm.json"

// credeblRealmManagementRoles are the roles of the realm-management
// client that both service accounts hold: the platform creates users,
// sets their passwords and roles, and makes a client for each
// organisation.
var credeblRealmManagementRoles = []string{
	"manage-users", "view-users", "query-users", "manage-clients", "view-clients", "query-clients",
	"create-client", "view-realm",
}

// platformRealmClient is one confidential client of the platform realm.
type platformRealmClient struct {
	ClientID                  string `json:"clientId"`
	Name                      string `json:"name"`
	Enabled                   bool   `json:"enabled"`
	ClientAuthenticatorType   string `json:"clientAuthenticatorType"`
	Secret                    string `json:"secret"`
	PublicClient              bool   `json:"publicClient"`
	StandardFlowEnabled       bool   `json:"standardFlowEnabled"`
	DirectAccessGrantsEnabled bool   `json:"directAccessGrantsEnabled"`
	ServiceAccountsEnabled    bool   `json:"serviceAccountsEnabled"`
	Protocol                  string `json:"protocol"`
}

// platformServiceAccount grants the roles of one service account.
type platformServiceAccount struct {
	Username               string              `json:"username"`
	Enabled                bool                `json:"enabled"`
	ServiceAccountClientID string              `json:"serviceAccountClientId"`
	ClientRoles            map[string][]string `json:"clientRoles"`
}

// platformRealm is the realm document.
type platformRealm struct {
	Realm                 string                   `json:"realm"`
	Enabled               bool                     `json:"enabled"`
	SslRequired           string                   `json:"sslRequired"`
	RegistrationAllowed   bool                     `json:"registrationAllowed"`
	LoginWithEmailAllowed bool                     `json:"loginWithEmailAllowed"`
	Roles                 map[string][]realmRole   `json:"roles"`
	Clients               []platformRealmClient    `json:"clients"`
	Users                 []platformServiceAccount `json:"users"`
}

// CredeblPlatformRealmJSON renders the platform realm. A nil secrets map
// writes the placeholder ${NAME} of each client secret, which Keycloak
// fills from its environment at the import, so the file holds no
// secret. A map fills the values of the stack .env, for the admin API.
func CredeblPlatformRealmJSON(secrets map[string]string) ([]byte, error) {
	secret := func(name string) (string, error) {
		if secrets == nil {
			return "${" + name + "}", nil
		}
		value := strings.TrimSpace(secrets[name])
		if value == "" {
			return "", fmt.Errorf("the CREDEBL platform realm needs %s; run vca setup", name)
		}
		return value, nil
	}
	admin, err := secret(CredeblAdminClientSecretEnv)
	if err != nil {
		return nil, err
	}
	management, err := secret(CredeblManagementClientSecretEnv)
	if err != nil {
		return nil, err
	}
	client := func(id, name, value string) platformRealmClient {
		return platformRealmClient{
			ClientID: id, Name: name, Enabled: true, ClientAuthenticatorType: "client-secret", Secret: value,
			DirectAccessGrantsEnabled: true, ServiceAccountsEnabled: true, Protocol: "openid-connect",
		}
	}
	account := func(id string) platformServiceAccount {
		return platformServiceAccount{
			Username: "service-account-" + strings.ToLower(id), Enabled: true, ServiceAccountClientID: id,
			ClientRoles: map[string][]string{"realm-management": credeblRealmManagementRoles},
		}
	}
	doc := platformRealm{
		Realm: CredeblPlatformRealm, Enabled: true, SslRequired: "external", LoginWithEmailAllowed: true,
		// The platform gives each user it makes the realm role mb-user.
		Roles: map[string][]realmRole{"realm": {
			{Name: "mb-user", Description: "A user of the CREDEBL platform."},
		}},
		Clients: []platformRealmClient{
			client(CredeblAdminClientID, "CREDEBL platform admin", admin),
			client(CredeblManagementClientID, "CREDEBL platform management", management),
		},
		Users: []platformServiceAccount{account(CredeblAdminClientID), account(CredeblManagementClientID)},
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("render the CREDEBL platform realm: %w", err)
	}
	return out, nil
}

// credeblKeycloakURL returns the address the bootstrap run reaches the
// Keycloak of the stack on.
func credeblKeycloakURL(opts BootstrapOptions) string {
	port := strconv.Itoa(KeycloakHostPort(configv1.Dpg_DPG_CREDEBL))
	if p := strings.TrimSpace(opts.Values[KeycloakHostPortEnv(configv1.Dpg_DPG_CREDEBL)]); p != "" {
		port = p
	}
	return strings.TrimRight(opts.value(CredeblKeycloakURLSetting, "http://127.0.0.1:"+port), "/")
}

// ensureCredeblPlatformRealm creates the platform realm with the secrets
// of the stack .env when the Keycloak of the stack lacks it, which
// happens when Keycloak started before the realm file existed. A realm
// that exists gets the client secrets of the .env again. The run signs
// in with the administrator of the Keycloak .env and touches no other
// realm.
func ensureCredeblPlatformRealm(ctx context.Context, opts BootstrapOptions, stack map[string]string, result *BootstrapResult) error {
	body, err := CredeblPlatformRealmJSON(stack)
	if err != nil {
		return err
	}
	keycloak, err := ReadKeycloakEnv(filepath.Dir(opts.Dir), configv1.Dpg_DPG_CREDEBL)
	if err != nil {
		return err
	}
	password := strings.TrimSpace(keycloak[KeycloakAdminPasswordEnv])
	if password == "" {
		return fmt.Errorf("CREDEBL platform realm: %s is missing from %s; run vca setup",
			KeycloakAdminPasswordEnv, KeycloakEnvFile(configv1.Dpg_DPG_CREDEBL))
	}
	user := strings.TrimSpace(keycloak[KeycloakAdminEnv])
	if user == "" {
		user = keycloakAdminUser
	}
	base := credeblKeycloakURL(opts)
	token, err := keycloakAdminToken(ctx, opts.client(), base, user, password)
	if err != nil {
		return fmt.Errorf("CREDEBL platform realm: %w", err)
	}
	status, _, err := doStatus(ctx, opts.client(), http.MethodGet, base+"/admin/realms/"+url.PathEscape(CredeblPlatformRealm), token, nil)
	if err != nil {
		return fmt.Errorf("read the CREDEBL platform realm: %w", err)
	}
	switch status {
	case http.StatusOK:
		if err := syncRealmClients(ctx, opts, base, CredeblPlatformRealm, token, body, result); err != nil {
			return err
		}
		result.step(opts.Out, "CREDEBL Keycloak realm %s present", CredeblPlatformRealm)
	case http.StatusNotFound:
		if _, err := doJSON(ctx, opts.client(), http.MethodPost, base+"/admin/realms", token, body); err != nil {
			return fmt.Errorf("create the CREDEBL platform realm: %w", err)
		}
		result.step(opts.Out, "CREDEBL Keycloak realm %s created", CredeblPlatformRealm)
	default:
		return fmt.Errorf("read the CREDEBL platform realm: the server answered %d", status)
	}
	return ensureCredeblEcosystemAccess(ctx, opts, base+"/admin/realms/"+url.PathEscape(CredeblPlatformRealm), token, result)
}

// EcosystemAccessAttribute is the user attribute and the token claim
// that hold the ecosystem roles of a platform user (ADR-068).
const EcosystemAccessAttribute = "ecosystem_access"

// keycloakNamed is an object of the Keycloak admin API with an id and a
// name, such as a client scope or a protocol mapper.
type keycloakNamed struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// named matches an object of the Keycloak admin API by its name.
func named(name string) func(keycloakNamed) bool {
	return func(o keycloakNamed) bool { return o.Name == name }
}

// ensureCredeblEcosystemAccess lets the platform realm carry the
// ecosystem roles of a user (P6-C9, ADR-068). The ecosystem service
// writes them to a user attribute that the user profile does not
// declare, and Keycloak 25 keeps such an attribute only when the user
// profile allows unmanaged attributes. The platform also refuses to turn
// ecosystems on without that policy. The guard of the platform reads the
// roles from a token claim, so a mapper on the profile client scope
// copies the attribute into each token. The run changes each part only
// when it is missing, and the management client of the platform keeps
// its roles.
func ensureCredeblEcosystemAccess(ctx context.Context, opts BootstrapOptions, realmURL, token string, result *BootstrapResult) error {
	raw, err := doJSON(ctx, opts.client(), http.MethodGet, realmURL+"/users/profile", token, nil)
	if err != nil {
		return fmt.Errorf("read the user profile of the CREDEBL platform realm: %w", err)
	}
	var profile map[string]json.RawMessage
	if json.Unmarshal(raw, &profile) != nil || profile == nil {
		return fmt.Errorf("read the user profile of the CREDEBL platform realm: %s", raw)
	}
	changed := false
	if string(profile["unmanagedAttributePolicy"]) != `"ENABLED"` {
		profile["unmanagedAttributePolicy"] = json.RawMessage(`"ENABLED"`)
		body, merr := json.Marshal(profile)
		if merr != nil {
			return merr
		}
		if _, perr := doJSON(ctx, opts.client(), http.MethodPut, realmURL+"/users/profile", token, body); perr != nil {
			return fmt.Errorf("allow unmanaged attributes in the CREDEBL platform realm: %w", perr)
		}
		changed = true
	}
	raw, err = doJSON(ctx, opts.client(), http.MethodGet, realmURL+"/client-scopes", token, nil)
	if err != nil {
		return fmt.Errorf("read the client scopes of the CREDEBL platform realm: %w", err)
	}
	var scopes []keycloakNamed
	if jerr := json.Unmarshal(raw, &scopes); jerr != nil {
		return fmt.Errorf("read the client scopes of the CREDEBL platform realm: %w", jerr)
	}
	i := slices.IndexFunc(scopes, named("profile"))
	if i < 0 {
		return errors.New("the CREDEBL platform realm has no profile client scope")
	}
	mappersURL := realmURL + "/client-scopes/" + url.PathEscape(scopes[i].ID) + "/protocol-mappers/models"
	raw, err = doJSON(ctx, opts.client(), http.MethodGet, mappersURL, token, nil)
	if err != nil {
		return fmt.Errorf("read the mappers of the profile client scope: %w", err)
	}
	var mappers []keycloakNamed
	if err := json.Unmarshal(raw, &mappers); err != nil {
		return fmt.Errorf("read the mappers of the profile client scope: %w", err)
	}
	if !slices.ContainsFunc(mappers, named(EcosystemAccessAttribute)) {
		body, merr := json.Marshal(map[string]any{
			"name": EcosystemAccessAttribute, "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-attribute-mapper",
			"config": map[string]string{
				"user.attribute": EcosystemAccessAttribute, "claim.name": EcosystemAccessAttribute, "jsonType.label": "JSON",
				"id.token.claim": "true", "access.token.claim": "true", "userinfo.token.claim": "true",
			},
		})
		if merr != nil {
			return merr
		}
		if _, err := doJSON(ctx, opts.client(), http.MethodPost, mappersURL, token, body); err != nil {
			return fmt.Errorf("map the ecosystem roles into the tokens of the CREDEBL platform realm: %w", err)
		}
		changed = true
	}
	if changed {
		result.step(opts.Out, "CREDEBL Keycloak realm %s carries the ecosystem access of each user", CredeblPlatformRealm)
	} else {
		result.step(opts.Out, "CREDEBL Keycloak realm %s already carries the ecosystem access of each user", CredeblPlatformRealm)
	}
	return nil
}
