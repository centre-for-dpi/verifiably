// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// TestKeycloakRealmPutsTheRealmRolesInTheIDToken: the auth services map
// the roles of a login from realm_access.roles of the ID token, and the
// default client scope of Keycloak writes the realm roles to the access
// token only. The client of every realm carries a mapper for the ID
// token, so a self registered issuer gets issuer-operator at sign in.
func TestKeycloakRealmPutsTheRealmRolesInTheIDToken(t *testing.T) {
	t.Parallel()
	for _, role := range []commonv1.Role{commonv1.Role_ROLE_ISSUER, commonv1.Role_ROLE_HOLDER, commonv1.Role_ROLE_VERIFIER, commonv1.Role_ROLE_ADMIN} {
		body, err := KeycloakRealm(Pair{Role: role, Dpg: configv1.Dpg_DPG_WALTID}, map[string]string{"VCA_PUBLIC_URL": "https://pair.example"})
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Clients []struct {
				ClientID string `json:"clientId"`
				Mappers  []struct {
					Mapper string            `json:"protocolMapper"`
					Config map[string]string `json:"config"`
				} `json:"protocolMappers"`
			} `json:"clients"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, c := range doc.Clients {
			if c.ClientID != DefaultClientID(role) {
				continue
			}
			for _, m := range c.Mappers {
				if m.Mapper == "oidc-usermodel-realm-role-mapper" && m.Config["claim.name"] == "realm_access.roles" &&
					m.Config["id.token.claim"] == "true" && m.Config["multivalued"] == "true" {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("the client of %s has no realm roles mapper for the ID token", RealmName(role))
		}
	}
}
