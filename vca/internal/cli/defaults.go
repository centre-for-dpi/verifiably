// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// The laptop path asks no question. Every value that follows from the
// role and the DPG has a default here (ADR-007 decision 2,
// ADR-008 decision 7). An operator overrides any of them with a flag,
// the process environment, or the env file.

// dpgAPIURL is the container URL of the DPG API that one role calls.
// The host name and the port come from the compose file of the stack
// under deploy/vca/dpg. A production deployment overrides the value with
// VCA_DPG_URL.
var dpgAPIURL = map[configv1.Dpg]map[commonv1.Role]string{
	configv1.Dpg_DPG_WALTID: {
		commonv1.Role_ROLE_ISSUER:   "http://waltid-issuer-api:7002",
		commonv1.Role_ROLE_HOLDER:   "http://waltid-wallet-api:7001",
		commonv1.Role_ROLE_VERIFIER: "http://waltid-verifier-api:7003",
	},
	configv1.Dpg_DPG_INJI: {
		commonv1.Role_ROLE_ISSUER:   "http://inji-certify:8090",
		commonv1.Role_ROLE_HOLDER:   "http://inji-mimoto:8099",
		commonv1.Role_ROLE_VERIFIER: "http://inji-verify-service:8080",
	},
	configv1.Dpg_DPG_CREDEBL: {
		commonv1.Role_ROLE_ISSUER:   "http://credebl-api-gateway:5000",
		commonv1.Role_ROLE_HOLDER:   "http://credebl-api-gateway:5000",
		commonv1.Role_ROLE_VERIFIER: "http://credebl-api-gateway:5000",
	},
}

// DefaultDpgURL returns the container URL of the DPG API of one pair.
// The admin role calls no DPG, so it gets an empty value.
func DefaultDpgURL(p Pair) string { return dpgAPIURL[p.Dpg][p.Role] }

// keycloakHostPort is the host port that each DPG stack maps to port
// 8080 of its Keycloak. The numbers come from the compose file of the
// stack under deploy/vca/dpg.
var keycloakHostPort = map[configv1.Dpg]int{
	configv1.Dpg_DPG_WALTID:  17010,
	configv1.Dpg_DPG_INJI:    17080,
	configv1.Dpg_DPG_CREDEBL: 17180,
}

// KeycloakContainer returns the container name of the Keycloak of one
// DPG stack. Every stack ships one, so a laptop needs no other IdP.
func KeycloakContainer(d configv1.Dpg) string {
	if _, ok := keycloakHostPort[d]; !ok {
		return ""
	}
	return ShortName(d.String()) + "-keycloak"
}

// KeycloakHostPort returns the host port of the Keycloak of one DPG
// stack. A browser reaches the login page there.
func KeycloakHostPort(d configv1.Dpg) int { return keycloakHostPort[d] }

// KeycloakHostPortEnv is the compose variable that carries the host port
// of the Keycloak of one DPG stack.
func KeycloakHostPortEnv(d configv1.Dpg) string {
	if KeycloakContainer(d) == "" {
		return ""
	}
	return envName(ShortName(d.String())) + "_KEYCLOAK_HOST_PORT"
}

// DefaultDiscoveryURL returns the discovery URL of the realm of the role
// of the pair at the Keycloak of the stack, as the services reach it on
// the compose network (ADR-035 decision 1). A production deployment
// replaces it with the national IdP.
func DefaultDiscoveryURL(p Pair) string {
	realm := RealmName(p.Role)
	if realm == "" {
		return ""
	}
	return discoveryURLOfRealm(p.Dpg, realm)
}

// discoveryURLOfRealm returns the discovery URL of one realm at the
// Keycloak of one stack, on the compose network.
func discoveryURLOfRealm(d configv1.Dpg, realm string) string {
	name := KeycloakContainer(d)
	if name == "" {
		return ""
	}
	return fmt.Sprintf("http://%s:8080/realms/%s/.well-known/openid-configuration", name, realm)
}

// legacyDiscoveryURL returns the discovery URL an earlier setup wrote,
// which named the one realm of every role.
func legacyDiscoveryURL(d configv1.Dpg) string { return discoveryURLOfRealm(d, legacyRealm) }

// DefaultOidcPublicURL returns the browser facing base URL of the
// Keycloak of the stack, on the host port the compose file maps, for a
// local deployment.
func DefaultOidcPublicURL(p Pair) string { return OidcPublicURLFor(p, "") }

// OidcPublicURLFor returns the browser facing base URL of the Keycloak
// of the stack for one public URL. A local public URL, or none, gives
// http://localhost with the host port. A public host gives http with
// that host and the same port, because the browser of a remote user
// cannot reach localhost on the server. Keycloak listens with no TLS
// on that port, so a production deployment sets its own value.
func OidcPublicURLFor(p Pair, publicURL string) string {
	port := KeycloakHostPort(p.Dpg)
	if port == 0 {
		return ""
	}
	host := hostOf(publicURL)
	if host == "" || isLocalHost(host) {
		host = "localhost"
	}
	return fmt.Sprintf("http://%s:%d", host, port)
}

// DefaultClientID returns the OAuth 2.0 client id of one role. The
// generated realm holds a client with this id.
func DefaultClientID(role commonv1.Role) string {
	name := ShortName(role.String())
	if name == "" {
		return ""
	}
	return "vca-" + name
}

// DpgPort is one host port of a container of a DPG stack.
type DpgPort struct {
	// Container is the container name in the stack compose file.
	Container string
	// Host is the port on the machine that runs compose.
	Host int
	// Env is the compose variable that overrides the host port.
	Env string
	// Port is the port the container listens on.
	Port int
}

// DpgHostPorts lists the host ports of the DPG stack of one pair that
// the deployment itself needs. The Keycloak of the stack is one, because
// a browser reaches the login page there. The Inji holder pair adds
// Inji Web, where the browser of the holder claims (P6-I7d).
func DpgHostPorts(p Pair) []DpgPort {
	name := KeycloakContainer(p.Dpg)
	if name == "" {
		return nil
	}
	out := []DpgPort{{Container: name, Host: KeycloakHostPort(p.Dpg), Env: KeycloakHostPortEnv(p.Dpg), Port: 8080}}
	if isInjiHolder(p) {
		out = append(out, DpgPort{Container: "inji-web", Host: 17085, Env: "INJI_WEB_HOST_PORT", Port: 3004})
	}
	return out
}

// IdpTable renders the Keycloak of every DPG stack as a Markdown table.
// The deploy documentation includes it. The realm follows the role of
// the pair, so the table names it as vca-<role>-realm.
func IdpTable() string {
	rows := "| DPG | Keycloak container | Host port | Default `VCA_OIDC_DISCOVERY_URL` |\n|---|---|---|---|\n"
	for _, d := range Dpgs() {
		rows += fmt.Sprintf("| `%s` | `%s` | %d | `%s` |\n",
			ShortName(d.String()), KeycloakContainer(d), KeycloakHostPort(d), discoveryURLOfRealm(d, "vca-<role>-realm"))
	}
	return rows
}

// DpgURLTable renders the default DPG URL of every pair as a Markdown
// table. The deploy documentation includes it.
func DpgURLTable() string {
	rows := "| Role and DPG | Default `VCA_DPG_URL` |\n|---|---|\n"
	for _, p := range AllPairs() {
		url := DefaultDpgURL(p)
		if url == "" {
			continue
		}
		rows += fmt.Sprintf("| `%s` | `%s` |\n", p.Name(), url)
	}
	return rows
}
