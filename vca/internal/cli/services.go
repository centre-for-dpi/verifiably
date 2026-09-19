// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"sort"
	"strconv"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// ImagePrefix is the registry path of every service image (ADR-005).
const ImagePrefix = "ghcr.io/centre-for-dpi/vca-"

// Service is one VCA service of the deployment.
type Service struct {
	// Name is the directory name under services.
	Name string
	// ListenEnv is the variable that holds the listen address.
	ListenEnv string
	// ExposedPort is the port of the EXPOSE line of the Dockerfile.
	// Several services share a port, so the compose file overrides it.
	ExposedPort int
	// Roles lists the roles that run the service.
	Roles []commonv1.Role
	// Dpg is set only for a DPG adapter service.
	Dpg configv1.Dpg
	// Stateful reports whether the service needs a data volume.
	Stateful bool
}

// Image returns the image reference of the service without a tag.
func (s Service) Image() string { return ImagePrefix + s.Name }

// Catalog lists every VCA service, in service name order.
// The list follows the Dockerfile and the README of each service.
func Catalog() []Service {
	issuer := []commonv1.Role{commonv1.Role_ROLE_ISSUER}
	holder := []commonv1.Role{commonv1.Role_ROLE_HOLDER}
	verifier := []commonv1.Role{commonv1.Role_ROLE_VERIFIER}
	admin := []commonv1.Role{commonv1.Role_ROLE_ADMIN}
	everyRole := []commonv1.Role{
		commonv1.Role_ROLE_ISSUER, commonv1.Role_ROLE_HOLDER, commonv1.Role_ROLE_VERIFIER,
	}
	out := []Service{
		{Name: "data-source", ListenEnv: "VCA_DATASOURCE_LISTEN", ExposedPort: 8083, Roles: issuer, Stateful: true},
		{Name: "dpg-adapter-credebl", ListenEnv: "VCA_CREDEBL_LISTEN", ExposedPort: 8080, Roles: everyRole, Dpg: configv1.Dpg_DPG_CREDEBL},
		{Name: "dpg-adapter-inji", ListenEnv: "VCA_INJI_LISTEN", ExposedPort: 8080, Roles: everyRole, Dpg: configv1.Dpg_DPG_INJI},
		{Name: "dpg-adapter-waltid", ListenEnv: "VCA_WALTID_LISTEN", ExposedPort: 8080, Roles: everyRole, Dpg: configv1.Dpg_DPG_WALTID},
		{Name: "issuance", ListenEnv: "VCA_ISSUANCE_LISTEN", ExposedPort: 8080, Roles: issuer},
		{Name: "issued-credentials", ListenEnv: "VCA_ISSUED_LISTEN", ExposedPort: 8084, Roles: issuer, Stateful: true},
		{Name: "issuer-auth", ListenEnv: "VCA_ISSUER_AUTH_LISTEN", ExposedPort: 8081, Roles: issuer},
		{Name: "schema-builder-ui", ListenEnv: "VCA_SCHEMABUILDER_LISTEN", ExposedPort: 8081, Roles: issuer},
		{Name: "schema-registry", ListenEnv: "VCA_SCHEMA_LISTEN", ExposedPort: 8080, Roles: issuer, Stateful: true},
		{Name: "status-bitstring", ListenEnv: "VCA_STATUS_BITSTRING_LISTEN", ExposedPort: 8084, Roles: issuer, Stateful: true},
		{Name: "status-token", ListenEnv: "VCA_STATUS_TOKEN_LISTEN", ExposedPort: 8085, Roles: issuer, Stateful: true},
		{Name: "trust-registry", ListenEnv: "VCA_TRUST_LISTEN", ExposedPort: 8080, Roles: admin, Stateful: true},
		{Name: "verifier-combined", ListenEnv: "VCA_VERIFIER_COMBINED_LISTEN", ExposedPort: 8088, Roles: verifier, Stateful: true},
		{Name: "verifier-discovery", ListenEnv: "VCA_DISCOVERY_LISTEN", ExposedPort: 8090, Roles: verifier, Stateful: true},
		{Name: "verifier-ingest", ListenEnv: "VCA_INGEST_LISTEN", ExposedPort: 8091, Roles: verifier},
		{Name: "verifier-policy", ListenEnv: "VCA_VERIFIER_POLICY_LISTEN", ExposedPort: 8086, Roles: verifier, Stateful: true},
		{Name: "verifier-results", ListenEnv: "VCA_VERIFIER_RESULTS_LISTEN", ExposedPort: 8087, Roles: verifier, Stateful: true},
		{Name: "wallet-auth", ListenEnv: "VCA_WALLET_AUTH_LISTEN", ExposedPort: 8083, Roles: holder},
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ServicesFor lists the services of one role and DPG pair, in name order.
// An adapter of another DPG is left out.
func ServicesFor(p Pair) []Service {
	var out []Service
	for _, s := range Catalog() {
		if !wantsRole(s.Roles, p.Role) {
			continue
		}
		if s.Dpg != configv1.Dpg_DPG_UNSPECIFIED && s.Dpg != p.Dpg {
			continue
		}
		out = append(out, s)
	}
	return out
}

// portalService names the service that serves the portal of a role.
func portalService(role commonv1.Role) string {
	switch role {
	case commonv1.Role_ROLE_ISSUER:
		return "issuance"
	case commonv1.Role_ROLE_HOLDER:
		return "wallet-auth"
	case commonv1.Role_ROLE_VERIFIER:
		return "verifier-results"
	case commonv1.Role_ROLE_ADMIN:
		return "trust-registry"
	default:
		return ""
	}
}

// authService names the login service of a role. Only the issuer role
// runs a separate one.
func authService(role commonv1.Role) string {
	if role == commonv1.Role_ROLE_ISSUER {
		return "issuer-auth"
	}
	return ""
}

// firstServicePort is the port the CLI assigns to the first service that
// is not the portal, the auth service, or the adapter.
const firstServicePort = 8100

// PortAssignment is the port plan of one service in one pair.
type PortAssignment struct {
	// Service is the service name.
	Service Service
	// Listen is the port inside the container.
	Listen int
	// Host is the port on the machine that runs compose.
	// Every pair gets its own block, so no two pairs collide.
	Host int
	// PortEnv is the variable that carries the port in the .env file.
	PortEnv string
}

// hostBase returns the first host port of a pair. Each role gets a block
// of 300 ports and each DPG a block of 100 inside it, so two pairs never
// map the same host port (ADR-008 decision 1).
func hostBase(p Pair) int {
	role, dpg := 0, 0
	for i, r := range Roles() {
		if r == p.Role {
			role = i
		}
	}
	for i, d := range Dpgs() {
		if d == p.Dpg {
			dpg = i
		}
	}
	return 18000 + role*300 + dpg*100
}

// AssignPorts plans the listen port and the host port of every service of
// a pair. The values map, keyed by environment variable name, overrides
// the portal, auth, and adapter ports. Every other service gets 8100 and
// up in service name order, as the Config message states.
func AssignPorts(p Pair, values map[string]string) []PortAssignment {
	portal := portFrom(values, "VCA_PORTS_PORTAL", 8080)
	auth := portFrom(values, "VCA_PORTS_AUTH", 8081)
	adapter := portFrom(values, "VCA_PORTS_ADAPTER", 8090)
	base := hostBase(p)
	next := firstServicePort
	var out []PortAssignment
	for i, s := range ServicesFor(p) {
		listen := 0
		env := ""
		switch {
		case s.Name == portalService(p.Role):
			listen, env = portal, "VCA_PORTS_PORTAL"
		case s.Name == authService(p.Role):
			listen, env = auth, "VCA_PORTS_AUTH"
		case s.Dpg != configv1.Dpg_DPG_UNSPECIFIED:
			listen, env = adapter, "VCA_PORTS_ADAPTER"
		default:
			listen = next
			env = "VCA_PORTS_" + envName(s.Name)
			next++
		}
		out = append(out, PortAssignment{Service: s, Listen: listen, Host: base + i, PortEnv: env})
	}
	return out
}

// portFrom reads a port from the values map and falls back to the default.
func portFrom(values map[string]string, key string, fallback int) int {
	if values != nil {
		if raw, ok := values[key]; ok {
			if n, err := strconv.Atoi(raw); err == nil && n >= 1024 && n <= 65535 {
				return n
			}
		}
	}
	return fallback
}

// envName turns a service name into the tail of a variable name.
// verifier-policy becomes VERIFIER_POLICY.
func envName(name string) string {
	out := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c == '-':
			out = append(out, '_')
		case c >= 'a' && c <= 'z':
			out = append(out, c-32)
		default:
			out = append(out, c)
		}
	}
	return string(out)
}

// PortValues turns a port plan into the extra variables of the .env file.
func PortValues(plan []PortAssignment) map[string]string {
	out := make(map[string]string, len(plan)*2)
	for _, a := range plan {
		out[a.PortEnv] = strconv.Itoa(a.Listen)
		out[a.Service.ListenEnv] = ":" + strconv.Itoa(a.Listen)
		out["VCA_HOST_PORT_"+envName(a.Service.Name)] = strconv.Itoa(a.Host)
	}
	return out
}
