// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"sort"
	"strconv"
	"strings"

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
	// Links name the variables that point at another service.
	// The CLI fills them from the port plan of the deployment.
	Links []Link
	// Fixed lists the variables whose value never changes.
	Fixed []FixedValue
}

// LinkKind says how the CLI builds the value of a cross service variable.
type LinkKind int

const (
	// LinkURL is the base URL of one other service, plus a path.
	LinkURL LinkKind = iota
	// LinkServiceMap is every service of the deployment, as name=url
	// items separated by commas. The admin health page reads it.
	LinkServiceMap
	// LinkAdapterMap is the DPG adapter of the pair, as one name=url item.
	LinkAdapterMap
	// LinkDpgName is the short name of the DPG of the pair.
	LinkDpgName
	// LinkPublicURL is the public base URL of the deployment.
	LinkPublicURL
)

// Link is one variable that names another service.
type Link struct {
	// Env is the variable the service reads.
	Env string
	// Target is the service the variable points at. It is used by
	// LinkURL only.
	Target string
	// Path is the path the CLI adds to the base URL.
	Path string
	// Kind says how to build the value.
	Kind LinkKind
}

// FixedValue is one variable with a value the CLI always writes.
type FixedValue struct {
	// Env is the variable name.
	Env string
	// Value is the value.
	Value string
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
		{Name: "admin", ListenEnv: "VCA_ADMIN_LISTEN", ExposedPort: 8093, Roles: admin, Stateful: true,
			Links: []Link{
				{Env: "VCA_ADMIN_PUBLIC_URL", Kind: LinkPublicURL},
				{Env: "VCA_ADMIN_TRUST_URL", Target: "trust-registry", Kind: LinkURL},
				{Env: "VCA_ADMIN_SERVICES", Kind: LinkServiceMap},
			},
			Fixed: []FixedValue{{Env: "VCA_ADMIN_STATE_DIR", Value: "/data"}}},
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
		{Name: "wallet-portal", ListenEnv: "VCA_WALLET_PORTAL_LISTEN", ExposedPort: 8092, Roles: holder, Stateful: true,
			Links: []Link{
				{Env: "VCA_WALLET_PORTAL_AUTH_JWKS_URL", Target: "wallet-auth", Path: "/.well-known/jwks.json", Kind: LinkURL},
				{Env: "VCA_WALLET_PORTAL_LOGIN_URL", Target: "wallet-auth", Path: "/login", Kind: LinkURL},
				{Env: "VCA_WALLET_PORTAL_DISCOVERY_URL", Target: "verifier-discovery", Kind: LinkURL},
				{Env: "VCA_WALLET_PORTAL_TRUST_URL", Target: "trust-registry", Kind: LinkURL},
				{Env: "VCA_WALLET_PORTAL_DPG", Kind: LinkDpgName},
				{Env: "VCA_WALLET_PORTAL_DPG_ADAPTERS", Kind: LinkAdapterMap},
			},
			Fixed: []FixedValue{{Env: "VCA_WALLET_PORTAL_STATE_DIR", Value: "/data"}}},
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
		return "wallet-portal"
	case commonv1.Role_ROLE_VERIFIER:
		return "verifier-results"
	case commonv1.Role_ROLE_ADMIN:
		return "admin"
	default:
		return ""
	}
}

// authService names the login service of a role. The verifier role and
// the admin role log staff in from their portal, so they run none.
func authService(role commonv1.Role) string {
	switch role {
	case commonv1.Role_ROLE_ISSUER:
		return "issuer-auth"
	case commonv1.Role_ROLE_HOLDER:
		return "wallet-auth"
	default:
		return ""
	}
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

// ownerPair returns the pair of the same DPG that runs one service.
// The pair of the caller wins when it runs the service itself, so a DPG
// adapter stays inside its own profile.
func ownerPair(p Pair, name string) (Pair, bool) {
	for _, s := range ServicesFor(p) {
		if s.Name == name {
			return p, true
		}
	}
	for _, r := range Roles() {
		other := Pair{Role: r, Dpg: p.Dpg}
		for _, s := range ServicesFor(other) {
			if s.Name == name {
				return other, true
			}
		}
	}
	return Pair{}, false
}

// serviceURL returns the URL of one service on the compose network.
// Every container of a pair carries the name <pair>-<service>, so two
// pairs of the same DPG reach each other.
func serviceURL(p Pair, name string) (string, bool) {
	owner, ok := ownerPair(p, name)
	if !ok {
		return "", false
	}
	for _, a := range AssignPorts(owner, nil) {
		if a.Service.Name == name {
			return "http://" + composeServiceName(owner, a.Service) + ":" + strconv.Itoa(a.Listen), true
		}
	}
	return "", false
}

// deploymentServices lists every service of one DPG across every role,
// once each, in service name order.
func deploymentServices(d configv1.Dpg) []Service {
	seen := map[string]bool{}
	var out []Service
	for _, s := range Catalog() {
		if s.Dpg != configv1.Dpg_DPG_UNSPECIFIED && s.Dpg != d {
			continue
		}
		if seen[s.Name] {
			continue
		}
		seen[s.Name] = true
		out = append(out, s)
	}
	return out
}

// LinkValues returns every cross service variable of one pair, keyed by
// variable name. The values point at the container names of the compose
// file, so a role reaches the services of another role of the same DPG.
// A link whose target no role runs is left out.
func LinkValues(p Pair, values map[string]string) map[string]string {
	out := map[string]string{}
	for _, s := range ServicesFor(p) {
		for _, f := range s.Fixed {
			out[f.Env] = f.Value
		}
		for _, link := range s.Links {
			if value, ok := linkValue(p, s, link, values); ok {
				out[link.Env] = value
			}
		}
	}
	return out
}

// linkValue builds the value of one link.
func linkValue(p Pair, s Service, link Link, values map[string]string) (string, bool) {
	switch link.Kind {
	case LinkURL:
		base, ok := serviceURL(p, link.Target)
		if !ok {
			return "", false
		}
		return base + link.Path, true
	case LinkServiceMap:
		var items []string
		for _, other := range deploymentServices(p.Dpg) {
			if other.Name == s.Name {
				continue
			}
			base, ok := serviceURL(p, other.Name)
			if !ok {
				continue
			}
			items = append(items, other.Name+"="+base)
		}
		if len(items) == 0 {
			return "", false
		}
		return strings.Join(items, ","), true
	case LinkAdapterMap:
		name := "dpg-adapter-" + ShortName(p.Dpg.String())
		base, ok := serviceURL(p, name)
		if !ok {
			return "", false
		}
		return ShortName(p.Dpg.String()) + "=" + base, true
	case LinkDpgName:
		if p.Dpg == configv1.Dpg_DPG_UNSPECIFIED {
			return "", false
		}
		return ShortName(p.Dpg.String()), true
	case LinkPublicURL:
		value := strings.TrimRight(values["VCA_PUBLIC_URL"], "/")
		return value, value != ""
	default:
		return "", false
	}
}
