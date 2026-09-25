// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// Generated DPG configuration file names (ADR-007 decision 5).
const (
	// CaddyFile is the reverse proxy configuration of a pair.
	CaddyFile = "Caddyfile"
	// OnboardFile is the walt.id issuer onboarding request body.
	OnboardFile = "waltid-onboard.json"
)

// The Keycloak of one stack (ADR-035 decisions 1 and 7). Its directory
// sits beside the pair directories under deploy. It holds one realm per
// role and the .env with the generated administrator password. Keycloak
// parses every JSON file of the directory at its first start, so nothing
// but a realm ends in .json there.
const (
	// KeycloakAdminEnv names the administrator of the Keycloak.
	KeycloakAdminEnv = "KEYCLOAK_ADMIN"
	// KeycloakAdminPasswordEnv names the generated administrator password.
	KeycloakAdminPasswordEnv = "KEYCLOAK_ADMIN_PASSWORD" //nolint:gosec // G101: a variable name, not a credential
	// keycloakAdminUser is the administrator name the CLI writes.
	keycloakAdminUser = "admin"
	// legacyRealm is the one realm an earlier setup wrote for every role.
	legacyRealm = "vca"
)

// RealmName returns the Keycloak realm of one role: vca-<role>-realm.
// Each role has its own user base (ADR-035 decision 1).
func RealmName(role commonv1.Role) string {
	name := ShortName(role.String())
	if name == "" {
		return ""
	}
	return "vca-" + name + "-realm"
}

// KeycloakDir returns the directory of the Keycloak of one stack under
// the deploy root: keycloak-<dpg>. A DPG with no Keycloak gives "".
func KeycloakDir(d configv1.Dpg) string {
	if KeycloakContainer(d) == "" {
		return ""
	}
	return "keycloak-" + ShortName(d.String())
}

// RealmFileOf returns the path of the realm of one pair under the deploy
// root: keycloak-<dpg>/vca-<role>-realm.json.
func RealmFileOf(p Pair) string {
	dir := KeycloakDir(p.Dpg)
	if dir == "" || RealmName(p.Role) == "" {
		return ""
	}
	return dir + "/" + RealmName(p.Role) + ".json"
}

// KeycloakEnvFile returns the path of the .env of the Keycloak of one
// stack under the deploy root. The stack file reads it.
func KeycloakEnvFile(d configv1.Dpg) string {
	dir := KeycloakDir(d)
	if dir == "" {
		return ""
	}
	return dir + "/" + EnvFileName
}

// hostOf returns the host part of a URL, without the port.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Hostname()
}

// Caddyfile renders the reverse proxy configuration of a pair. The
// reverse proxy of the host terminates TLS and forwards every request
// to the host port of a service, so the file works from a Caddy that
// other projects on the same host share. One line in that Caddy,
// import <deploy dir>/*/Caddyfile, takes every pair (ADR-007 decision 5).
//
// The site holds one handle block per route of the route table, in
// service name order. A Strip route removes the first segment of its
// matcher with uri strip_prefix, so the service sees the path without
// its prefix. A handle block per refused matcher answers 404 to every
// Connect path that no route names (ADR-047). The exact root redirects
// to the home page of the role, and a final handle block sends every
// other path to the home service. Caddy sorts handle blocks by the
// length of their path matcher, so the order in the file does not
// matter.
//
// The issuer pair of a stack also carries the site of the Keycloak of
// the stack when the OIDC public URL names a public host.
func Caddyfile(p Pair, values map[string]string) string {
	host := hostOf(values["VCA_PUBLIC_URL"])
	if host == "" {
		host = "localhost"
	}
	home := HomeOf(p.Role)
	var b strings.Builder
	fmt.Fprintf(&b, "# Caddyfile for %s. The vca setup command generated it.\n", p.Name())
	fmt.Fprintf(&b, "# Edit it and run vca deploy --role %s --dpg %s again.\n",
		ShortName(p.Role.String()), ShortName(p.Dpg.String()))
	b.WriteString("# Import it into the Caddy of the host: import <deploy dir>/*/Caddyfile\n")
	fmt.Fprintf(&b, "%s {\n", host)
	b.WriteString("\tencode gzip\n")
	for _, sr := range PairRoutes(p, values) {
		fmt.Fprintf(&b, "\t# %s\n", sr.Service)
		fmt.Fprintf(&b, "\thandle %s {\n", sr.Route.Match)
		if prefix := sr.Route.StripPrefix(); prefix != "" {
			fmt.Fprintf(&b, "\t\turi strip_prefix %s\n", prefix)
		}
		fmt.Fprintf(&b, "\t\treverse_proxy 127.0.0.1:%d\n", sr.Host)
		b.WriteString("\t}\n")
	}
	b.WriteString("\t# Every other Connect service stays on the compose network (ADR-047)\n")
	for _, match := range RefusedRoutes(p) {
		fmt.Fprintf(&b, "\thandle %s {\n", match)
		b.WriteString("\t\trespond 404\n")
		b.WriteString("\t}\n")
	}
	homePort := 0
	for _, a := range HostPorts(p, values) {
		if a.Service.Name == home.Service {
			homePort = a.Host
		}
	}
	fmt.Fprintf(&b, "\t# The home page of the %s role, on %s\n", ShortName(p.Role.String()), home.Service)
	b.WriteString("\thandle / {\n")
	// The * matcher keeps Caddy from reading the path as a matcher.
	fmt.Fprintf(&b, "\t\tredir * %s 302\n", home.Path)
	b.WriteString("\t}\n")
	b.WriteString("\thandle {\n")
	fmt.Fprintf(&b, "\t\treverse_proxy 127.0.0.1:%d\n", homePort)
	b.WriteString("\t}\n")
	b.WriteString("}\n")
	if site := keycloakSite(p, values); site != "" {
		b.WriteString("\n" + site)
	}
	return b.String()
}

// LandingCaddyfile renders the site of the landing for the reverse proxy
// of the host: vca.<domain> goes to the host port of the landing
// (ADR-033 decision 2). A local landing or a missing public URL gives
// nothing.
func LandingCaddyfile(values map[string]string) string {
	host := hostOf(values[LandingPublicURLEnv])
	if host == "" || isLocalHost(host) {
		return ""
	}
	var b strings.Builder
	b.WriteString("# The landing of the deployment. Every journey starts here.\n")
	fmt.Fprintf(&b, "%s {\n", host)
	b.WriteString("\tencode gzip\n")
	fmt.Fprintf(&b, "\treverse_proxy 127.0.0.1:%d\n", LandingHostPortOf(values))
	b.WriteString("}\n")
	return b.String()
}

// keycloakSite renders the site block of the Keycloak of the stack. The
// issuer pair owns it, as it owns the realm import. A local OIDC public
// URL needs no site.
func keycloakSite(p Pair, values map[string]string) string {
	if p.Role != commonv1.Role_ROLE_ISSUER {
		return ""
	}
	host := hostOf(values["VCA_OIDC_PUBLIC_URL"])
	if host == "" || isLocalHost(host) {
		return ""
	}
	port := KeycloakHostPort(p.Dpg)
	if port == 0 {
		return ""
	}
	for _, d := range DpgHostPorts(p) {
		if d.Container == KeycloakContainer(p.Dpg) {
			port = portFrom(values, d.Env, d.Host)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# The Keycloak of the %s stack. The browser reaches the login page here.\n",
		ShortName(p.Dpg.String()))
	fmt.Fprintf(&b, "%s {\n", host)
	fmt.Fprintf(&b, "\treverse_proxy 127.0.0.1:%d\n", port)
	b.WriteString("}\n")
	return b.String()
}

// realmClient is one OpenID Connect client of the generated realm.
type realmClient struct {
	ClientID                  string   `json:"clientId"`
	Name                      string   `json:"name"`
	Enabled                   bool     `json:"enabled"`
	Secret                    string   `json:"secret,omitempty"`
	PublicClient              bool     `json:"publicClient"`
	StandardFlowEnabled       bool     `json:"standardFlowEnabled"`
	ImplicitFlowEnabled       bool     `json:"implicitFlowEnabled"`
	DirectAccessGrantsEnabled bool     `json:"directAccessGrantsEnabled"`
	RedirectUris              []string `json:"redirectUris"`
	WebOrigins                []string `json:"webOrigins"`
	Attributes                struct {
		PkceCodeChallengeMethod string `json:"pkce.code.challenge.method"`
	} `json:"attributes"`
}

// realm is the Keycloak realm of one role that the CLI writes.
type realm struct {
	Realm                 string        `json:"realm"`
	Enabled               bool          `json:"enabled"`
	SslRequired           string        `json:"sslRequired"`
	RegistrationAllowed   bool          `json:"registrationAllowed"`
	ResetPasswordAllowed  bool          `json:"resetPasswordAllowed"`
	LoginWithEmailAllowed bool          `json:"loginWithEmailAllowed"`
	Roles                 realmRoles    `json:"roles"`
	DefaultRole           realmRole     `json:"defaultRole"`
	Clients               []realmClient `json:"clients"`
}

type realmRoles struct {
	Realm []realmRole `json:"realm"`
}

// realmRole is one realm role. The default role of the realm is a
// composite: every self registered user gets its members.
type realmRole struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Composite   bool             `json:"composite,omitempty"`
	Composites  *realmComposites `json:"composites,omitempty"`
}

type realmComposites struct {
	Realm []string `json:"realm"`
}

// roleRealmRoles lists the realm roles of one role and the one a self
// registered user gets. The issuer and verifier roles are the ones the
// auth services map (ADR-012 decision 3, ADR-036 decision 1). A holder
// is a citizen. An admin gets no role at registration: the bootstrap
// token binds the first admin (ADR-035 decision 6).
func roleRealmRoles(role commonv1.Role) (roles []realmRole, selfRegistered string) {
	switch role {
	case commonv1.Role_ROLE_ISSUER:
		return []realmRole{
			{Name: "issuer-admin", Description: "Manage schemas, issuance, and issuer staff."},
			{Name: "issuer-operator", Description: "Issue and revoke credentials."},
			{Name: "issuer-viewer", Description: "Read schemas and issued credentials."},
		}, "issuer-operator"
	case commonv1.Role_ROLE_VERIFIER:
		return []realmRole{
			{Name: "verifier-admin", Description: "Manage policies, trust, and verifier staff."},
			{Name: "verifier-operator", Description: "Run verifications and read results."},
			{Name: "verifier-viewer", Description: "Read verification results."},
		}, "verifier-operator"
	case commonv1.Role_ROLE_HOLDER:
		return []realmRole{
			{Name: "holder", Description: "Hold and present credentials."},
		}, "holder"
	case commonv1.Role_ROLE_ADMIN:
		return []realmRole{
			{Name: "super-admin", Description: "Administer tenants, trust entries, and providers."},
		}, ""
	}
	return nil, ""
}

// KeycloakRealm renders the realm of the role of a pair. The Keycloak of
// the stack imports it. The realm has self registration on, and the
// default role of the realm gives a self registered user the role of
// the pair (ADR-035 decision 1). It holds one client with the exact
// redirect URI of the deployment, the authorization code flow, and PKCE
// S256 (ADR-010 decision 2). The implicit flow stays off. A generated
// client secret makes the client confidential.
func KeycloakRealm(p Pair, values map[string]string) ([]byte, error) {
	public := strings.TrimRight(values["VCA_PUBLIC_URL"], "/")
	if public == "" {
		return nil, fmt.Errorf("realm: %s is empty", "VCA_PUBLIC_URL")
	}
	name := RealmName(p.Role)
	if name == "" {
		return nil, fmt.Errorf("realm: the role of %s is unspecified", p.Name())
	}
	clientID := values["VCA_OIDC_CLIENT_ID"]
	if clientID == "" {
		clientID = DefaultClientID(p.Role)
	}
	redirect := values["VCA_OIDC_REDIRECT_URI"]
	if redirect == "" {
		redirect = public + "/auth/callback"
	}
	secret := values["VCA_OIDC_CLIENT_SECRET"]
	client := realmClient{
		ClientID:            clientID,
		Name:                "Verifiable Credentials Adapters " + ShortName(p.Role.String()),
		Enabled:             true,
		Secret:              secret,
		PublicClient:        secret == "",
		StandardFlowEnabled: true,
		RedirectUris:        []string{redirect},
		WebOrigins:          []string{public},
	}
	client.Attributes.PkceCodeChallengeMethod = "S256"
	roles, selfRegistered := roleRealmRoles(p.Role)
	defaultRole := realmRole{
		Name:        "default-roles-" + name,
		Description: "The roles of every user of the realm.",
		Composite:   true,
		Composites:  &realmComposites{Realm: []string{}},
	}
	if selfRegistered != "" {
		defaultRole.Composites.Realm = []string{selfRegistered}
	}
	r := realm{
		Realm:                 name,
		Enabled:               true,
		SslRequired:           "external",
		RegistrationAllowed:   true,
		ResetPasswordAllowed:  true,
		LoginWithEmailAllowed: true,
		Roles:                 realmRoles{Realm: append(roles, defaultRole)},
		DefaultRole:           realmRole{Name: defaultRole.Name, Composite: true},
		Clients:               []realmClient{client},
	}
	return json.MarshalIndent(r, "", "  ")
}

// onboardRequest is the body of POST /onboard/issuer of walt.id.
type onboardRequest struct {
	Key struct {
		Backend string `json:"backend"`
		KeyType string `json:"keyType"`
	} `json:"key"`
	Did struct {
		Method string `json:"method"`
		Config struct {
			Domain string `json:"domain"`
			Path   string `json:"path"`
		} `json:"config"`
	} `json:"did"`
}

// WaltidOnboard renders the body that provisions a did:web issuer on the
// walt.id issuer API. The vca dpg bootstrap waltid command posts it
// (ADR-008 decision 4).
func WaltidOnboard(values map[string]string) ([]byte, error) {
	domain := hostOf(values["VCA_PUBLIC_URL"])
	if domain == "" {
		return nil, fmt.Errorf("onboard: %s is not an absolute URL", "VCA_PUBLIC_URL")
	}
	var req onboardRequest
	req.Key.Backend = "jwk"
	req.Key.KeyType = "secp256r1"
	req.Did.Method = "web"
	req.Did.Config.Domain = domain
	req.Did.Config.Path = "/issuer"
	return json.MarshalIndent(req, "", "  ")
}

// DpgConfigFiles renders every generated DPG configuration file of a pair
// that lives in the directory of the pair. Every pair gets a Caddyfile.
// walt.id gets the onboarding body as well. The realm of the pair lives
// in the directory of the Keycloak of the stack, see KeycloakFiles.
func DpgConfigFiles(p Pair, values map[string]string, plan []PortAssignment) ([]File, error) {
	files := []File{{Name: CaddyFile, Data: []byte(Caddyfile(p, values)), Mode: 0o644}}
	if p.Dpg == configv1.Dpg_DPG_WALTID {
		body, onboardErr := WaltidOnboard(values)
		if onboardErr != nil {
			return nil, onboardErr
		}
		files = append(files, File{Name: OnboardFile, Data: append(body, '\n'), Mode: 0o644})
	}
	return files, nil
}

// KeycloakFiles renders the files of the Keycloak of the stack that one
// setup run writes, with paths relative to the deploy root: the realm of
// the role of the pair, and the .env of the Keycloak with the generated
// administrator password (ADR-035 decisions 1 and 7). existing holds the
// values of that .env from an earlier run, so the password of the stack
// survives every later run of any role. A pair whose DPG ships no
// Keycloak gets nothing.
func KeycloakFiles(p Pair, values, existing map[string]string, random io.Reader) ([]File, error) {
	if KeycloakDir(p.Dpg) == "" {
		return nil, nil
	}
	realmBody, err := KeycloakRealm(p, values)
	if err != nil {
		return nil, err
	}
	env, err := KeycloakEnv(p.Dpg, existing, random)
	if err != nil {
		return nil, err
	}
	return []File{
		{Name: RealmFileOf(p), Data: append(realmBody, '\n'), Mode: 0o644},
		{Name: KeycloakEnvFile(p.Dpg), Data: []byte(env), Mode: 0o600},
	}, nil
}

// KeycloakEnv renders the .env of the Keycloak of one stack. The
// administrator name is admin. The password comes from existing when an
// earlier run generated it, else from random. No default password ships
// (ADR-035 consequence 3).
func KeycloakEnv(d configv1.Dpg, existing map[string]string, random io.Reader) (string, error) {
	user := existing[KeycloakAdminEnv]
	if user == "" {
		user = keycloakAdminUser
	}
	password := existing[KeycloakAdminPasswordEnv]
	if password == "" {
		generated, err := RandomSecret(random)
		if err != nil {
			return "", fmt.Errorf("generate the Keycloak administrator password: %w", err)
		}
		password = generated
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# The Keycloak of the %s stack. Every role of the stack shares it.\n", ShortName(d.String()))
	b.WriteString("# The vca setup command wrote this file. A later run keeps the password.\n")
	b.WriteString("# Sign in to the administration console with these values.\n")
	b.WriteString(KeycloakAdminEnv + "=" + quoteValue(user) + "\n")
	b.WriteString(KeycloakAdminPasswordEnv + "=" + quoteValue(password) + "\n")
	return b.String(), nil
}

// ResourceFloor is the memory and CPU floor of one role, in the units the
// deploy documentation uses (ADR-008 decision 7).
type ResourceFloor struct {
	// Role is the role the floor applies to.
	Role commonv1.Role
	// Services is the number of VCA services the role runs.
	Services int
	// VcaMemoryMiB is the memory the VCA services need together.
	VcaMemoryMiB int
	// DpgMemoryMiB is the memory the DPG stack needs.
	DpgMemoryMiB int
	// Cpus is the CPU count the role needs.
	Cpus float64
}

// TotalMemoryMiB is the memory floor of the role and its DPG together.
func (f ResourceFloor) TotalMemoryMiB() int { return f.VcaMemoryMiB + f.DpgMemoryMiB }

// perServiceMemoryMiB is the memory one distroless Go service needs.
// A service holds one HTTP server and a small cache (ADR-005 decision 1).
const perServiceMemoryMiB = 96

// dpgMemoryMiB is the memory floor of one DPG stack, from the compose
// files under deploy/vca/dpg. Each figure holds the Keycloak of the
// stack.
var dpgMemoryMiB = map[configv1.Dpg]int{
	configv1.Dpg_DPG_WALTID:  2048,
	configv1.Dpg_DPG_INJI:    2560,
	configv1.Dpg_DPG_CREDEBL: 2560,
}

// keycloakMemoryMiB is the memory floor of the Keycloak of one stack.
const keycloakMemoryMiB = 512

// Floor returns the resource floor of one pair. The target of ADR-008
// decision 7 is under 4 GB for a single role with one DPG.
func Floor(p Pair) ResourceFloor {
	services := len(ServicesFor(p))
	dpg := dpgMemoryMiB[p.Dpg]
	if p.Role == commonv1.Role_ROLE_ADMIN {
		// The admin role talks to no DPG. Its profile starts only the
		// Keycloak of the stack, which logs the admins in.
		dpg = keycloakMemoryMiB
	}
	return ResourceFloor{
		Role:         p.Role,
		Services:     services,
		VcaMemoryMiB: services * perServiceMemoryMiB,
		DpgMemoryMiB: dpg,
		Cpus:         1 + float64(services)/4,
	}
}

// LandingMemoryMiB is the memory the landing adds to a deployment, once.
// It is one more distroless Go service (ADR-033 consequence 2).
const LandingMemoryMiB = perServiceMemoryMiB

// FloorNote is the sentence under the floor table that names the landing.
// The deploy documentation holds it word for word.
func FloorNote() string {
	return fmt.Sprintf("The landing adds %d MiB once, whatever the selection, because every profile starts the one landing container.", LandingMemoryMiB)
}

// FloorTable renders the resource floor of every pair as a Markdown table.
// The deploy documentation includes it (ADR-008 decision 7).
func FloorTable() string {
	var b strings.Builder
	b.WriteString("| Role and DPG | VCA services | VCA memory | DPG memory | Total memory | CPUs |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, p := range AllPairs() {
		f := Floor(p)
		fmt.Fprintf(&b, "| `%s` | %d | %d MiB | %d MiB | %d MiB | %s |\n",
			p.Name(), f.Services, f.VcaMemoryMiB, f.DpgMemoryMiB, f.TotalMemoryMiB(),
			strconv.FormatFloat(f.Cpus, 'f', -1, 64))
	}
	return b.String()
}
