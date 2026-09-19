// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
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
	// RealmFile is the Keycloak realm that Inji and CREDEBL import.
	RealmFile = "keycloak-realm.json"
	// OnboardFile is the walt.id issuer onboarding request body.
	OnboardFile = "waltid-onboard.json"
)

// DefaultRealm is the Keycloak realm name the CLI creates.
const DefaultRealm = "vca"

// hostOf returns the host part of a URL, without the port.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Hostname()
}

// Caddyfile renders the reverse proxy configuration of a pair.
// Caddy terminates TLS at the public host and sends every request to the
// portal service on the compose network (ADR-007 decision 5).
func Caddyfile(p Pair, values map[string]string, plan []PortAssignment) string {
	host := hostOf(values["VCA_PUBLIC_URL"])
	if host == "" {
		host = "localhost"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Caddyfile for %s. The vca setup command generated it.\n", p.Name())
	fmt.Fprintf(&b, "# Edit it and run vca deploy --role %s --dpg %s again.\n",
		ShortName(p.Role.String()), ShortName(p.Dpg.String()))
	fmt.Fprintf(&b, "%s {\n", host)
	b.WriteString("\tencode gzip\n")
	for _, a := range plan {
		if a.Service.Name == portalService(p.Role) {
			continue
		}
		fmt.Fprintf(&b, "\thandle /%s/* {\n", a.Service.Name)
		fmt.Fprintf(&b, "\t\treverse_proxy %s:%d\n", a.Service.Name, a.Listen)
		b.WriteString("\t}\n")
	}
	for _, a := range plan {
		if a.Service.Name != portalService(p.Role) {
			continue
		}
		fmt.Fprintf(&b, "\treverse_proxy %s:%d\n", a.Service.Name, a.Listen)
	}
	b.WriteString("}\n")
	return b.String()
}

// realmClient is one OpenID Connect client of the generated realm.
type realmClient struct {
	ClientID                  string   `json:"clientId"`
	Name                      string   `json:"name"`
	Enabled                   bool     `json:"enabled"`
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

// realm is the Keycloak realm the CLI writes for Inji and CREDEBL.
type realm struct {
	Realm                 string        `json:"realm"`
	Enabled               bool          `json:"enabled"`
	SslRequired           string        `json:"sslRequired"`
	RegistrationAllowed   bool          `json:"registrationAllowed"`
	LoginWithEmailAllowed bool          `json:"loginWithEmailAllowed"`
	Roles                 realmRoles    `json:"roles"`
	Clients               []realmClient `json:"clients"`
}

type realmRoles struct {
	Realm []realmRole `json:"realm"`
}

type realmRole struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// KeycloakRealm renders the realm that the Inji and the CREDEBL stacks
// import. The realm holds one public client with the exact redirect URI
// of the deployment, the authorization code flow, and PKCE
// (ADR-010 decision 2). The implicit flow stays off.
func KeycloakRealm(p Pair, values map[string]string) ([]byte, error) {
	public := strings.TrimRight(values["VCA_PUBLIC_URL"], "/")
	if public == "" {
		return nil, fmt.Errorf("realm: %s is empty", "VCA_PUBLIC_URL")
	}
	clientID := values["VCA_OIDC_CLIENT_ID"]
	if clientID == "" {
		clientID = "vca-" + ShortName(p.Role.String())
	}
	redirect := values["VCA_OIDC_REDIRECT_URI"]
	if redirect == "" {
		redirect = public + "/auth/callback"
	}
	client := realmClient{
		ClientID:            clientID,
		Name:                "Verifiable Credentials Adapters " + ShortName(p.Role.String()),
		Enabled:             true,
		PublicClient:        true,
		StandardFlowEnabled: true,
		RedirectUris:        []string{redirect},
		WebOrigins:          []string{public},
	}
	client.Attributes.PkceCodeChallengeMethod = "S256"
	r := realm{
		Realm:       DefaultRealm,
		Enabled:     true,
		SslRequired: "external",
		Roles: realmRoles{Realm: []realmRole{
			{Name: "vca-issuer-staff", Description: "Issue and revoke credentials."},
			{Name: "vca-verifier-staff", Description: "Run verifications and read results."},
			{Name: "vca-admin", Description: "Administer tenants, trust entries, and providers."},
		}},
		Clients: []realmClient{client},
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

// DpgConfigFiles renders every generated DPG configuration file of a pair.
// walt.id gets the onboarding body. Inji and CREDEBL get a Keycloak realm.
// Every pair gets a Caddyfile.
func DpgConfigFiles(p Pair, values map[string]string, plan []PortAssignment) ([]File, error) {
	files := []File{{Name: CaddyFile, Data: []byte(Caddyfile(p, values, plan)), Mode: 0o644}}
	switch p.Dpg {
	case configv1.Dpg_DPG_WALTID:
		body, err := WaltidOnboard(values)
		if err != nil {
			return nil, err
		}
		files = append(files, File{Name: OnboardFile, Data: append(body, '\n'), Mode: 0o644})
	case configv1.Dpg_DPG_INJI, configv1.Dpg_DPG_CREDEBL:
		body, err := KeycloakRealm(p, values)
		if err != nil {
			return nil, err
		}
		files = append(files, File{Name: RealmFile, Data: append(body, '\n'), Mode: 0o644})
	}
	return files, nil
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
// files under deploy/vca/dpg.
var dpgMemoryMiB = map[configv1.Dpg]int{
	configv1.Dpg_DPG_WALTID:  1536,
	configv1.Dpg_DPG_INJI:    2560,
	configv1.Dpg_DPG_CREDEBL: 2560,
}

// Floor returns the resource floor of one pair. The target of ADR-008
// decision 7 is under 4 GB for a single role with one DPG.
func Floor(p Pair) ResourceFloor {
	services := len(ServicesFor(p))
	dpg := dpgMemoryMiB[p.Dpg]
	if p.Role == commonv1.Role_ROLE_ADMIN {
		// The admin role talks to no DPG, so it needs only Postgres.
		dpg = 256
	}
	return ResourceFloor{
		Role:         p.Role,
		Services:     services,
		VcaMemoryMiB: services * perServiceMemoryMiB,
		DpgMemoryMiB: dpg,
		Cpus:         1 + float64(services)/4,
	}
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
