// SPDX-License-Identifier: Apache-2.0

// Package topology tells a page which role and DPG pairs a deployment
// can run, which of them run now, and what each can do (ADR-034).
//
// The CLI writes every candidate pair into the variable VCA_PEERS of
// every service that draws pages. Format and Parse read and write that
// value. A Prober checks each candidate and caches the answer.
//
// The package is pure apart from the Prober. It imports no service and
// no vendor name: the pair names come from the role and DPG enums.
package topology

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// Env is the variable that carries the peer list.
const Env = "VCA_PEERS"

// Separators of the value: items, fields of an item, and services.
const (
	itemSep    = ";"
	fieldSep   = "|"
	serviceSep = ","
)

// Peer is one candidate role and DPG pair of a deployment.
type Peer struct {
	// Pair is the pair name, for example issuer-waltid. It is the
	// compose profile and the directory of the pair.
	Pair string
	// Role is the role of the pair.
	Role commonv1.Role
	// Dpg is the DPG of the pair.
	Dpg configv1.Dpg
	// PublicURL is the address a browser opens for the pair.
	PublicURL string
	// Services maps each service name of the pair onto the URL that
	// reaches it on the internal network.
	Services map[string]string
}

// Home returns the internal URL of the service that answers at the
// root of the public URL, or an empty string when the pair has none.
func (p Peer) Home() string { return p.Services[HomeService(p.Role)] }

// Auth returns the internal URL of the login service of the pair, or
// an empty string when the role has none.
func (p Peer) Auth() string {
	name := AuthService(p.Role)
	if name == "" {
		return ""
	}
	return p.Services[name]
}

// Adapter returns the internal URL of the DPG adapter of the pair, or
// an empty string when the pair runs none.
func (p Peer) Adapter() string { return p.Services[AdapterService(p.Dpg)] }

// HomeService names the service that answers at the root of the public
// URL of a role. The CLI routes the root of a pair to it.
func HomeService(role commonv1.Role) string {
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

// HomePath returns the path of the home page of a role under the public
// URL of its pair. The root of the pair redirects there, and a sign in
// returns there.
func HomePath(role commonv1.Role) string {
	switch role {
	case commonv1.Role_ROLE_ISSUER:
		return "/issuer/"
	case commonv1.Role_ROLE_VERIFIER:
		return "/portal/"
	case commonv1.Role_ROLE_HOLDER:
		return "/wallet/"
	case commonv1.Role_ROLE_ADMIN:
		return "/admin/"
	default:
		return ""
	}
}

// SignInURL returns the address a browser opens to sign in on a pair and
// come back to the home page of its role: the chooser at /auth/ of the
// public URL with return_to (ADR-033 decision 6, ADR-035).
func (p Peer) SignInURL() string {
	return strings.TrimRight(p.PublicURL, "/") + "/auth/?return_to=" + url.QueryEscape(HomePath(p.Role))
}

// AuthService names the login service of a role. The admin logs staff
// in from its portal, so it runs none (ADR-036 decision 1).
func AuthService(role commonv1.Role) string {
	switch role {
	case commonv1.Role_ROLE_ISSUER:
		return "issuer-auth"
	case commonv1.Role_ROLE_HOLDER:
		return "wallet-auth"
	case commonv1.Role_ROLE_VERIFIER:
		return "verifier-auth"
	default:
		return ""
	}
}

// AdapterService names the DPG adapter service of a DPG, or an empty
// string for no DPG.
func AdapterService(dpg configv1.Dpg) string {
	if dpg == configv1.Dpg_DPG_UNSPECIFIED {
		return ""
	}
	return "dpg-adapter-" + shortName(dpg.String())
}

// PairName returns the pair name of a role and a DPG, for example
// issuer-waltid.
func PairName(role commonv1.Role, dpg configv1.Dpg) string {
	return shortName(role.String()) + "-" + shortName(dpg.String())
}

// shortName turns an enum name such as ROLE_ISSUER into issuer.
func shortName(name string) string {
	if i := strings.Index(name, "_"); i >= 0 {
		name = name[i+1:]
	}
	return strings.ToLower(name)
}

// ParsePair turns a pair name into its role and DPG.
func ParsePair(name string) (commonv1.Role, configv1.Dpg, error) {
	i := strings.Index(name, "-")
	if i <= 0 || i == len(name)-1 {
		return 0, 0, fmt.Errorf("the pair %q is not <role>-<dpg>", name)
	}
	roleName, dpgName := name[:i], name[i+1:]
	role := commonv1.Role_ROLE_UNSPECIFIED
	for value, number := range commonv1.Role_value {
		if number != 0 && shortName(value) == roleName {
			role = commonv1.Role(number)
		}
	}
	if role == commonv1.Role_ROLE_UNSPECIFIED {
		return 0, 0, fmt.Errorf("the pair %q names no known role", name)
	}
	dpg := configv1.Dpg_DPG_UNSPECIFIED
	for value, number := range configv1.Dpg_value {
		if number != 0 && shortName(value) == dpgName {
			dpg = configv1.Dpg(number)
		}
	}
	if dpg == configv1.Dpg_DPG_UNSPECIFIED {
		return 0, 0, fmt.Errorf("the pair %q names no known DPG", name)
	}
	return role, dpg, nil
}

// Format renders the peers as one line for VCA_PEERS. Each item is
// pair|public|svc=url,svc=url and items are separated by a semicolon.
// The services come out in name order, so the value is stable.
func Format(peers []Peer) string {
	items := make([]string, 0, len(peers))
	for _, p := range peers {
		names := make([]string, 0, len(p.Services))
		for name := range p.Services {
			names = append(names, name)
		}
		sort.Strings(names)
		services := make([]string, 0, len(names))
		for _, name := range names {
			services = append(services, name+"="+p.Services[name])
		}
		items = append(items, p.Pair+fieldSep+p.PublicURL+fieldSep+strings.Join(services, serviceSep))
	}
	return strings.Join(items, itemSep)
}

// Parse reads the value of VCA_PEERS. An empty value gives no peer.
// Every error names the variable and the item.
func Parse(value string) ([]Peer, error) {
	var out []Peer
	seen := map[string]bool{}
	for _, item := range strings.Split(strings.TrimSpace(value), itemSep) {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		p, err := parseItem(item)
		if err != nil {
			return nil, fmt.Errorf("%s: item %q: %w", Env, item, err)
		}
		if seen[p.Pair] {
			return nil, fmt.Errorf("%s: item %q: the pair appears twice", Env, item)
		}
		seen[p.Pair] = true
		out = append(out, p)
	}
	return out, nil
}

// parseItem reads one pair|public|services item.
func parseItem(item string) (Peer, error) {
	fields := strings.Split(item, fieldSep)
	if len(fields) != 3 {
		return Peer{}, errors.New("want three fields pair|public|services")
	}
	role, dpg, err := ParsePair(fields[0])
	if err != nil {
		return Peer{}, err
	}
	if err := checkURL(fields[1]); err != nil {
		return Peer{}, fmt.Errorf("public URL: %w", err)
	}
	p := Peer{Pair: fields[0], Role: role, Dpg: dpg, PublicURL: fields[1], Services: map[string]string{}}
	if fields[2] == "" {
		return p, nil
	}
	for _, entry := range strings.Split(fields[2], serviceSep) {
		name, target, ok := strings.Cut(entry, "=")
		if !ok || name == "" {
			return Peer{}, fmt.Errorf("service %q is not name=url", entry)
		}
		if err := checkURL(target); err != nil {
			return Peer{}, fmt.Errorf("service %s: %w", name, err)
		}
		p.Services[name] = target
	}
	return p, nil
}

// checkURL accepts an absolute http or https URL with a host.
func checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%q is not an http or https URL with a host", raw)
	}
	return nil
}
