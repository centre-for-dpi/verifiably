// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"strings"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
)

// Route is one path of a service behind the reverse proxy of a pair.
// Every service of a pair answers on one host name, so the routes of
// the services of a role must not collide. The catalogue lists the
// routes, and the Caddyfile of a pair renders them.
//
// The table comes from the HTTP mux of each service. The rules:
//
//   - The proxy publishes a Connect service only when a browser or a
//     party outside the host calls it and every RPC of it checks the
//     caller. Every other Connect service stays on the compose network,
//     and the Caddyfile answers 404 to its path (ADR-047).
//   - /static/* is the same embedded asset set in every UI service, so
//     only the home service of a role lists it.
//   - /.well-known/jwks.json, /token, and /auth/* belong to the auth
//     service of the role: issuer-auth, wallet-auth, verifier-auth, or
//     admin.
//   - An API only service whose public URLs start with its *_BASE_URL
//     keeps a prefix, and its base URL carries the prefix:
//     status-bitstring, status-token, and trust-registry. Their routes
//     name the protocol paths under the prefix and strip the prefix.
//   - A service with HTML pages gets root level routes, and the links
//     that carry its public URL hold the bare VCA_PUBLIC_URL.
//
// The routes per role, with the home of the role first:
//
//	issuer    /                                    issuance (redirect to /issuer/)
//	          /issuer/*                            issuance (the issuer overview)
//	          /identity/*  /issue/*                issuance (identity, issue)
//	          /notifications/*  /help/*            issuance (notifications, help)
//	          /static/*                            issuance
//	          /issuance/pdf/*                      issuance (the document of a citizen)
//	          /.well-known/did.json                issuance (a did:web issuer)
//	          /portal/*                            schema-registry (the schemas page)
//	          /.well-known/openid-credential-issuer schema-registry
//	          /.well-known/vct/*  /vct/*           schema-registry
//	          /schemas/*  /api/schemas             schema-registry
//	          /sources/*                           data-source (the bulk issuance pages)
//	          /builder/*                           schema-builder-ui (the schema builder)
//	          /pdf/preview/*                       schema-builder-ui
//	          /auth/*  /token  /.well-known/jwks.json       issuer-auth
//	          /vca.issuerauth.v1.IssuerAuthService/*        issuer-auth
//	          /vca.admin.v1.AdminService/*                  issuer-auth
//	          /issued/*                            issued-credentials (the issued credentials pages)
//	          /issued/chain-head  /issued/jwks.json issued-credentials
//	          /status-bitstring/status/*  (strip)  status-bitstring
//	          /status-bitstring/.well-known/jwks.json  (strip)
//	          /status-token/status/*  (strip)      status-token
//	          /status-token/.well-known/jwks.json  (strip)
//	          /offers/*                            dpg-adapter-inji
//	holder    /                                    wallet-portal (redirect to /wallet/)
//	          /wallet/*                            wallet-portal (the wallet)
//	          /static/*                            wallet-portal
//	          /auth/*  (strip)                     wallet-auth
//	          /.well-known/jwks.json               wallet-auth
//	          /vca.walletauth.v1.WalletAuthService/*  wallet-auth
//	          /vca.admin.v1.AdminService/*         wallet-auth
//	          /offers/*                            dpg-adapter-inji
//	verifier  /                                    verifier-results (redirect to /portal/)
//	          /portal/*                            verifier-results (the results page)
//	          /verify/*                            verifier-results (the citizen check)
//	          /static/*                            verifier-results
//	          /discovery/*                         verifier-discovery (the issuer pages)
//	          /catalog  /catalog/*                 verifier-discovery
//	          /scan/*                              verifier-ingest (the scanner)
//	          /oid4vp/*                            verifier-ingest
//	          /auth/*  /token  /.well-known/jwks.json       verifier-auth
//	          /vca.verifierauth.v1.VerifierAuthService/*    verifier-auth
//	          /vca.admin.v1.AdminService/*                  verifier-auth
//	          /offers/*                            dpg-adapter-inji
//	admin     /                                    admin (redirect to /admin/)
//	          /admin/*                             admin (the admin portal)
//	          /static/*                            admin
//	          /auth/*  /token  /.well-known/jwks.json  admin
//	          /device_authorization  /cli/*        admin
//	          /vca.admin.v1.AdminService/*         admin
//	          /trust-registry/trust-list/*  (strip) trust-registry
//	          /trust-registry/.well-known/*  (strip)
//	          /trust-registry/dedi/*  /trust-registry/trust/*  (strip)
//
// Every role refuses /vca.* with 404, and the holder refuses
// /auth/vca.* too. The data-source, verifier-policy, and
// verifier-combined services and the walt.id and CREDEBL adapters have
// no route at all.
type Route struct {
	// Match is the Caddy path matcher, for example /auth/* or /token.
	Match string
	// Strip removes the first segment of the matcher, for example
	// /status-token, before the request reaches the service. The
	// service sees /status/<id> for /status-token/status/<id>.
	Strip bool
	// Page names the HTML page a browser opens at the route. Empty
	// means an API route. The entry report after a deploy lists the
	// pages.
	Page string
}

// Path returns the path a browser opens for the route: the matcher
// without its wildcard.
func (r Route) Path() string { return strings.TrimSuffix(r.Match, "*") }

// StripPrefix returns the prefix that the proxy removes before the
// request reaches the service: the first segment of the matcher. It is
// empty for a route that does not strip.
func (r Route) StripPrefix() string {
	if !r.Strip {
		return ""
	}
	segment, _, _ := strings.Cut(strings.TrimPrefix(r.Match, "/"), "/")
	return "/" + segment
}

// rpc returns the route of one Connect service. connect-go mounts a
// service handler at / plus the full service name plus /. Only a
// service with a caller check gets one (ADR-047 decision 1).
func rpc(serviceName string) Route { return Route{Match: "/" + serviceName + "/*"} }

// statusRoutes lists the public paths of a status service under its
// prefix: the signed lists and the key set that signs them.
func statusRoutes(prefix string) []Route {
	return []Route{{Match: prefix + "/status/*", Strip: true}, {Match: prefix + "/.well-known/jwks.json", Strip: true}}
}

// connectPrefix is the matcher of every Connect path at the root. The
// full name of every VCA service starts with vca.
const connectPrefix = "/vca.*"

// RefusedRoutes lists the matchers that the Caddyfile of a pair answers
// with 404 (ADR-047 decision 2). The last handle block sends every path
// that no route names to the home service, so the Caddyfile refuses
// every Connect path that no route names. A strip route that takes a
// whole prefix, such as /auth/* of wallet-auth, gets the same refusal
// under that prefix.
func RefusedRoutes(p Pair) []string {
	out := []string{connectPrefix}
	seen := map[string]bool{connectPrefix: true}
	for _, sr := range PairRoutes(p, nil) {
		prefix := sr.Route.StripPrefix()
		if prefix == "" || sr.Route.Match != prefix+"/*" {
			continue
		}
		if match := prefix + connectPrefix; !seen[match] {
			seen[match] = true
			out = append(out, match)
		}
	}
	return out
}

// Home is where the root of a pair sends the browser.
type Home struct {
	// Service is the service that serves the home page. It also takes
	// every path that no route names.
	Service string
	// Path is the path of the home page, for example /portal/.
	Path string
}

// HomeOf returns the home of a role. The page comes from the code of
// the service: the root of schema-registry and of admin redirect to
// their portal prefix, issuance serves the issuer home under /issuer,
// wallet-portal serves its pages under /wallet,
// and verifier-results serves the staff pages under /portal. The
// topology package names the service, so a page and the CLI agree.
func HomeOf(role commonv1.Role) Home {
	service, path := topology.HomeService(role), topology.HomePath(role)
	if service == "" || path == "" {
		return Home{}
	}
	return Home{Service: service, Path: path}
}

// ServiceRoute is one route of one service of a pair, with the host
// port the reverse proxy sends it to.
type ServiceRoute struct {
	// Service is the service name.
	Service string
	// Route is the route.
	Route Route
	// Host is the host port of the service.
	Host int
}

// PairRoutes lists every route of every service of a pair, in service
// name order and then in catalogue order. The values map overrides a
// host port, as HostPorts does.
func PairRoutes(p Pair, values map[string]string) []ServiceRoute {
	var out []ServiceRoute
	for _, a := range HostPorts(p, values) {
		for _, r := range a.Service.Routes {
			out = append(out, ServiceRoute{Service: a.Service.Name, Route: r, Host: a.Host})
		}
	}
	return out
}

// PageLink is one HTML page of a pair that an operator opens.
type PageLink struct {
	// Title names the page.
	Title string
	// Service is the service that serves it.
	Service string
	// URL is the public URL of the page.
	URL string
}

// Pages lists the pages of a pair under its public URL. The home page
// comes first. The list comes from the route table, so the entry report
// cannot drift from the Caddyfile.
func Pages(p Pair, public string) []PageLink {
	public = strings.TrimRight(public, "/")
	home := HomeOf(p.Role)
	var out []PageLink
	for _, sr := range PairRoutes(p, nil) {
		if sr.Route.Page == "" {
			continue
		}
		link := PageLink{Title: sr.Route.Page, Service: sr.Service, URL: public + sr.Route.Path()}
		if sr.Service == home.Service && sr.Route.Path() == home.Path {
			out = append([]PageLink{link}, out...)
			continue
		}
		out = append(out, link)
	}
	return out
}

// RouteTable renders the routes of every role as Markdown. The getting
// started guide includes it under "Where each page lives". The three
// DPG adapters appear as one row set, dpg-adapter-<dpg>, and a route
// that only one adapter serves names that adapter.
func RouteTable() string {
	var b strings.Builder
	for i, role := range Roles() {
		if i > 0 {
			b.WriteString("\n")
		}
		home := HomeOf(role)
		fmt.Fprintf(&b, "The `%s` role. Its home page is `%s` on `%s`.\n\n", ShortName(role.String()), home.Path, home.Service)
		b.WriteString("| Path | Service | Note |\n")
		b.WriteString("|---|---|---|\n")
		fmt.Fprintf(&b, "| `/` | `%s` | Sends the browser to `%s`. |\n", home.Service, home.Path)
		for _, row := range routeRows(role) {
			fmt.Fprintf(&b, "| `%s` | `%s` | %s |\n", row.match, row.service, row.note)
		}
		for _, match := range RefusedRoutes(Pair{Role: role, Dpg: Dpgs()[0]}) {
			fmt.Fprintf(&b, "| `%s` | none | The proxy answers 404. |\n", match)
		}
		fmt.Fprintf(&b, "| Every other path | `%s` | |\n", home.Service)
	}
	return b.String()
}

// routeRow is one row of the route table.
type routeRow struct {
	match, service, note string
}

// routeRows lists the rows of one role. The adapters fold into one
// service name, and a route that not every adapter serves gets a note.
func routeRows(role commonv1.Role) []routeRow {
	var out []routeRow
	adapters := 0
	served := map[string][]string{}
	var adapterOrder []string
	for _, s := range Catalog() {
		if s.Scope != ScopePair || !wantsRole(s.Roles, role) {
			continue
		}
		if s.Dpg == configv1.Dpg_DPG_UNSPECIFIED {
			for _, r := range s.Routes {
				out = append(out, routeRow{match: r.Match, service: s.Name, note: routeNote(r)})
			}
			continue
		}
		adapters++
		for _, r := range s.Routes {
			if _, ok := served[r.Match]; !ok {
				adapterOrder = append(adapterOrder, r.Match)
			}
			served[r.Match] = append(served[r.Match], ShortName(s.Dpg.String()))
		}
	}
	for _, match := range adapterOrder {
		note := ""
		if len(served[match]) < adapters {
			note = "Only the `" + strings.Join(served[match], "`, `") + "` adapter."
		}
		out = append(out, routeRow{match: match, service: "dpg-adapter-<dpg>", note: note})
	}
	return out
}

// routeNote is the third column of the route table.
func routeNote(r Route) string {
	switch {
	case r.Page != "":
		return "A page: " + r.Page + "."
	case r.Strip:
		return "The service sees the path without `" + r.StripPrefix() + "`."
	default:
		return ""
	}
}
