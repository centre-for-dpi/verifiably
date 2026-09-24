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
//   - /static/* is the same embedded asset set in every UI service, so
//     only the home service of a role lists it.
//   - /.well-known/jwks.json, /token, and /auth/* belong to the auth
//     service of the role: issuer-auth, wallet-auth, or admin.
//   - An API only service whose public URLs start with its *_BASE_URL
//     keeps a prefix route with Strip, and its base URL carries the
//     prefix: status-bitstring, status-token, and trust-registry.
//   - A service with HTML pages gets root level routes, and the links
//     that carry its public URL hold the bare VCA_PUBLIC_URL.
//
// The routes per role, with the home of the role first:
//
//	issuer    /                                    schema-registry (redirect to /portal/)
//	          /portal/*                            schema-registry (the schemas page)
//	          /static/*                            schema-registry
//	          /vca.schema.v1.SchemaService/*       schema-registry
//	          /.well-known/openid-credential-issuer schema-registry
//	          /.well-known/vct/*  /vct/*           schema-registry
//	          /schemas/*  /api/schemas             schema-registry
//	          /builder/*                           schema-builder-ui (the schema builder)
//	          /pdf/preview/*                       schema-builder-ui
//	          /vca.schemabuilder.v1.SchemaBuilderService/*  schema-builder-ui
//	          /auth/*  /token  /.well-known/jwks.json       issuer-auth
//	          /vca.issuerauth.v1.IssuerAuthService/*        issuer-auth
//	          /vca.admin.v1.AdminService/*                  issuer-auth
//	          /vca.issuance.v1.IssuanceService/*   issuance
//	          /issuance/pdf/*                      issuance
//	          /vca.issued.v1.IssuedService/*       issued-credentials
//	          /issued/chain-head  /issued/jwks.json issued-credentials
//	          /vca.datasource.v1.DataSourceService/*  data-source
//	          /status-bitstring/*  (strip)         status-bitstring
//	          /status-token/*  (strip)             status-token
//	          /vca.backend.v1.*Service/*           dpg-adapter-<dpg>
//	          /offers/*                            dpg-adapter-inji
//	holder    /                                    wallet-portal (redirect to /wallet/)
//	          /wallet/*                            wallet-portal (the wallet)
//	          /static/*                            wallet-portal
//	          /vca.walletportal.v1.WalletPortalService/*  wallet-portal
//	          /auth/*  (strip)                     wallet-auth
//	          /.well-known/jwks.json               wallet-auth
//	          /vca.walletauth.v1.WalletAuthService/*  wallet-auth
//	          /vca.admin.v1.AdminService/*         wallet-auth
//	          /vca.backend.v1.*Service/*           dpg-adapter-<dpg>
//	          /offers/*                            dpg-adapter-inji
//	verifier  /                                    verifier-results (redirect to /portal/)
//	          /portal/*                            verifier-results (the results page)
//	          /verify/*                            verifier-results (the citizen check)
//	          /static/*                            verifier-results
//	          /vca.results.v1.ResultsService/*     verifier-results
//	          /discovery/*                         verifier-discovery (the issuer pages)
//	          /catalog  /catalog/*                 verifier-discovery
//	          /vca.discovery.v1.DiscoveryService/* verifier-discovery
//	          /scan/*                              verifier-ingest (the scanner)
//	          /oid4vp/*                            verifier-ingest
//	          /vca.ingest.v1.IngestService/*       verifier-ingest
//	          /vca.policy.v1.PolicyService/*       verifier-policy
//	          /vca.combined.v1.CombinedService/*   verifier-combined
//	          /vca.backend.v1.*Service/*           dpg-adapter-<dpg>
//	          /offers/*                            dpg-adapter-inji
//	admin     /                                    admin (redirect to /admin/)
//	          /admin/*                             admin (the admin portal)
//	          /static/*                            admin
//	          /auth/*  /token  /.well-known/jwks.json  admin
//	          /device_authorization  /cli/*        admin
//	          /vca.admin.v1.AdminService/*         admin
//	          /trust-registry/*  (strip)           trust-registry
type Route struct {
	// Match is the Caddy path matcher, for example /auth/* or /token.
	Match string
	// Strip removes the matched prefix before the request reaches the
	// service. A Strip route renders handle_path in place of handle.
	Strip bool
	// Page names the HTML page a browser opens at the route. Empty
	// means an API route. The entry report after a deploy lists the
	// pages.
	Page string
}

// Path returns the path a browser opens for the route: the matcher
// without its wildcard.
func (r Route) Path() string { return strings.TrimSuffix(r.Match, "*") }

// rpc returns the route of one Connect service. connect-go mounts a
// service handler at / plus the full service name plus /.
func rpc(serviceName string) Route { return Route{Match: "/" + serviceName + "/*"} }

// backendRoutes lists the Connect services every DPG adapter serves.
func backendRoutes() []Route {
	return []Route{
		rpc("vca.backend.v1.CapabilityService"),
		rpc("vca.backend.v1.IssuerBackendService"),
		rpc("vca.backend.v1.HolderBackendService"),
		rpc("vca.backend.v1.VerifierBackendService"),
		rpc("vca.backend.v1.CatalogBackendService"),
	}
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
// their portal prefix, wallet-portal serves its pages under /wallet,
// and verifier-results serves the staff pages under /portal. The
// topology package names the service, so a page and the CLI agree.
func HomeOf(role commonv1.Role) Home {
	service := topology.HomeService(role)
	switch role {
	case commonv1.Role_ROLE_ISSUER:
		return Home{Service: service, Path: "/portal/"}
	case commonv1.Role_ROLE_HOLDER:
		return Home{Service: service, Path: "/wallet/"}
	case commonv1.Role_ROLE_VERIFIER:
		return Home{Service: service, Path: "/portal/"}
	case commonv1.Role_ROLE_ADMIN:
		return Home{Service: service, Path: "/admin/"}
	default:
		return Home{}
	}
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
		return "The service sees the path without `" + strings.TrimSuffix(r.Path(), "/") + "`."
	default:
		return ""
	}
}
