// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"sort"
	"strconv"
	"strings"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
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
	// UI reports whether the service draws HTML pages. Such a service
	// reads the theme file at start, so compose and the Helm charts
	// deliver it (ADR-032 decision 1).
	UI bool
	// Links name the variables that point at another service.
	// The CLI fills them from the port plan of the deployment.
	Links []Link
	// Fixed lists the variables whose value never changes.
	Fixed []FixedValue
	// Routes lists the paths of the service behind the reverse proxy of
	// the pair. The Route type documents the table and its rules. A
	// service that only other services call has none (ADR-047).
	Routes []Route
	// Scope says whether the service runs once per pair or once per
	// deployment. The zero value is ScopePair.
	Scope Scope
}

// Scope says how many copies of a service a deployment runs.
type Scope int

const (
	// ScopePair runs the service once in every role and DPG pair. Every
	// service of the catalogue is one, unless it says otherwise.
	ScopePair Scope = iota
	// ScopeDeployment runs the service once for the whole deployment.
	// Every pair profile starts it, it takes no pair port, and its .env
	// file lives in its own directory under deploy (ADR-033 decision 2).
	ScopeDeployment
)

// The landing service (ADR-033 decision 2). It listens on
// LandingListenPort inside its container, publishes LandingHostPort on
// the host, and reads deploy/LandingDir/.env.
const (
	LandingService    = "landing"
	LandingDir        = "landing"
	LandingHostPort   = 17900
	LandingListenPort = 8080
	// LandingPublicURLEnv is the address a browser opens for the landing.
	LandingPublicURLEnv = "VCA_LANDING_PUBLIC_URL"
	// LandingHostPortEnv overrides the host port in the landing .env.
	LandingHostPortEnv = "VCA_HOST_PORT_LANDING"
	// LandingHost is the host name of the landing under a base domain.
	LandingHost = "vca"
)

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
	// LinkPublicURL is the public base URL of the deployment, plus a
	// path.
	LinkPublicURL
	// LinkAdapterURL is the base URL of the DPG adapter of the pair,
	// plus a path.
	LinkAdapterURL
	// LinkCopy is the value of another variable of the same .env file.
	// Target names that variable. A service that reads a shared secret
	// or the DPG URL under its own prefix gets it this way.
	LinkCopy
	// LinkPeers is every candidate pair of the deployment with its
	// public URL and the internal URL of each of its services, in the
	// format of the topology package. Every service that draws pages
	// reads it (ADR-034 decision 1).
	LinkPeers
	// LinkLandingURL is the public URL of the landing, plus a path. The
	// sign in chooser of an auth service links back to its role picker
	// (ADR-035).
	LinkLandingURL
)

// Link is one variable that names another service.
type Link struct {
	// Env is the variable the service reads.
	Env string
	// Target is the service the variable points at. LinkURL reads a
	// service name. LinkCopy reads a variable name.
	Target string
	// Path is the path the CLI adds to the base URL.
	Path string
	// Kind says how to build the value.
	Kind LinkKind
	// Roles limits the link to some roles. Empty means every role that
	// runs the service.
	Roles []commonv1.Role
}

// appliesTo reports whether a link is written for one role.
func (l Link) appliesTo(r commonv1.Role) bool {
	if len(l.Roles) == 0 {
		return true
	}
	for _, role := range l.Roles {
		if role == r {
			return true
		}
	}
	return false
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
	// signingKey is the shared signing key under the name a service
	// reads. sessionKey and bootstrapToken are the same for the other
	// two generated secrets.
	signingKey := func(env string) Link { return Link{Env: env, Target: "VCA_SECRETS_SIGNING_KEY", Kind: LinkCopy} }
	sessionKey := func(env string) Link { return Link{Env: env, Target: "VCA_SECRETS_SESSION_KEY", Kind: LinkCopy} }
	dpgURL := func(env string, roles ...commonv1.Role) Link {
		return Link{Env: env, Target: "VCA_DPG_URL", Kind: LinkCopy, Roles: roles}
	}
	state := func(env string) []FixedValue { return []FixedValue{{Env: env, Value: "/data"}} }
	// peers is the candidate pair list of every service that draws
	// pages or logs a user in (ADR-034 decision 1).
	peers := Link{Env: topology.Env, Kind: LinkPeers}
	// landing is the way back from a sign in chooser (ADR-035).
	landing := func(env string) Link { return Link{Env: env, Kind: LinkLandingURL} }
	// jwks and auth are the routes of the auth service of a role. The
	// auth services of the issuer, holder, and verifier draw the sign in
	// chooser at /auth/ (ADR-035); the admin draws its own at /admin/login.
	jwks := Route{Match: "/.well-known/jwks.json"}
	// staffJWKS and staffLogin guard the staff pages of a service with a
	// session of the auth service of its role (ADR-036 decisions 2 and
	// 3). The key set travels on the internal network; the browser
	// follows the login URL, so it is public.
	staffJWKS := func(env string, auth string) Link {
		return Link{Env: env, Target: auth, Path: "/.well-known/jwks.json", Kind: LinkURL}
	}
	staffLogin := func(env string) Link { return Link{Env: env, Kind: LinkPublicURL, Path: "/auth/"} }
	// adminJWKS is the key set of the admin pair of the same stack. An
	// auth service accepts an admin session it signed on its provider
	// RPCs, so the admin portal can push a provider (ADR-035 decision 5).
	adminJWKS := func(env string) Link {
		return Link{Env: env, Target: "admin", Path: "/.well-known/jwks.json", Kind: LinkURL}
	}
	// audit is the audit store of a service that records changes and
	// serves them to the admin only (ADR-039 decision 1): the directory
	// of the store and the admin key set that opens it.
	audit := func(prefix string) ([]Link, FixedValue) {
		return []Link{adminJWKS(prefix + "ADMIN_JWKS_URL")}, FixedValue{Env: prefix + "AUDIT_DIR", Value: "/data/audit"}
	}
	issuanceAudit, issuanceAuditDir := audit("VCA_ISSUANCE_")
	issuedAudit, issuedAuditDir := audit("VCA_ISSUED_")
	trustAudit, trustAuditDir := audit("VCA_TRUST_")
	resultsAudit, resultsAuditDir := audit("VCA_VERIFIER_RESULTS_")
	auth := Route{Match: "/auth/*"}
	signIn := Route{Match: "/auth/*", Page: "Sign in"}
	assets := Route{Match: "/static/*"}
	out := []Service{
		// The landing runs once per deployment and serves every role. Its
		// site takes every path, so one route names the page.
		{Name: LandingService, ListenEnv: "VCA_LANDING_LISTEN", ExposedPort: LandingListenPort, Roles: Roles(),
			Scope: ScopeDeployment, UI: true,
			Links:  []Link{{Env: LandingPublicURLEnv, Kind: LinkPublicURL}, peers},
			Routes: []Route{{Match: "/*", Page: "Landing"}}},
		{Name: "admin", ListenEnv: "VCA_ADMIN_LISTEN", ExposedPort: 8093, Roles: admin, Stateful: true, UI: true,
			Links: []Link{
				{Env: "VCA_ADMIN_PUBLIC_URL", Kind: LinkPublicURL},
				{Env: "VCA_ADMIN_TRUST_URL", Target: "trust-registry", Kind: LinkURL},
				{Env: "VCA_ADMIN_SERVICES", Kind: LinkServiceMap},
				signingKey("VCA_ADMIN_SIGNING_KEY"),
				sessionKey("VCA_ADMIN_SESSION_KEY"),
				{Env: "VCA_ADMIN_BOOTSTRAP_TOKEN", Target: "VCA_SECRETS_BOOTSTRAP_TOKEN", Kind: LinkCopy},
				peers, landing("VCA_ADMIN_LANDING_URL"),
			},
			Fixed: state("VCA_ADMIN_STATE_DIR"),
			Routes: []Route{
				rpc("vca.admin.v1.AdminService"), jwks, auth,
				{Match: "/device_authorization"}, {Match: "/token"}, {Match: "/cli/*"},
				{Match: "/admin/*", Page: "Admin portal"}, assets,
			}},
		{Name: "data-source", ListenEnv: "VCA_DATASOURCE_LISTEN", ExposedPort: 8083, Roles: issuer, Stateful: true,
			// The issuance service is the only caller, on the compose network,
			// so the proxy publishes nothing of it (ADR-047).
			Fixed: []FixedValue{{Env: "VCA_DATASOURCE_STORE_FILE", Value: "/data/sources.json"}}},
		{Name: "dpg-adapter-credebl", ListenEnv: "VCA_CREDEBL_LISTEN", ExposedPort: 8080, Roles: everyRole, Dpg: configv1.Dpg_DPG_CREDEBL,
			Links: []Link{dpgURL("VCA_CREDEBL_API_URL")}},
		{Name: "dpg-adapter-inji", ListenEnv: "VCA_INJI_LISTEN", ExposedPort: 8080, Roles: everyRole, Dpg: configv1.Dpg_DPG_INJI,
			Links: []Link{
				dpgURL("VCA_INJI_CERTIFY_URL", commonv1.Role_ROLE_ISSUER, commonv1.Role_ROLE_HOLDER),
				dpgURL("VCA_INJI_VERIFY_URL", commonv1.Role_ROLE_VERIFIER),
				{Env: "VCA_INJI_PUBLIC_URL", Kind: LinkPublicURL},
			},
			// The credential offer of the authorization code channel lives
			// under the public URL of the adapter. The Connect services of
			// every adapter stay on the compose network (ADR-047).
			Routes: []Route{{Match: "/offers/*"}}},
		// The walt.id adapter keeps the issuer identity in its data volume
		// (ADR-046 decision 4).
		{Name: "dpg-adapter-waltid", ListenEnv: "VCA_WALTID_LISTEN", ExposedPort: 8080, Roles: everyRole, Dpg: configv1.Dpg_DPG_WALTID,
			Stateful: true, Fixed: []FixedValue{{Env: "VCA_WALTID_IDENTITY_FILE", Value: "/data/issuer-identity.json"}},
			Links: []Link{
				dpgURL("VCA_WALTID_ISSUER_URL", commonv1.Role_ROLE_ISSUER),
				dpgURL("VCA_WALTID_WALLET_URL", commonv1.Role_ROLE_HOLDER),
				dpgURL("VCA_WALTID_VERIFIER_URL", commonv1.Role_ROLE_VERIFIER),
			}},
		// The issuance service is the issuer home (ADR-044 decision 1): it
		// serves the overview, the identity, the issue, the notifications,
		// and the help pages behind the staff guard, and the shared assets.
		{Name: "issuance", ListenEnv: "VCA_ISSUANCE_LISTEN", ExposedPort: 8080, Roles: issuer, Stateful: true, UI: true,
			Links: append([]Link{
				{Env: "VCA_ISSUANCE_PUBLIC_URL", Kind: LinkPublicURL},
				{Env: "VCA_ISSUANCE_ADAPTER_URL", Kind: LinkAdapterURL},
				{Env: "VCA_ISSUANCE_SCHEMA_URL", Target: "schema-registry", Kind: LinkURL},
				{Env: "VCA_ISSUANCE_STATUS_URL", Target: "status-bitstring", Kind: LinkURL},
				{Env: "VCA_ISSUANCE_ISSUED_URL", Target: "issued-credentials", Kind: LinkURL},
				{Env: "VCA_ISSUANCE_DATA_SOURCE_URL", Target: "data-source", Kind: LinkURL},
				staffJWKS("VCA_ISSUANCE_AUTH_JWKS_URL", "issuer-auth"),
				staffLogin("VCA_ISSUANCE_LOGIN_URL"),
				peers,
			}, issuanceAudit...),
			Fixed: []FixedValue{issuanceAuditDir},
			// The rendered document of a citizen lives under the public URL.
			// The pages call the IssuanceService in process, so the proxy
			// does not publish it (ADR-047).
			Routes: []Route{
				{Match: "/issuance/pdf/*"},
				{Match: "/issuer/*", Page: "Issuer portal"}, {Match: "/identity/*", Page: "Issuer identity"},
				{Match: "/issue/*", Page: "Issue"}, {Match: "/notifications/*", Page: "Issuer notifications"},
				{Match: "/help/*", Page: "Issuer help"}, assets,
				// A did:web issuer of the host resolves here (ADR-046).
				{Match: "/.well-known/did.json"},
			}},
		{Name: "issued-credentials", ListenEnv: "VCA_ISSUED_LISTEN", ExposedPort: 8084, Roles: issuer, Stateful: true,
			Links: append([]Link{{Env: "VCA_ISSUED_STATUS_URL", Target: "status-bitstring", Kind: LinkURL}}, issuedAudit...),
			Fixed: []FixedValue{{Env: "VCA_ISSUED_STORE_FILE", Value: "/data/issued.json"}, issuedAuditDir},
			// An auditor reads the signed chain head and its key. The
			// IssuedService stays on the compose network (ADR-047).
			Routes: []Route{{Match: "/issued/chain-head"}, {Match: "/issued/jwks.json"}}},
		// The auth services draw the sign in chooser (ADR-035), so they
		// read the theme file like every UI service.
		{Name: "issuer-auth", ListenEnv: "VCA_ISSUER_AUTH_LISTEN", ExposedPort: 8081, Roles: issuer, Stateful: true, UI: true,
			Links: []Link{peers, landing("VCA_ISSUER_AUTH_LANDING_URL"), adminJWKS("VCA_ISSUER_AUTH_ADMIN_JWKS_URL")},
			Fixed: state("VCA_ISSUER_AUTH_STATE_DIR"),
			// The service mounts the login endpoints at / and at /auth. The
			// pair routes only /auth, so the redirect URI of the realm holds.
			Routes: []Route{
				rpc("vca.issuerauth.v1.IssuerAuthService"), rpc("vca.admin.v1.AdminService"),
				jwks, {Match: "/token"}, signIn,
			}},
		{Name: "schema-builder-ui", ListenEnv: "VCA_SCHEMABUILDER_LISTEN", ExposedPort: 8081, Roles: issuer, UI: true,
			Links: []Link{
				{Env: "VCA_SCHEMABUILDER_REGISTRY_URL", Target: "schema-registry", Kind: LinkURL},
				{Env: "VCA_SCHEMABUILDER_CATALOG_URL", Kind: LinkAdapterURL},
				{Env: "VCA_SCHEMABUILDER_PORTAL_URL", Kind: LinkPublicURL, Path: "/portal/"},
				staffJWKS("VCA_SCHEMABUILDER_AUTH_JWKS_URL", "issuer-auth"),
				staffLogin("VCA_SCHEMABUILDER_LOGIN_URL"),
				peers,
			},
			// The root of the service redirects to /builder/, but the home
			// of the issuer takes the root of the pair.
			Routes: []Route{{Match: "/builder/*", Page: "Schema builder"}, {Match: "/pdf/preview/*"}}},
		{Name: "schema-registry", ListenEnv: "VCA_SCHEMA_LISTEN", ExposedPort: 8080, Roles: issuer, Stateful: true, UI: true,
			Links: []Link{
				{Env: "VCA_SCHEMA_BASE_URL", Kind: LinkPublicURL},
				{Env: "VCA_SCHEMA_BACKEND_URL", Kind: LinkAdapterURL},
				{Env: "VCA_SCHEMA_BUILDER_URL", Kind: LinkPublicURL, Path: "/builder/"},
				// The list page counts the issued credentials of each schema.
				{Env: "VCA_SCHEMA_ISSUED_URL", Target: "issued-credentials", Kind: LinkURL},
				staffJWKS("VCA_SCHEMA_AUTH_JWKS_URL", "issuer-auth"),
				staffLogin("VCA_SCHEMA_LOGIN_URL"),
				peers,
			},
			Fixed: []FixedValue{{Env: "VCA_SCHEMA_STORE_FILE", Value: "/data/schemas.json"}},
			// The OID4VCI metadata, the vct documents, and the schema files
			// live at the root of the public URL, so the base URL is bare.
			Routes: []Route{
				{Match: "/.well-known/openid-credential-issuer"}, {Match: "/.well-known/vct/*"},
				{Match: "/vct/*"}, {Match: "/schemas/*"}, {Match: "/api/schemas"},
				{Match: "/portal/*", Page: "Schemas"},
			}},
		{Name: "status-bitstring", ListenEnv: "VCA_STATUS_BITSTRING_LISTEN", ExposedPort: 8084, Roles: issuer, Stateful: true,
			Links: []Link{
				{Env: "VCA_STATUS_BITSTRING_BASE_URL", Kind: LinkPublicURL, Path: "/status-bitstring"},
				signingKey("VCA_STATUS_BITSTRING_SIGNING_KEY_FILE"),
			},
			Fixed: state("VCA_STATUS_BITSTRING_STATE_DIR"),
			// Both status services serve /status/, /.well-known/jwks.json,
			// and the same Connect service, so each keeps its own prefix.
			// The proxy publishes the lists and the key set, never the
			// Connect service (ADR-047).
			Routes: statusRoutes("/status-bitstring")},
		{Name: "status-token", ListenEnv: "VCA_STATUS_TOKEN_LISTEN", ExposedPort: 8085, Roles: issuer, Stateful: true,
			Links: []Link{
				{Env: "VCA_STATUS_TOKEN_BASE_URL", Kind: LinkPublicURL, Path: "/status-token"},
				signingKey("VCA_STATUS_TOKEN_SIGNING_KEY_FILE"),
			},
			Fixed:  state("VCA_STATUS_TOKEN_STATE_DIR"),
			Routes: statusRoutes("/status-token")},
		{Name: "trust-registry", ListenEnv: "VCA_TRUST_LISTEN", ExposedPort: 8080, Roles: admin, Stateful: true,
			Links: append([]Link{
				{Env: "VCA_TRUST_BASE_URL", Kind: LinkPublicURL, Path: "/trust-registry"},
				signingKey("VCA_TRUST_SIGNING_KEY_FILE"),
			}, trustAudit...),
			Fixed: []FixedValue{{Env: "VCA_TRUST_STORE_FILE", Value: "/data/trust.json"}, trustAuditDir},
			// The registry serves all of /.well-known/, which the admin
			// service needs for its JWKS, so the registry keeps a prefix.
			// The proxy publishes the signed lists and the key set, never
			// the Connect service (ADR-047).
			Routes: []Route{
				{Match: "/trust-registry/trust-list/*", Strip: true}, {Match: "/trust-registry/.well-known/*", Strip: true},
				{Match: "/trust-registry/dedi/*", Strip: true}, {Match: "/trust-registry/trust/*", Strip: true},
			}},
		// The verifier staff sign in service (ADR-036 decision 1). It shares
		// the routes of issuer-auth and draws the same chooser.
		{Name: "verifier-auth", ListenEnv: "VCA_VERIFIER_AUTH_LISTEN", ExposedPort: 8081, Roles: verifier, Stateful: true, UI: true,
			Links: []Link{peers, landing("VCA_VERIFIER_AUTH_LANDING_URL"), adminJWKS("VCA_VERIFIER_AUTH_ADMIN_JWKS_URL")},
			Fixed: state("VCA_VERIFIER_AUTH_STATE_DIR"),
			Routes: []Route{
				rpc("vca.verifierauth.v1.VerifierAuthService"), rpc("vca.admin.v1.AdminService"),
				jwks, {Match: "/token"}, signIn,
			}},
		{Name: "verifier-combined", ListenEnv: "VCA_VERIFIER_COMBINED_LISTEN", ExposedPort: 8088, Roles: verifier, Stateful: true,
			Links: []Link{
				{Env: "VCA_VERIFIER_COMBINED_POLICY_URL", Target: "verifier-policy", Kind: LinkURL},
				{Env: "VCA_VERIFIER_COMBINED_RESULTS_URL", Target: "verifier-results", Kind: LinkURL},
				{Env: "VCA_VERIFIER_COMBINED_DISCOVERY_URL", Target: "verifier-discovery", Kind: LinkURL},
			},
			// No caller outside the compose network exists (ADR-047).
			Fixed: state("VCA_VERIFIER_COMBINED_STATE_DIR")},
		{Name: "verifier-discovery", ListenEnv: "VCA_DISCOVERY_LISTEN", ExposedPort: 8090, Roles: verifier, Stateful: true, UI: true,
			Links: []Link{
				{Env: "VCA_DISCOVERY_BASE_URL", Kind: LinkPublicURL},
				{Env: "VCA_DISCOVERY_TRUST_URL", Target: "trust-registry", Kind: LinkURL},
				staffJWKS("VCA_DISCOVERY_AUTH_JWKS_URL", "verifier-auth"),
				staffLogin("VCA_DISCOVERY_LOGIN_URL"),
				peers,
			},
			// The staff pages default to /portal, which verifier-results
			// holds, so the pair moves them to /discovery. The pages link
			// with absolute paths, so a prefix that the proxy removes would
			// break them.
			Fixed: append(state("VCA_DISCOVERY_STATE_DIR"), FixedValue{Env: "VCA_DISCOVERY_PORTAL_PREFIX", Value: "/discovery"}),
			// A wallet reads the catalogue over plain HTTP. The pages call
			// the DiscoveryService in process (ADR-047).
			Routes: []Route{{Match: "/catalog"}, {Match: "/catalog/*"}, {Match: "/discovery/*", Page: "Issuer discovery"}}},
		{Name: "verifier-ingest", ListenEnv: "VCA_INGEST_LISTEN", ExposedPort: 8091, Roles: verifier, Stateful: true, UI: true,
			Links: []Link{
				{Env: "VCA_INGEST_BASE_URL", Kind: LinkPublicURL},
				{Env: "VCA_INGEST_DISCOVERY_URL", Target: "verifier-discovery", Kind: LinkURL},
				signingKey("VCA_INGEST_SIGNING_KEY_FILE"),
				staffJWKS("VCA_INGEST_AUTH_JWKS_URL", "verifier-auth"),
				staffLogin("VCA_INGEST_LOGIN_URL"),
				peers,
			},
			Fixed: state("VCA_INGEST_STATE_DIR"),
			// The wallet reaches the OID4VP endpoints under the base URL,
			// and the scanner page links with absolute paths, so the
			// service sits at the root.
			Routes: []Route{{Match: "/oid4vp/*"}, {Match: "/scan/*", Page: "Scanner"}}},
		{Name: "verifier-policy", ListenEnv: "VCA_VERIFIER_POLICY_LISTEN", ExposedPort: 8086, Roles: verifier, Stateful: true,
			// verifier-results and verifier-combined call it on the compose
			// network (ADR-047).
			Links: []Link{{Env: "VCA_VERIFIER_POLICY_TRUST_URL", Target: "trust-registry", Kind: LinkURL}},
			Fixed: state("VCA_VERIFIER_POLICY_STATE_DIR")},
		{Name: "verifier-results", ListenEnv: "VCA_VERIFIER_RESULTS_LISTEN", ExposedPort: 8087, Roles: verifier, Stateful: true, UI: true,
			Links: append([]Link{
				{Env: "VCA_VERIFIER_RESULTS_POLICY_URL", Target: "verifier-policy", Kind: LinkURL},
				staffJWKS("VCA_VERIFIER_RESULTS_AUTH_JWKS_URL", "verifier-auth"),
				staffLogin("VCA_VERIFIER_RESULTS_LOGIN_URL"),
				peers,
			}, resultsAudit...),
			Fixed: append(state("VCA_VERIFIER_RESULTS_STATE_DIR"), resultsAuditDir),
			Routes: []Route{
				{Match: "/portal/*", Page: "Verification results"}, {Match: "/verify/*", Page: "Citizen check"}, assets,
			}},
		{Name: "wallet-auth", ListenEnv: "VCA_WALLET_AUTH_LISTEN", ExposedPort: 8083, Roles: holder, Stateful: true, UI: true,
			Links: []Link{
				{Env: "VCA_WALLET_AUTH_HOLDER_BACKEND_URL", Kind: LinkAdapterURL},
				peers, landing("VCA_WALLET_AUTH_LANDING_URL"), adminJWKS("VCA_WALLET_AUTH_ADMIN_JWKS_URL"),
			},
			Fixed: state("VCA_WALLET_AUTH_STATE_DIR"),
			// The service mounts the login endpoints at / and at
			// /wallet/auth. The proxy removes /auth, so the redirect URI of
			// the realm of the role has the same shape for every role.
			Routes: []Route{
				rpc("vca.walletauth.v1.WalletAuthService"), rpc("vca.admin.v1.AdminService"),
				jwks, {Match: "/auth/*", Strip: true, Page: "Sign in"},
			}},
		{Name: "wallet-portal", ListenEnv: "VCA_WALLET_PORTAL_LISTEN", ExposedPort: 8092, Roles: holder, Stateful: true, UI: true,
			Links: []Link{
				{Env: "VCA_WALLET_PORTAL_AUTH_JWKS_URL", Target: "wallet-auth", Path: "/.well-known/jwks.json", Kind: LinkURL},
				// The browser follows the login URL, so it is public. It opens
				// the sign in chooser of wallet-auth (ADR-035).
				{Env: "VCA_WALLET_PORTAL_LOGIN_URL", Kind: LinkPublicURL, Path: "/auth/?return_to=/wallet/"},
				{Env: "VCA_WALLET_PORTAL_DISCOVERY_URL", Target: "verifier-discovery", Kind: LinkURL},
				{Env: "VCA_WALLET_PORTAL_TRUST_URL", Target: "trust-registry", Kind: LinkURL},
				{Env: "VCA_WALLET_PORTAL_DPG", Kind: LinkDpgName},
				{Env: "VCA_WALLET_PORTAL_DPG_ADAPTERS", Kind: LinkAdapterMap},
				peers,
			},
			Fixed: state("VCA_WALLET_PORTAL_STATE_DIR"),
			// The pages call the WalletPortalService in process and the
			// browser reaches /wallet/blobs, so the proxy does not publish
			// the Connect service (ADR-047).
			Routes: []Route{{Match: "/wallet/*", Page: "Wallet"}, assets}},
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// UIServices lists the services that draw pages, in name order.
func UIServices() []Service {
	var out []Service
	for _, s := range Catalog() {
		if s.UI {
			out = append(out, s)
		}
	}
	return out
}

// DeploymentServices lists the services that run once per deployment,
// in name order.
func DeploymentServices() []Service {
	var out []Service
	for _, s := range Catalog() {
		if s.Scope == ScopeDeployment {
			out = append(out, s)
		}
	}
	return out
}

// ServicesFor lists the services of one role and DPG pair, in name order.
// An adapter of another DPG and a deployment scoped service are left out.
func ServicesFor(p Pair) []Service {
	var out []Service
	for _, s := range Catalog() {
		if s.Scope != ScopePair || !wantsRole(s.Roles, p.Role) {
			continue
		}
		if s.Dpg != configv1.Dpg_DPG_UNSPECIFIED && s.Dpg != p.Dpg {
			continue
		}
		out = append(out, s)
	}
	return out
}

// portalService names the service that takes the VCA_PORTS_PORTAL
// listen port of a role. The issuer keeps issuance there, so an
// existing .env file keeps its ports. HomeOf names the service that
// answers at the root of the public URL.
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

// authService names the login service of a role. The admin logs staff
// in from its portal, so it runs none. The topology package holds the
// table, so a page and the CLI agree.
func authService(role commonv1.Role) string { return topology.AuthService(role) }

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

// deploymentServices lists every pair service of one DPG across every
// role, once each, in service name order. The admin health page reads
// the list, so a deployment scoped service, which no pair owns, stays out.
func deploymentServices(d configv1.Dpg) []Service {
	seen := map[string]bool{}
	var out []Service
	for _, s := range Catalog() {
		if s.Scope != ScopePair || (s.Dpg != configv1.Dpg_DPG_UNSPECIFIED && s.Dpg != d) {
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

// PeerOverrides holds the .env values of every other pair directory of
// the deploy root, keyed by pair name. The peer list honours the port
// overrides and the public URL of each of them.
type PeerOverrides map[string]map[string]string

// LinkValues returns every cross service variable of one pair, keyed by
// variable name. The values point at the container names of the compose
// file, so a role reaches the services of another role of the same DPG.
// A link whose target no role runs is left out.
func LinkValues(p Pair, values map[string]string) map[string]string {
	return LinkValuesWith(p, values, nil)
}

// LinkValuesWith is LinkValues with the .env values of the other pair
// directories, so the peer list honours their overrides.
func LinkValuesWith(p Pair, values map[string]string, peers PeerOverrides) map[string]string {
	out := map[string]string{}
	for _, s := range ServicesFor(p) {
		for _, f := range s.Fixed {
			out[f.Env] = f.Value
		}
		for _, link := range s.Links {
			if !link.appliesTo(p.Role) {
				continue
			}
			if value, ok := linkValue(p, s, link, values, peers); ok {
				out[link.Env] = value
			}
		}
	}
	return out
}

// Peers lists every candidate pair of the deployment for the topology
// package (ADR-034 decision 1). The pair itself keeps the public URL of
// its values. Under a base domain every other pair gets its host name
// there. Otherwise a pair directory that names a public URL keeps it,
// and the rest get the localhost address of their home service. The
// internal URLs follow the port plan of each pair, with the overrides
// of its own .env file.
func Peers(p Pair, values map[string]string, overrides PeerOverrides) []topology.Peer {
	return candidatePeers(values[DomainEnv], p.Name(), values, overrides)
}

// candidatePeers builds the peer list. own names the pair whose values
// are the values map; an empty own, as for the landing, reads every
// pair from the overrides.
func candidatePeers(domain, own string, values map[string]string, overrides PeerOverrides) []topology.Peer {
	out := make([]topology.Peer, 0, len(AllPairs()))
	for _, candidate := range AllPairs() {
		ports := overrides[candidate.Name()]
		public := ""
		switch {
		case candidate.Name() == own:
			public = strings.TrimRight(values["VCA_PUBLIC_URL"], "/")
			ports = values
		case domain != "":
			public = PairPublicURL(candidate, domain)
		case strings.TrimRight(ports["VCA_PUBLIC_URL"], "/") != "":
			public = strings.TrimRight(ports["VCA_PUBLIC_URL"], "/")
		}
		if public == "" {
			public = LocalPublicURL(candidate)
		}
		services := map[string]string{}
		for _, a := range AssignPorts(candidate, ports) {
			services[a.Service.Name] = "http://" + composeServiceName(candidate, a.Service) + ":" + strconv.Itoa(a.Listen)
		}
		out = append(out, topology.Peer{
			Pair: candidate.Name(), Role: candidate.Role, Dpg: candidate.Dpg, PublicURL: public, Services: services,
		})
	}
	return out
}

// LandingPublicURL returns the address a browser opens for the landing:
// https://vca.<domain> under a base domain, else the localhost address
// of its host port (ADR-033 decision 2).
func LandingPublicURL(domain string) string {
	if domain != "" {
		return "https://" + LandingHost + "." + domain
	}
	return "http://localhost:" + strconv.Itoa(LandingHostPort)
}

// LandingValues returns the variables of deploy/landing/.env: the listen
// address, the public URL, every candidate pair with the overrides of the
// pair directories, and the image version. An empty version means
// latest. The links of the landing entry of the catalogue drive the
// values, so the .env and the service agree.
func LandingValues(domain string, overrides PeerOverrides, version string) map[string]string {
	if version == "" {
		version = "latest"
	}
	out := map[string]string{VersionEnv: version}
	for _, s := range DeploymentServices() {
		if s.Name != LandingService {
			continue
		}
		out[s.ListenEnv] = ":" + strconv.Itoa(s.ExposedPort)
		public := LandingPublicURL(domain)
		for _, link := range s.Links {
			switch link.Kind {
			case LinkPublicURL:
				out[link.Env] = public + link.Path
			case LinkPeers:
				out[link.Env] = topology.Format(candidatePeers(domain, "", nil, overrides))
			}
		}
	}
	return out
}

// linkValue builds the value of one link.
func linkValue(p Pair, s Service, link Link, values map[string]string, peers PeerOverrides) (string, bool) {
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
		if value == "" {
			return "", false
		}
		return value + link.Path, true
	case LinkAdapterURL:
		name := "dpg-adapter-" + ShortName(p.Dpg.String())
		base, ok := serviceURL(p, name)
		if !ok {
			return "", false
		}
		return base + link.Path, true
	case LinkCopy:
		value := values[link.Target]
		return value, value != ""
	case LinkPeers:
		return topology.Format(Peers(p, values, peers)), true
	case LinkLandingURL:
		return LandingPublicURL(values[DomainEnv]) + link.Path, true
	default:
		return "", false
	}
}
