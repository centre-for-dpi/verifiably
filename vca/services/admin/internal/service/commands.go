// SPDX-License-Identifier: Apache-2.0

package service

import (
	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/helptext"
)

// ServiceName is the full name of the admin service.
const ServiceName = "vca.admin.v1.AdminService"

// command describes one CLI command of the vca admin tree (ADR-009
// decision 2). The summary and the long text come from the description
// option of the RPC, so the CLI, the man pages, and the portal help page
// show the same sentence (ADR-009 decisions 3 and 4).
type command struct {
	path  string
	rpc   string
	long  string
	flags []flag
}

// flag is one command flag.
type flag struct {
	name      string
	text      string
	mandatory bool
	value     string
}

// commands is the command tree. The order is the order of the help page.
var commands = []command{
	{path: "admin tenant create", rpc: "CreateTenant", flags: []flag{
		{name: "name", text: "The display name of the tenant.", mandatory: true},
	}},
	{path: "admin tenant get", rpc: "GetTenant", flags: []flag{
		{name: "id", text: "The tenant id.", mandatory: true},
	}},
	{path: "admin tenant list", rpc: "ListTenants", flags: []flag{
		{name: "page-size", text: "The number of tenants in one page.", value: "50"},
		{name: "page-token", text: "The token of the next page."},
	}},
	{path: "admin tenant update", rpc: "UpdateTenant", flags: []flag{
		{name: "id", text: "The tenant id.", mandatory: true},
		{name: "name", text: "The new display name."},
		{name: "state", text: "The new state, active or suspended."},
	}},
	{path: "admin tenant delete", rpc: "DeleteTenant", flags: []flag{
		{name: "id", text: "The tenant id.", mandatory: true},
	}},
	{path: "admin trust add", rpc: "UpsertTrustEntry", flags: []flag{
		{name: "did", text: "The DID of the entity."},
		{name: "x509-subject", text: "The x509 subject of the entity."},
		{name: "name", text: "The display name of the entity.", mandatory: true},
		{name: "role", text: "The role: issuer, holder, or verifier.", mandatory: true},
		{name: "status", text: "The trust status: active, suspended, revoked, or pending.", value: "active"},
		{name: "credential-type", text: "One credential type. Repeat the flag for more types."},
		{name: "service-endpoint", text: "The base URL of the entity deployment."},
	}},
	{path: "admin trust get", rpc: "GetTrustEntry", flags: []flag{
		{name: "did", text: "The DID of the entity."},
		{name: "x509-subject", text: "The x509 subject of the entity."},
	}},
	{path: "admin trust list", rpc: "ListTrustEntries", flags: []flag{
		{name: "role", text: "The role filter."},
		{name: "status", text: "The status filter, for example pending."},
		{name: "page-size", text: "The number of entries in one page.", value: "50"},
		{name: "page-token", text: "The token of the next page."},
	}},
	{path: "admin trust remove", rpc: "DeleteTrustEntry", flags: []flag{
		{name: "did", text: "The DID of the entity."},
		{name: "x509-subject", text: "The x509 subject of the entity."},
	}},
	{path: "admin trust approve", rpc: "ApproveTrustEntry",
		long: "Sets a pending trust entry to active. The registry then publishes it. The audit log records the decision.",
		flags: []flag{
			{name: "did", text: "The DID of the entity."},
			{name: "x509-subject", text: "The x509 subject of the entity."},
		}},
	{path: "admin trust reject", rpc: "RejectTrustEntry",
		long: "Removes a pending trust entry. The audit log records the decision.",
		flags: []flag{
			{name: "did", text: "The DID of the entity."},
			{name: "x509-subject", text: "The x509 subject of the entity."},
		}},
	{path: "admin registry add", rpc: "AddTrustRegistry",
		long: "Federates with one external trust registry. The trust registry reads its list at once and checks it against the anchor.",
		flags: []flag{
			{name: "name", text: "The display name of the registry.", mandatory: true},
			{name: "method", text: "The list format: etsi-lote-json, etsi-tsl-xml, or dedi.", mandatory: true},
			{name: "url", text: "The URL of the list or manifest.", mandatory: true},
			{name: "jwks-url", text: "The URL of the JWK Set that signs the list."},
			{name: "x509-certificate", text: "A PEM file with the X.509 anchor certificate."},
			{name: "refresh", text: "How often the service reads the list.", value: "24h"},
		}},
	{path: "admin registry list", rpc: "ListTrustRegistries"},
	{path: "admin registry remove", rpc: "RemoveTrustRegistry", flags: []flag{
		{name: "id", text: "The registry id.", mandatory: true},
	}},
	{path: "admin registry sync", rpc: "SyncTrustRegistry", flags: []flag{
		{name: "id", text: "The registry id.", mandatory: true},
	}},
	{path: "admin onboard", rpc: "CreateAuthProvider",
		long: "Reads the provider metadata and registers a client. The command uses dynamic client registration when the provider supports it.",
		flags: []flag{
			{name: "issuer", text: "The issuer URL of the provider.", mandatory: true},
			{name: "name", text: "The display name on the login page."},
			{name: "client-id", text: "The client id, when the provider registers no client."},
			{name: "client-secret-env", text: "The environment variable that holds the client secret."},
			{name: "dynamic", text: "Register the client with dynamic client registration.", value: "true"},
			{name: "initial-access-token", text: "The token the registration endpoint asks for."},
			{name: "roles-claim-path", text: "The dot path of the claim that carries roles.", value: "realm_access.roles"},
		}},
	{path: "admin onboard-provider", rpc: "OnboardProvider",
		long: "Registers one provider from its issuer URL. The command runs the same onboarding path as admin onboard.",
		flags: []flag{
			{name: "issuer-url", text: "The issuer URL of the provider.", mandatory: true},
			{name: "client-id", text: "The client id, when the provider registers no client."},
			{name: "client-secret-env", text: "The environment variable that holds the client secret."},
			{name: "dynamic", text: "Register the client with dynamic client registration.", value: "true"},
		}},
	{path: "admin provider get", rpc: "GetAuthProvider", flags: []flag{
		{name: "id", text: "The provider id.", mandatory: true},
	}},
	{path: "admin provider list", rpc: "ListAuthProviders", flags: []flag{
		{name: "page-size", text: "The number of providers in one page.", value: "50"},
		{name: "page-token", text: "The token of the next page."},
	}},
	{path: "admin provider update", rpc: "UpdateAuthProvider", flags: []flag{
		{name: "id", text: "The provider id.", mandatory: true},
		{name: "name", text: "The new display name."},
		{name: "enabled", text: "Accept logins with this provider.", value: "true"},
	}},
	{path: "admin provider remove", rpc: "DeleteAuthProvider", flags: []flag{
		{name: "id", text: "The provider id.", mandatory: true},
	}},
	{path: "admin apikey create", rpc: "CreateApiKey",
		long: "Shows the secret value once. The service stores only a hash of the value.",
		flags: []flag{
			{name: "name", text: "The display name of the key.", mandatory: true},
			{name: "tenant", text: "The tenant that owns the key.", mandatory: true},
			{name: "role", text: "One role the key grants. Repeat the flag for more roles.", mandatory: true},
			{name: "expires", text: "The end of validity as an RFC 3339 time."},
		}},
	{path: "admin apikey list", rpc: "ListApiKeys", flags: []flag{
		{name: "tenant", text: "The tenant filter."},
		{name: "page-size", text: "The number of keys in one page.", value: "50"},
	}},
	{path: "admin apikey revoke", rpc: "RevokeApiKey", flags: []flag{
		{name: "id", text: "The key id.", mandatory: true},
	}},
	{path: "admin health", rpc: "GetServiceHealth"},
	{path: "admin audit", rpc: "QueryAuditLog", flags: []flag{
		{name: "actor", text: "The actor filter."},
		{name: "action", text: "The action filter."},
		{name: "from", text: "The earliest time as an RFC 3339 time."},
		{name: "to", text: "The latest time as an RFC 3339 time."},
		{name: "page-size", text: "The number of records in one page.", value: "50"},
	}},
	{path: "admin bind", rpc: "OnboardAdmin",
		long: "Binds the first super admin. The command needs the bootstrap token that the service printed at its first start.",
		flags: []flag{
			{name: "bootstrap-token", text: "The one time bootstrap token.", mandatory: true},
			{name: "provider", text: "The provider id that issued the id token."},
		}},
	{path: "admin help", rpc: "ListCommands",
		long: "Prints every command with the help text of its RPC. The portal help page shows the same list."},
}

// Commands returns the command tree with the help text of each RPC. The
// CLI, the man pages, and the portal help page render this list.
func Commands() []*adminv1.ListCommandsResponse_Command {
	out := make([]*adminv1.ListCommandsResponse_Command, 0, len(commands))
	for _, c := range commands {
		summary := helptext.Describe(ServiceName, c.rpc)
		long := c.long
		if long == "" {
			long = summary
		}
		cmd := &adminv1.ListCommandsResponse_Command{
			Path:        c.path,
			Summary:     summary,
			Description: long,
			Rpc:         "AdminService." + c.rpc,
		}
		for _, f := range c.flags {
			cmd.Flags = append(cmd.Flags, &adminv1.ListCommandsResponse_Flag{
				Name:         f.name,
				Description:  f.text,
				Mandatory:    f.mandatory,
				DefaultValue: f.value,
			})
		}
		out = append(out, cmd)
	}
	return out
}
