# admin: super admin API and portal

`admin` holds every super admin operation of a deployment. The CLI and
the portal are two clients of one proto service. This page describes the
design. The service [README](../services/admin/README.md) tells you how
to run it.

This page covers ADR-009 decisions 1, 3, 4, 5, and 6, and ADR-010
decisions 1 to 7.

## One service, two clients

Every admin operation is an RPC on `vca.admin.v1.AdminService`: tenants,
trust entries, auth providers, API keys, service health, the audit log,
and the admin binding. The portal calls the same RPCs as the `vca admin`
CLI. No admin action exists in the portal that you cannot script. No command
exists that the portal cannot do.

The portal adds no business logic. A page reads the browser session.
The page then calls one RPC with that session as a bearer token. The
vca UI kit renders the answer.

## Help text from one source

Each RPC in `proto/vca/admin/v1/admin.proto` carries a `description`
option in Simplified Technical English. The package
`services/internal/helptext` reads that option from the generated proto
descriptors at run time:

```go
helptext.Describe("vca.admin.v1.AdminService", "CreateTenant")
// "Creates one tenant."
helptext.Service("AdminService") // every RPC in proto file order
helptext.All()                   // every RPC of every linked service
```

`ListCommands` joins the command tree with that text. The CLI help, the
man pages, the `/admin/help` page, and the OpenAPI document read the
same sentence. You write the sentence once.

## Admin login

The portal uses OpenID Connect only. It has no password field, and the
service stores no password.

`GET /admin/login` and `GET /auth/` draw the sign in chooser of the
admin role (ADR-035, board Signin-Admin). The page comes from the
renderer that every auth service shares, `services/internal/signin`,
so the four roles look the same. It shows one button per enabled
provider with its realm, the first admin callout, and the bootstrap
card. A provider that offers registration gets a register action.
`GET /auth/providers.json` lists the providers with `id`,
`display_name`, `realm`, and `register`, and nothing else. The landing
reads it.

1. The browser opens `GET /auth/login?provider=<id>&return_to=/admin/`.
2. The service reads the provider metadata from the discovery document.
   It makes a PKCE verifier, a `state`, and a `nonce`.
3. The provider sends the browser back to the exact redirect URI.
4. The service checks the ID token: signature, `iss`, `aud`, `exp`, and
   `nonce`.
5. The service checks the `iss` and `sub` pair against the admin
   bindings. A bound subject gets a session JWT.

The flow follows RFC 9700: no implicit flow, one exact redirect URI,
PKCE S256 on every request, and no token in a query string.

A session JWT carries `iss` (the public URL), `sub` (`iss|sub` of the
provider), `aud` (`vca-admin`), `exp`, `iat`, `jti`, `sid`, `roles`, and
`provider`. The header carries `alg: ES256` and the `kid` of the service
key. Another service checks a super admin call with the key set at
`/.well-known/jwks.json`. No service keeps a session table.

## The first super admin

The service counts the admin bindings at each start. When no admin
exists, it stores a one time bootstrap token and logs it once:

- `VCA_ADMIN_BOOTSTRAP_TOKEN` sets the value.
- An empty variable makes the service generate a value.

The operator opens the login page, pastes the token, and signs in, or
registers when no account exists yet: the bootstrap card has both
actions, and the register action opens
`GET /auth/register?provider=<id>&bootstrap_token=<token>`
(ADR-035 decision 6). The service consumes the token and binds the
`iss` and `sub` claims of that login to the super admin role. The token
works once. A restart with the same value does not make a spent token
work again.

The CLI does the same step with the `OnboardAdmin` RPC. The RPC takes the
bootstrap token, an ID token, and a provider id. It needs no session,
because no admin exists yet.

The first admin needs a provider before any admin exists.
The service seeds one from the `VCA_OIDC_*` variables that the setup CLI
writes, under the id `default` with the role `admin`
(ADR-035 decision 6).
The seed of a stack is the admin realm of its Keycloak.
The first admin registers there and signs in with the bootstrap token.
A stored record survives a restart, so an edit through the RPCs stays.

## Provider onboarding

`CreateAuthProvider` onboards one OpenID Connect provider:

1. The service reads the metadata document of the issuer.
2. With `dynamic_registration`, the service registers a client through
   OAuth 2.0 Dynamic Client Registration (RFC 7591). The registration
   asks for the authorization code grant only.
3. Without a registration endpoint, the caller sends a client id and a
   secret reference.
4. The service stores the provider record. The record holds a reference
   to the client secret, never the value.

The portal form at `/admin/providers/new` runs the same RPC. The page
needs a super admin session, so only an existing admin adds a provider.

### The provider form

The form of board Admin-Providers starts with a kind preset: Keycloak,
WSO2 Identity Server, eSignet, or a generic OpenID Connect provider.
The preset fills the fields the operator leaves empty: the roles claim
path (`realm_access.roles` for Keycloak, `groups` for WSO2), the scopes,
and the token endpoint method (`private_key_jwt` for eSignet). For a
Keycloak discovery URL the preset reads the realm and its console URL.
The form then takes the issuer URL, the client, the secret references,
the token endpoint method, and the register action. It ends with the
roles and the stacks. The stack boxes list the stacks with a present
pair. No box means every stack.

"Test discovery" reads the metadata document of the typed issuer
through `core/fetchguard`. The guard refuses a private or loopback
address and plain http. `VCA_ADMIN_ALLOW_PRIVATE_NETWORK` and
`VCA_ADMIN_ALLOW_PLAIN_HTTP` turn the rules off for development. The
answer names the issuer, the endpoints, and the dynamic registration
support. It also names the register action of the sign in page and the
token endpoint methods. With htmx the answer lands under the form.
Without a script the same button posts the form and the page returns
with the result.

The edit form at `/admin/providers/{id}` shows every field but the
secret references. An empty reference field keeps the stored one, so the
form never echoes a reference or a value. The table offers a switch that
turns one provider on or off and a remove action.

A client secret from a registration goes to the vault. With a state
directory the vault writes one file with mode 0600. Without a state
directory the vault keeps the value in memory, and the value ends at a
restart.

The record carries more than the endpoints (ADR-035 decision 2): the
kind, the realm label, the registration mode, and the console URL.
It also carries the stacks, the token endpoint method, the key
reference of `private_key_jwt`, and the default flag.
`docs/issuer-auth.md` lists every field and its values.
An update keeps the fields the caller sends back.

### Fan out to the auth services

A stored provider reaches the auth service of every live pair its
roles and stacks name (ADR-035 decision 5). `VCA_PEERS` lists the
candidate pairs. The service probes them and pushes to the live ones.
An empty stack list means every stack. The admin role has no auth
service, so it is never a target.

The push carries the admin session token of the caller. Each auth
service checks that token against the admin key set at
`/.well-known/jwks.json` of this service, through
`VCA_<ROLE>_AUTH_ADMIN_JWKS_URL`. An API key opens the RPC here, but the
auth services accept no key. A push from a key fails at every target.

A push is idempotent. A target that holds a record with the same
discovery URL and client id gets an update, not a copy. Every target
gets one audit record, `admin.PushAuthProvider`, with the pair name,
the record id, and the outcome. A partial failure shows there. The
RPC answer carries the stored record and one `PushResult` per target.
Each result names the pair, the outcome, and the reason of a failure.
The portal shows one line per target after a save.

## CLI login

The CLI logs in without a browser redirect of its own:

| Path | Method | Purpose |
|---|---|---|
| `/device_authorization` | POST | Starts the device authorization grant at the provider. |
| `/token` | POST | Exchanges a device code for an admin session token. |
| `/cli/login` | POST | Starts a loopback login and returns the authorization URL. |
| `/cli/token` | POST | Exchanges the one time loopback code for a session token. |

The admin service adds the client id and the client secret, so the CLI
holds no client credential. A provider that advertises
`device_authorization_endpoint` supports the device grant. A provider
without that endpoint gets the loopback helper of RFC 8252: the browser
returns to `http://127.0.0.1:<port>/callback?code=<code>`, and the CLI
exchanges the code for the session. No token travels in a URL.

## Cross site request forgery

Every browser POST carries a synchronizer token. The token holds one
session id, so a token of one session does not work in another. The
session cookie carries `HttpOnly`, `SameSite=Lax`, and `Secure` outside
localhost. A POST without a valid token gets `403`.

`GET /auth/session` returns the claims of the current session and a fresh
token for the next POST.

## Audit log

Every admin action writes one record to an append only log: the actor,
the action, the request id, the target, and the result. The record id
starts with the time in milliseconds, so the store returns the records in
time order. The log has an append function and a query function. No
function changes or removes a record. The code is the shared package
`services/internal/auditlog`. The auth services keep their sign in
events in the same kind of store (ADR-039).

The actor is `iss|sub` for a session, or `apikey:<id>` for a machine
key. `QueryAuditLog` filters by actor, action, and time. The
`/admin/audit` page shows the same records.

## Service health

`GetServiceHealth` probes the `/readyz` endpoint of every service that
`VCA_ADMIN_SERVICES` names. The probes run at the same time. A service
reports its version in the `X-Vca-Version` header, or in a
`version=<value>` token in the body. The dashboard at `/admin/` shows the
result.

## Other services keep working

`issuer-auth` and `wallet-auth` mount the provider and API key RPCs of
this contract on their own port. Those services stay unchanged. The admin
service becomes the source of truth for a deployment wide view. Each
service keeps its own records for its own logins.

## Pages

Every page sits in the portal shell of the UI kit. The shell holds the
role chip, the stack switcher, the user menu, and the side navigation.
The switcher lists the admin pairs of the deployment. The user menu holds
the sign out form. The pages of the side navigation come from
`internal/rolenav`. The navigation ends with one link per identity
console that a provider record of kind `keycloak` names. A deployment
with another provider shows no such link (ADR-035 decision 2).

The overview shows six cards. The trust card counts the active issuers.
The other cards cover the trust registry, the providers with their realms, the tenants, and the API keys.
The sixth card counts the audit events of the day. The first run checklist sits
below the cards (ADR-035 decision 6). It stays until the operator
completes four steps. The bootstrap token bound the first admin. No
enabled admin provider offers a register action on the sign in page. The
trust list has one entry. Every role has one enabled provider.

| Path | Purpose |
|---|---|
| `/admin/` | The overview: the stat cards, the first run checklist, and the service health. |
| `/admin/login` | The sign in chooser with the bootstrap card. `/auth/` draws the same page. |
| `/admin/tenants` | The tenant list with the create form. The form offers the stacks with multi tenancy. |
| `/admin/tenants/{id}` | One tenant with its tenant on each stack, its DIDs, and the bind form. |
| `/admin/trust` | The trust list. Pending entries come first, with approve and reject. The add form takes a DID or an X.509 subject. |
| `/admin/trust/registries` | The local registry with its published lists. Each external registry with its last sync and last error. The add form. |
| `/admin/providers` | The login provider table: realm or issuer, roles, stacks, state, default flag, and the row actions. |
| `/admin/providers/new` | The provider form with the kind presets and the discovery test. |
| `/admin/providers/{id}` | The edit form of one provider. |
| `/admin/keys` | The VCA API keys with tenant and expiry, and the stack credentials. A new secret appears once. |
| `/admin/audit` | The audit log with filters. |
| `/admin/notifications` | The VCA delivery channels with their state, and the stack webhooks where a stack has them. |
| `/admin/help` | Every command and every RPC with its help text. |

### Tenants on stacks

A VCA tenant maps onto at most one tenant per stack (ADR-037). The
admin service reaches the adapter of each stack through the peer
topology. It calls `vca.backend.v1.TenantBackendService` there. The
pages offer a stack only when its live adapter lists
`FEATURE_MULTI_TENANCY`. A deployment without such a stack shows no
tenancy control at all.

The create form takes the display name, the stacks, and the agent type
of the stack tenants. The service checks every stack before it writes.
When one stack fails, the service removes the tenant from the stacks
that took it, and removes the VCA record. The detail page reads each
stack tenant again, so it shows the DIDs the stack holds now. A stack
that does not answer shows the reason. Add to stack calls `BindTenant`.
Remove from stack calls `UnbindTenant`, and the stack deletes its
tenant. Delete removes the stack tenants first. A stack that does not
run keeps its tenant, so the delete waits until the stack runs again.
The admin service writes one audit record for each create, bind,
unbind, and delete. The CLI has the same actions under
`vca admin tenant`.

### API keys and stack credentials

A VCA API key belongs to one tenant and carries one role (ADR-038). The
form offers the tenants by name and an expiry of 30 days, 90 days, one
year, or no end. The table names the tenant and the expiry, and marks a
key past its expiry.

A stack tenant can hold client credentials of its own. The page shows
them only when a live adapter lists
`FEATURE_TENANT_CLIENT_CREDENTIALS`. The form offers each tenant on
such a stack. The stack makes the credential. The answer to the form
shows the client ID and the secret once. The page never shows the
secret again, and VCA keeps no copy. The admin service writes one audit
record for each create and delete, with the credential id and never
the secret. The CLI has the same actions under
`vca admin stack-credential`.

### Notifications

The notifications page lists the VCA delivery channels: email, SMS, and
a VCA webhook (ADR-040). Each row says "Not built in this release". The
page names what is not built in plain words and gives no date.

A stack can call a webhook on the events of one tenant. The page shows
the stack webhooks only when a live adapter lists `FEATURE_WEBHOOKS`.
The admin service reads each webhook through
`vca.backend.v1.NotificationBackendService` and sets it with
`SetStackWebhook`. A webhook must use https. An empty URL clears it.
Each change writes one audit record. The CLI has the same actions under
`vca admin webhook`.

### Trust review

An entry with the status `pending` waits for review. The trust registry
publishes no pending entry, and a lookup never trusts one. The trust
page lists the pending entries first. Each one has two buttons. Approve
calls `ApproveTrustEntry`, which sets the entry to `active`. Reject calls
`RejectTrustEntry`, which removes the entry. Both refuse an entry that is
not pending. Each button is a POST form with the synchronizer token. The
admin service writes one audit record for each decision, also when it
fails. The CLI has the same two actions: `vca admin trust approve` and
`vca admin trust reject`.

The registries tab shows the local registry with the URLs of its lists
and its key set. Each external registry shows its format, its anchor,
its last sync, and the reason of a failed read. Sync now reads the list
at once. Remove stops the federation. The CLI has the same actions under
`vca admin registry`. The admin service writes one audit record for each
change.

The add form has an identifier type: DID or X.509 subject. The type
decides how the registry reads the value, so a subject never reads as a
DID.

Every page meets the structural rules of WCAG 2.2 AA that the UI kit
guarantees. The tests check each page with `a11ytest.AssertPage`.

## Standards

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html) PKCE
- [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html) Dynamic Client Registration
- [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628.html) Device Authorization Grant
- [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html) OAuth 2.0 for Native Apps
- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) OAuth 2.0 Security Best Current Practice
