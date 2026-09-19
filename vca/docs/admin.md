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

The operator opens the login page, pastes the token, and signs in. The
service consumes the token and binds the `iss` and `sub` claims of that
login to the super admin role. The token works once. A restart with the
same value does not make a spent token work again.

The CLI does the same step with the `OnboardAdmin` RPC. The RPC takes the
bootstrap token, an ID token, and a provider id. It needs no session,
because no admin exists yet.

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

The portal wizard at `/admin/providers/new` runs the same RPC. The page
needs a super admin session, so only an existing admin adds a provider.

A client secret from a registration goes to the vault. With a state
directory the vault writes one file with mode 0600. Without a state
directory the vault keeps the value in memory, and the value ends at a
restart.

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
function changes or removes a record.

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

| Path | Purpose |
|---|---|
| `/admin/` | The dashboard with the service health. |
| `/admin/login` | The OpenID Connect login page with the bootstrap field. |
| `/admin/tenants` | The tenant list with the create form. |
| `/admin/trust` | The trust entry list with the add form. |
| `/admin/providers` | The login provider list. |
| `/admin/providers/new` | The onboarding wizard. |
| `/admin/keys` | The API key list. A new secret appears once. |
| `/admin/audit` | The audit log with filters. |
| `/admin/help` | Every command and every RPC with its help text. |

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
