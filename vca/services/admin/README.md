# `admin`

`admin` serves the super admin API and the super admin portal of a deployment.

## What it does

- It serves `vca.admin.v1.AdminService`: tenants, trust entries, auth providers, API keys, service health, the audit log, and the admin binding (ADR-009 decision 1).
- It serves the admin portal. Every page calls one RPC, so the portal and the `vca admin` CLI cannot diverge.
- It logs admins in with OpenID Connect only. It stores no password (ADR-010 decision 1).
- It binds the first super admin with a one time bootstrap token that it prints at the first start (ADR-010 decision 4).
- It writes one audit record for each admin action with the actor, the action, and the request id (ADR-009 decision 6).
- It follows [OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html), [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html), [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html), [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html), [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html), [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628.html), and [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html).

It keeps no password and no client secret value. A provider record holds a reference to a secret, never the value.

### Endpoints

| Path | Method | Purpose |
|---|---|---|
| `/vca.admin.v1.AdminService/*` | POST | The Connect RPCs of the contract. |
| `/admin/` | GET | The portal dashboard. Other pages live under the same prefix. |
| `/auth/login` | GET | Starts an admin login. The query takes `provider`, `return_to`, and `bootstrap_token`. |
| `/auth/callback` | GET | Ends a login. The service sets the session cookie. |
| `/auth/logout` | POST | Ends the session. The request needs the `X-CSRF-Token` header. |
| `/auth/session` | GET | Returns the claims of the current session and a fresh CSRF token. |
| `/device_authorization` | POST | Starts the device authorization grant for the CLI. |
| `/token` | POST | Exchanges a device code for an admin session token. |
| `/cli/login` | POST | Starts a loopback login for the CLI and returns the authorization URL. |
| `/cli/token` | POST | Exchanges the one time loopback code for a session token. |
| `/.well-known/jwks.json` | GET | Publishes the session key. Other services check a super admin call with it. |
| `/healthz`, `/readyz` | GET | Health probes. |
| `/static/*` | GET | The UI kit assets. |

### Settings

| Variable | Default | Purpose |
|---|---|---|
| `VCA_ADMIN_LISTEN` | `:8093` | The listen address. |
| `VCA_ADMIN_PUBLIC_URL` | required | The URL the browser uses. |
| `VCA_ADMIN_REDIRECT_URI` | `<public url>/auth/callback` | The exact redirect URI at the provider. |
| `VCA_ADMIN_STATE_DIR` | empty | The directory of the records. Empty keeps them in memory. |
| `VCA_ADMIN_SIGNING_KEY` | empty | The PEM file of the ES256 session key. |
| `VCA_ADMIN_SESSION_KEY` | empty | The HMAC key of the CSRF tokens. |
| `VCA_ADMIN_SESSION_TTL` | `15m` | The lifetime of a session JWT. |
| `VCA_ADMIN_COOKIE_NAME` | `vca_admin_session` | The session cookie name. |
| `VCA_ADMIN_INSECURE_COOKIE` | `false` | Drops the `Secure` attribute, for localhost only. |
| `VCA_ADMIN_BOOTSTRAP_TOKEN` | empty | The one time token of the first admin. Empty makes one at start. |
| `VCA_ADMIN_TRUST_URL` | empty | The base URL of the trust registry service. |
| `VCA_ADMIN_TIMEOUT` | `10s` | The timeout of a call to a provider or a service. |
| `VCA_ADMIN_SERVICES` | empty | The services to probe as `name=url` pairs, separated by commas. |
| `VCA_ADMIN_PORTAL_PREFIX` | `/admin` | The URL prefix of the portal pages. |
| `VCA_ADMIN_LOGOUT_REDIRECT` | `/admin/` | The page the browser opens after a logout. |
| `VCA_ADMIN_LANDING_URL` | none | The public URL of the landing. The sign in page links back to its role picker. |
| `VCA_PEERS` | empty | The candidate pairs of the deployment. A new provider goes to the auth service of every live pair it names. |
| `VCA_OIDC_DISCOVERY_URL` | empty | The discovery URL of a first provider, registered as `default` with the role `admin`. |
| `VCA_OIDC_CLIENT_ID` | empty | The client id of the first provider. |
| `VCA_OIDC_CLIENT_SECRET` | empty | The client secret of the first provider. The record keeps the variable name, never the value. |
| `VCA_OIDC_ROLES_CLAIM_PATH` | `realm_access.roles` | The dot path of the claim that carries roles. |
| `VCA_OIDC_PUBLIC_URL` | empty | The base URL a browser uses to reach the first provider. The console link derives from it. |
| `VCA_OIDC_INTERNAL_AUTHORITY` | empty | The `scheme://host` the service uses to reach the first provider on the container network. |

## How to run

Planned (ADR-007, ADR-008):

```sh
vca setup --role admin
vca deploy --role admin
```

Now:

```sh
cd services/admin
VCA_ADMIN_PUBLIC_URL=http://localhost:8093 \
VCA_ADMIN_INSECURE_COOKIE=true \
VCA_ADMIN_SERVICES=trust-registry=http://localhost:8082 \
VCA_ADMIN_TRUST_URL=http://localhost:8082 \
go run .
```

The start log prints the bootstrap token once:

```
WARN no super admin exists: use this one time bootstrap token to bind the first admin bootstrap_token=... login_url=http://localhost:8093/admin/login
```

As a container:

```sh
docker build -f services/admin/Dockerfile -t vca-admin .
docker run --rm -p 8093:8093 \
  -e VCA_ADMIN_PUBLIC_URL=http://localhost:8093 \
  -e VCA_ADMIN_INSECURE_COOKIE=true \
  -v vca-admin-data:/data -e VCA_ADMIN_STATE_DIR=/data \
  vca-admin
```

## How to check it works

1. Probe the service:

```sh
curl -fsS http://localhost:8093/readyz
```

2. Read the help of every command and every RPC:

```sh
curl -fsS -X POST http://localhost:8093/vca.admin.v1.AdminService/ListCommands \
  -H 'content-type: application/json' -d '{}' | head
```

3. Add a login provider with the CLI, or with the RPC:

```sh
curl -fsS -X POST http://localhost:8093/vca.admin.v1.AdminService/CreateAuthProvider \
  -H 'content-type: application/json' -H "authorization: Bearer $VCA_ADMIN_SESSION" \
  -d '{"provider":{"displayName":"Keycloak","discoveryUrl":"https://keycloak.example/realms/vca/.well-known/openid-configuration","enabled":true},"dynamicRegistration":true}'
```

4. Open `http://localhost:8093/admin/login`, paste the bootstrap token, and sign in. Your identity now holds the super admin role.

5. Open `http://localhost:8093/admin/help`. The page shows the same sentences as the CLI help.

6. Run the tests:

```sh
go test ./services/admin/... ./services/internal/helptext/...
```

## Reference

- Design page: [docs/admin.md](../../docs/admin.md)
- Contract: [proto/vca/admin/v1/admin.proto](../../proto/vca/admin/v1/admin.proto)
- ADR-009 decisions 1, 3, 4, 5, 6 and ADR-010 decisions 1 to 7
- Shared login library: [services/internal/oidcflow](../internal/oidcflow)
- Help text reader: [services/internal/helptext](../internal/helptext)
