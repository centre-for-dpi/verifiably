# `verifier-auth`

`verifier-auth` logs verifier staff in with OpenID Connect and issues session tokens for the verifier role (ADR-036 decision 1). It shares its code with `issuer-auth`; the audience of a session is `vca-verifier`.

## What it does

- It runs the OpenID Connect authorization code flow with PKCE against a registered provider and returns an ES256 session JWT.
- It works with any provider that publishes a discovery document: Keycloak, WSO2 Identity Server, or a national IdP.
- It owns these documents in the state directory: `providers.json`, `role_mappings.json`, `clients.json`. The documents hold no secret values, only references.
- It follows [OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html), [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html), [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html), [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html), and [RFC 6749 section 4.4](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.4).

It does not store passwords, and it does not keep a session table.

### Endpoints

| Path | Method | Purpose |
|---|---|---|
| `/login?provider=<id>&return_to=<path>` | GET | Starts a login. The browser goes to the provider. |
| `/callback` | GET | Ends a login. The service sets the session cookie and returns the session JWT. |
| `/logout` | POST | Ends the session. The request needs the `X-CSRF-Token` header. |
| `/session` | GET | Returns the claims of the current session and a fresh CSRF token. |
| `/token` | POST | Issues a service JWT to a machine client with `grant_type=client_credentials`. |
| `/.well-known/jwks.json` | GET | Publishes the public key. Other services check sessions with it. |
| `/vca.verifierauth.v1.VerifierAuthService/*` | POST | The Connect RPCs of the contract. |
| `/vca.admin.v1.AdminService/*AuthProvider*` | POST | Registers providers at runtime. Needs the admin token. |
| `/vca.admin.v1.AdminService/*ApiKey*` | POST | Registers machine clients at runtime. Needs the admin token. |
| `/healthz`, `/readyz` | GET | Health probes. |

The same login endpoints exist under `/auth/`. The default redirect URI is the public URL plus `/auth/callback`.

### Roles

The service maps provider claims to `verifier-admin`, `verifier-operator`, and `verifier-viewer` (ADR-036 decision 1, ADR-012 decision 3). The default mapping reads the claim at `realm_access.roles` and expects the same three names. An admin changes the mapping per provider with `SetRoleMapping`. A subject with no matching claim cannot log in.

A machine client gets roles from its API key: the `admin` deployment role gives `verifier-admin`, the `verifier` role gives `verifier-operator`, and every other role gives `verifier-viewer`.

## How to run

Planned (ADR-007, ADR-008):

```sh
vca setup --role verifier --dpg <dpg>
vca deploy --role verifier --dpg <dpg>
```

Now:

```sh
cd services/verifier-auth
VCA_PUBLIC_URL=http://localhost:8081 VCA_VERIFIER_AUTH_INSECURE_COOKIE=true go run .
```

Configuration comes from environment variables. The table lists each one.

| Variable | Meaning | Default |
|---|---|---|
| `VCA_VERIFIER_AUTH_LISTEN` | The address the service listens on. | `:8081` |
| `VCA_PUBLIC_URL` | The public base URL. Redirect URIs and the token `iss` claim use it. Required. | none |
| `VCA_OIDC_REDIRECT_URI` | The exact redirect URI registered at the provider. | public URL plus `/auth/callback` |
| `VCA_OIDC_DISCOVERY_URL` | The discovery URL of a first provider, registered as `default`. | none |
| `VCA_OIDC_CLIENT_ID` | The client id of the first provider. | none |
| `VCA_OIDC_CLIENT_SECRET` | The name of the environment variable that holds the client secret. | none |
| `VCA_OIDC_ROLES_CLAIM_PATH` | The dot path of the claim that carries roles. | `realm_access.roles` |
| `VCA_OIDC_INTERNAL_AUTHORITY` | The `scheme://host` the service uses to reach the provider on the container network. | none |
| `VCA_OIDC_PUBLIC_URL` | The base URL a browser uses to reach the first provider. The console link of the record derives from it. | none |
| `VCA_SECRETS_SIGNING_KEY` | The path of the ES256 private key in PEM. Empty makes a key at start. | none |
| `VCA_SECRETS_SESSION_KEY` | The CSRF key, 16 bytes or more. Empty makes a key at start. | none |
| `VCA_VERIFIER_AUTH_SESSION_TTL` | The lifetime of a session JWT. | `15m` |
| `VCA_VERIFIER_AUTH_MACHINE_TOKEN_TTL` | The lifetime of a client credentials JWT. | `1h` |
| `VCA_VERIFIER_AUTH_TENANT_ID` | The tenant of every session. | `default` |
| `VCA_VERIFIER_AUTH_ADMIN_TOKEN` | The bearer token the admin service uses for the admin RPCs. | none |
| `VCA_VERIFIER_AUTH_ADMIN_JWKS_URL` | The key set of the admin service. An admin session it signed opens the provider RPCs too. | empty: no admin session is accepted |
| `VCA_VERIFIER_AUTH_STATE_DIR` | The directory for the persisted documents. Empty keeps them in memory. | none |
| `VCA_VERIFIER_AUTH_COOKIE_NAME` | The session cookie name. | `vca_verifier_session` |
| `VCA_VERIFIER_AUTH_INSECURE_COOKIE` | Drops the `Secure` cookie flag. Use it on localhost only. | `false` |
| `VCA_VERIFIER_AUTH_LOGOUT_REDIRECT` | The relative path the browser goes to after logout. | none |
| `VCA_VERIFIER_AUTH_LANDING_URL` | The public URL of the landing. The sign in chooser links back to its role picker. | none |
| `VCA_THEME_FILE` | The theme file of the deployment (ADR-032). Empty selects the embedded default. | none |

Register more providers at runtime with the admin RPC. You do not need a JSON file:

```sh
curl -X POST http://localhost:8081/vca.admin.v1.AdminService/CreateAuthProvider \
  -H "Authorization: Bearer $VCA_VERIFIER_AUTH_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"provider":{"displayName":"Keycloak","discoveryUrl":"https://idp.example/realms/verifier/.well-known/openid-configuration","clientId":"vca-verifier","clientSecret":{"store":"STORE_ENV","name":"KEYCLOAK_SECRET"},"enabled":true}}'
```

The provider record holds a reference to the secret, never the value. Set `VCA_OIDC_INTERNAL_AUTHORITY` when the service reaches the provider on a container network name. The browser keeps the public authorization endpoint (ADR-012 decision 6).

The container image is `ghcr.io/centre-for-dpi/vca-verifier-auth`. It listens on
one port and runs as a non-root user with a read-only file system. Mount a
volume at `/data` to keep providers between restarts.

## Sign in chooser

`GET /auth/` draws the sign in page of the verifier role: one button per
enabled provider with its realm, and a register action when the provider
offers one (ADR-035). `GET /auth/providers.json` lists the providers with
`id`, `display_name`, `realm`, and `register`, and nothing else.
`GET /auth/register?provider=<id>&return_to=<path>` starts a registration.
The same paths answer at the root. See [docs/verifier-auth.md](../../docs/verifier-auth.md).

## How to check it works

1. Open `http://localhost:8081/healthz`. The response is `200 OK`.
2. Open `http://localhost:8081/readyz`. The response is `200 OK` with the number of providers.
3. Open `http://localhost:8081/auth/` in a browser, pick the provider, and log in.
4. Look for a JSON body with `session_token` and `csrf_token`, and a `Set-Cookie` header with `HttpOnly; Secure; SameSite=Lax`.
5. Open `http://localhost:8081/.well-known/jwks.json`. Look for one key with `kty: EC` and the `kid` from the token header.

If a step fails, see [errors.md](../../docs/errors.md) for the message and the next step.

## Reference

- API: [`proto/vca/verifierauth/v1/verifierauth.proto`](../../proto/vca/verifierauth/v1/verifierauth.proto)
- Decision records: [ADR-036](../../docs/adr/ADR-036-verifier-staff-sign-in.md), [ADR-012](../../../ADR.md#adr-012-issuer-oidc-auth-flows)
- Error codes: VCA-301, VCA-302, VCA-401
- Standards: [OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html), [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html)
