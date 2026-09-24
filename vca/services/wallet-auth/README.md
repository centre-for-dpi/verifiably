# `wallet-auth`

`wallet-auth` logs citizens in with OpenID Connect at a national IdP and issues short lived session tokens for the wallet role.

## What it does

- It runs the OpenID Connect authorization code flow with PKCE and returns an ES256 session JWT that lives 15 minutes.
- It works with any provider that publishes a discovery document, for example eSignet. The holder backend is a DPG adapter: walt.id, Inji, or CREDEBL.
- It owns these documents in the state directory: `providers.json`, `wallets.json`, `grants.json`. A wallet record holds a salted hash of `iss|sub`, a wallet id, and a key thumbprint. The grants document holds AES-GCM ciphertext.
- It follows [OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html), [OIDC RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html), and [OID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html).

It does not store a name, an email address, or any other claim of the citizen. It does not hold a holder private key.

### Endpoints

| Path | Method | Purpose |
|---|---|---|
| `/login?provider=<id>&return_to=<path>` | GET | Starts a login. Rate limited per client address. |
| `/callback` | GET | Ends a login. The service sets the session cookie and returns the session JWT. |
| `/logout` | POST | Ends the session. The request needs the `X-CSRF-Token` header. |
| `/session` | GET | Returns the claims of the current session and a fresh CSRF token. |
| `/.well-known/jwks.json` | GET | Publishes the public key. The wallet portal checks sessions with it. |
| `/vca.walletauth.v1.WalletAuthService/*` | POST | The Connect RPCs of the contract. |
| `/vca.admin.v1.AdminService/*AuthProvider*` | POST | Registers providers at runtime. Needs the admin token. |
| `/healthz`, `/readyz` | GET | Health probes. |

The same login endpoints exist under `/wallet/auth/`. The default redirect URI is the public URL plus `/wallet/auth/callback`.

### Issuance grant

`GetAuthorizationGrant` returns the IdP access token of the session as the OID4VCI authorization grant (ADR-020 decision 3). The first call binds the grant to one credential issuer URL. A call for another issuer fails. The service seals the token with AES-256-GCM under `VCA_WALLET_AUTH_GRANT_KEY` and deletes it at logout.

## How to run

Planned (ADR-007, ADR-008):

```sh
vca setup --role holder --dpg <dpg>
vca deploy --role holder --dpg <dpg>
```

Now:

```sh
cd services/wallet-auth
VCA_PUBLIC_URL=http://localhost:8083 VCA_WALLET_AUTH_INSECURE_COOKIE=true go run .
```

Configuration comes from environment variables. The table lists each one.

| Variable | Meaning | Default |
|---|---|---|
| `VCA_WALLET_AUTH_LISTEN` | The address the service listens on. | `:8083` |
| `VCA_PUBLIC_URL` | The public base URL. Redirect URIs and the token `iss` claim use it. Required. | none |
| `VCA_OIDC_REDIRECT_URI` | The exact redirect URI registered at the provider. | public URL plus `/wallet/auth/callback` |
| `VCA_OIDC_DISCOVERY_URL` | The discovery URL of a first provider, registered as `default`. | none |
| `VCA_OIDC_CLIENT_ID` | The client id of the first provider. | none |
| `VCA_OIDC_CLIENT_SECRET` | The name of the environment variable that holds the client secret. | none |
| `VCA_OIDC_INTERNAL_AUTHORITY` | The `scheme://host` the service uses to reach the provider on the container network. | none |
| `VCA_OIDC_PUBLIC_URL` | The base URL a browser uses to reach the first provider. The console link of the record derives from it. | none |
| `VCA_SECRETS_SIGNING_KEY` | The path of the ES256 private key in PEM. Empty makes a key at start. | none |
| `VCA_SECRETS_SESSION_KEY` | The CSRF key, 16 bytes or more. Empty makes a key at start. | none |
| `VCA_WALLET_AUTH_SESSION_TTL` | The lifetime of a session JWT. | `15m` |
| `VCA_WALLET_AUTH_SALT` | The salt that hashes `iss|sub`, 16 bytes or more, hex or base64. Empty makes a salt at start. | none |
| `VCA_WALLET_AUTH_GRANT_KEY` | The 32 byte AES key that seals IdP tokens, hex or base64. Empty makes a key at start. | none |
| `VCA_WALLET_AUTH_GRANT_TYPE` | The grant type that `GetAuthorizationGrant` returns. | `urn:ietf:params:oauth:grant-type:jwt-bearer` |
| `VCA_WALLET_AUTH_HOLDER_BACKEND_URL` | The Connect base URL of the holder backend adapter. Empty keeps wallet ids local. | none |
| `VCA_REDIS_URL` | Optional. Empty selects the in-memory limiter, which is fine for one replica. Set a Redis URL for more than one replica. This build has no Redis client and refuses to start with one set. | none |
| `VCA_WALLET_AUTH_LOGIN_RATE` | The login starts one client address can make per minute. | `30` |
| `VCA_WALLET_AUTH_ADMIN_TOKEN` | The bearer token the admin service uses for the provider RPCs. | none |
| `VCA_WALLET_AUTH_STATE_DIR` | The directory for the persisted documents. Empty keeps them in memory. | none |
| `VCA_WALLET_AUTH_COOKIE_NAME` | The session cookie name. | `vca_wallet_session` |
| `VCA_WALLET_AUTH_INSECURE_COOKIE` | Drops the `Secure` cookie flag. Use it on localhost only. | `false` |
| `VCA_WALLET_AUTH_LOGOUT_REDIRECT` | The relative path the browser goes to after logout. | none |

Set `VCA_WALLET_AUTH_SALT` and `VCA_WALLET_AUTH_GRANT_KEY` in production. Without them, wallet keys and sealed grants change at each restart.

The container image is `ghcr.io/centre-for-dpi/vca-wallet-auth`. It listens on
one port and runs as a non-root user with a read-only file system. Mount a
volume at `/data` to keep providers and wallets between restarts.

## How to check it works

1. Open `http://localhost:8083/healthz`. The response is `200 OK`.
2. Open `http://localhost:8083/readyz`. The response is `200 OK` with the number of providers and wallets.
3. Open `http://localhost:8083/login?provider=default` in a browser and log in at the provider.
4. Look for a JSON body with `session_token` and `csrf_token`. The `sub` claim is a hash, not the IdP subject.
5. Call `GetAuthorizationGrant` with the token and an issuer URL. Look for the IdP access token in `grant`.

If a step fails, see [errors.md](../../docs/errors.md) for the message and the next step.

## Reference

- API: [`proto/vca/walletauth/v1/walletauth.proto`](../../proto/vca/walletauth/v1/walletauth.proto)
- OpenAPI: `gen/openapi/walletauth.yaml`
- Decision record: [ADR-020](../../../ADR.md#adr-020-wallet-oidc-auth-flows)
- Error codes: VCA-301, VCA-303, VCA-401
- Standards: [OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html), [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html)
