# issuer-auth: staff login for the issuer role

`issuer-auth` logs issuer staff in with OpenID Connect and issues ES256
session tokens. Other issuer services check a token with the public key
at `/.well-known/jwks.json` and keep no session table. This page describes
the design. The service [README](../services/issuer-auth/README.md) tells
you how to run it.

This implements ADR-012 decisions 1 to 6 and ADR-010 decisions 2 and 7.

## Login flow

1. The browser opens `GET /login?provider=<id>&return_to=<path>`.
2. The service reads the provider metadata from the discovery document. It makes a PKCE verifier, a `state`, and a `nonce`. It sends the browser to the authorization endpoint with `response_type=code`.
3. The provider sends the browser back to the exact redirect URI, `GET /callback?state=...&code=...`.
4. The service takes the pending login by `state` and posts the code and the PKCE verifier to the token endpoint. It checks the ID token: signature against the provider JWKS, `iss`, `aud`, `exp`, and `nonce`.
5. The service maps the claims to issuer roles and signs a session JWT.
6. The browser gets the cookie `HttpOnly; Secure; SameSite=Lax` and a JSON body with the token and a CSRF token, or a redirect to `return_to`.

The same steps run through the RPCs `LoginStart` and `LoginCallback` for
a portal that wants to drive the flow itself.

The service follows RFC 9700: no implicit flow, exact redirect URI match,
PKCE S256 on every request, and no token in a query string. A request
with `access_token` in the query gets `400`.

## Sign in chooser

`GET /auth/` draws the sign in page of the issuer role with the renderer
that every auth service shares, `services/internal/signin` (ADR-035,
board Signin). The left column names the role, the title, and the way
back to the role picker of the landing, from
`VCA_ISSUER_AUTH_LANDING_URL`. The right panel lists one button per
enabled provider with its realm in the monospace stack, the default
provider first. A provider with a register action gets a register
button after a rule; a provider without one gets none. One line says
that VCA is not tied to Keycloak.

`GET /auth/providers.json` lists the providers with `id`,
`display_name`, `realm`, and `register`, and nothing else: no client
id, no discovery URL, no secret. The landing reads it to name the realm
on the intro page. `GET /auth/register?provider=<id>&return_to=<path>`
starts a registration. It uses `prompt=create` when the provider lists
it, else the registration endpoint of a Keycloak realm. A provider that
offers neither gives `404`. The registration ends at the same redirect
URI as a login. The three paths answer at the root too.

The page reads the theme file of the deployment at start, like every
service that draws pages (ADR-032).

## Session tokens

A session JWT carries `iss` (the public URL), `sub` (`iss|sub` of the
provider), `aud` (`vca-issuer`), `exp` (15 minutes by default), `iat`,
`jti`, `sid`, `roles`, `provider`, `name`, and `tenant`. The header
carries `alg: ES256` and the `kid` of the service key. The `kid` is the
RFC 7638 thumbprint of the public key.

A service that checks a session does this:

1. Read `/.well-known/jwks.json` once and cache it.
2. Check the signature with the key that matches `kid`.
3. Check `iss`, `aud`, and `exp`.
4. Read `roles`.

`Introspect` does the same check on the server and also consults the deny
list. Use it when a client cannot check a signature itself.

## Logout

`POST /logout` needs the session cookie or bearer token and a synchronizer
token in `X-CSRF-Token` or the form field `csrf_token` (ADR-010 decision
7). The service adds the `sid` to the deny list until the token expires
and clears the cookie. When the provider advertises
`end_session_endpoint`, the response redirects the browser to the RP
initiated logout URL with `id_token_hint`.

## Roles

The role mapping of a provider has a claim path, a list of rules, and an
optional default role. The claim path is a dot path into the ID token
claims, for example `realm_access.roles`. A rule maps one claim value to
one of `issuer-admin`, `issuer-operator`, or `issuer-viewer`. A subject
gets every role whose rule matches. A subject with no match gets the
default role, or cannot log in when there is none.

`GetRoleMapping` and `SetRoleMapping` need the admin token or a session
with `issuer-admin`.

## Machine clients

A machine client gets a token with the client credentials grant at
`POST /token`. The client authenticates with HTTP Basic or with the form
fields `client_id` and `client_secret`. The response is a service JWT with
`client_id` and `roles`, valid for one hour by default.

An admin registers a client with the `CreateApiKey` RPC. The response
shows the secret once. The service stores a SHA-256 hash of the secret.
`RevokeApiKey` stops the client at once. The static bearer keys of the
legacy `VERIFIABLY_API_KEYS` variable have no replacement in this service.

## Providers

An admin registers providers at runtime with the `CreateAuthProvider`,
`UpdateAuthProvider`, and `DeleteAuthProvider` RPCs of the admin contract.
This service serves them. The record holds the discovery URL and the
client id. It holds a reference to the client secret, not the value. The
service reads the secret value at the token exchange and never stores it.

A first provider can come from the `VCA_OIDC_*` variables that the setup
CLI writes. The service registers it once under the id `default`.
A discovery URL of a Keycloak realm gives a record of kind `keycloak`
with that realm and the default flag.
The console URL of the record is the console of the realm under
`VCA_OIDC_PUBLIC_URL`.
A stored record survives a restart, so an edit through the admin RPCs
stays.

## The provider record

A provider record describes the provider beyond its endpoints
(ADR-035 decision 2):

| Field | Meaning |
|---|---|
| `kind` | `generic`, `keycloak`, `wso2`, or `esignet`. The kind selects a fallback and a label. No code path depends on it. |
| `realm` | The realm or tenant label the login page shows. |
| `registration` | `none`, `prompt_create`, or `keycloak_endpoint`. Empty lets the metadata and the kind decide. |
| `console_url` | The administration console of the provider. |
| `stacks` | The stacks whose pairs use the provider. Empty means every stack. |
| `token_auth_method` | `client_secret_basic`, `client_secret_post`, `private_key_jwt`, or `none`. Empty means Basic with a secret and none without one. |
| `private_key` | A reference to the key that signs the client assertion of `private_key_jwt`. The record never holds the key. |
| `is_default` | True for the provider that the setup CLI seeded. |

The register action of the login page follows the record
(ADR-035 decision 3).
A provider that lists `create` in `prompt_values_supported` gets
`prompt=create` on the authorization request.
A provider of kind `keycloak` without it gets the registration endpoint
of the realm with the same PKCE parameters.
Any other provider shows no register action.

The token exchange authenticates with the method of the record
(ADR-035 decision 4).
`private_key_jwt` sends a client assertion (RFC 7523).
Its `iss` and `sub` are the client id, its `aud` is the token endpoint,
and its `exp` is one minute away.
It carries a fresh `jti`.
The key is ES256 or Ed25519, as every VCA key (ADR-011 decision 5).

## Public and internal URLs

The public URL builds the redirect URI and the token `iss`. The listen
address is internal. A provider on a container network can have a
different host name. Then `VCA_OIDC_INTERNAL_AUTHORITY` moves the token,
userinfo, and JWKS endpoints to that host. The authorization and end
session endpoints stay public, because the browser uses them.

## Storage

The service persists three documents in the state directory:
`providers.json`, `role_mappings.json`, and `clients.json`. Pending logins
and the deny list live in memory and are short lived. A deployment with
many replicas needs a shared store for both. The shared store package of
the services module will replace the local file store.

## Tests

The test suite runs the full flow against a fake OpenID Provider on
`httptest`: discovery, JWKS, authorization, token exchange with PKCE, key
rotation, and RP initiated logout. Every package has 90 percent statement
coverage or more.
