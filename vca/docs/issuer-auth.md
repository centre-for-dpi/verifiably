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
