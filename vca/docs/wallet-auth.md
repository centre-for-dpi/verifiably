# wallet-auth: citizen login for the wallet role

`wallet-auth` logs citizens in with OpenID Connect at a national IdP and
issues short lived ES256 session tokens. The service holds no personal
data beyond a salted hash of the pairwise subject. This page describes
the design. The service [README](../services/wallet-auth/README.md) tells
you how to run it.

This implements ADR-020 decisions 1, 2, 3, 4, 5, and 6. It shares the
login library and the token format with [issuer-auth](issuer-auth.md).

## Login flow

The flow is the same as for issuer-auth: `GET /login` sends the browser
to the provider with PKCE S256, `state`, and `nonce`. `GET /callback`
exchanges the code, checks the ID token, and sets the session cookie.
The default scope is `openid` alone. The service asks for no profile
claims.

The service then computes the wallet key:

```text
key = base64url(HMAC-SHA256(salt, iss + "|" + sub))
```

The salt is `VCA_WALLET_AUTH_SALT`, one value per deployment. The key
selects the wallet record. On the first login the service asks the holder
backend to create a wallet. It stores the wallet id under the key. The
backend receives the key, never `iss` or `sub`. Without a holder backend
the key is the wallet id.

## Session tokens

A wallet session JWT carries `iss`, `sub` (the wallet key), `aud`
(`vca-wallet`), `exp` (15 minutes by default), `iat`, `jti`, `sid`,
`provider`, `wallet_id`, `holder_did`, and `has_holder_key`. The portal
checks the token with `/.well-known/jwks.json` or with `Introspect`.

The `Session.pairwise_subject` field of the contract carries the wallet
key, not the raw `iss|sub`, so no personal data leaves the service.

## Issuance grant

`GetAuthorizationGrant` returns the IdP access token of the session as
the OID4VCI authorization grant (ADR-020 decision 3). The portal sends
it to the credential issuer when the DPG accepts the IdP as its
authorization server. The response carries the grant type from
`VCA_WALLET_AUTH_GRANT_TYPE` and the token expiry.

The service seals the tokens of each session with AES-256-GCM under
`VCA_WALLET_AUTH_GRANT_KEY` and keeps only ciphertext in the state
directory. The session id is the associated data, so a ciphertext cannot
move to another session. The first call binds the grant to one credential
issuer URL. A call for another issuer fails with `permission_denied`.
Logout deletes the sealed tokens.

## Holder key

`RegisterHolderKey` binds a public key that the browser created with
WebCrypto (ADR-020 decision 4). The request carries the public JWK and a
compact JWS over the session id, signed with the private key. The service
checks the proof, stores the RFC 7638 thumbprint, derives a `did:jwk`,
and returns both. The private key never reaches the service.

## Logout

`POST /logout` needs the session and a synchronizer token. The service
adds the `sid` to the deny list, deletes the sealed tokens, and clears
the cookie. When the provider advertises `end_session_endpoint`, the
response redirects the browser to the RP initiated logout URL with
`id_token_hint` (ADR-020 decision 5).

## Rate limit and OTP

The `limits` package defines a `Limiter` and an `OTP` interface with an
in-memory version for one replica. The service limits login starts per
client address, 30 per minute by default, on the HTTP endpoint and on the
`LoginStart` RPC. `VCA_REDIS_URL` is optional. Empty selects the
in-memory limiter, which is fine for one replica. Set a Redis URL for
more than one replica. ADR-020 decision 6 asks for Redis. The build
network cannot fetch a Redis client, so `RedisLimiter` is a stub that
returns `ErrNotConfigured`. A deployment that sets `VCA_REDIS_URL`
refuses to start until the client lands. The doc comment on the type
names the Redis commands the real version uses.

## Storage

The service persists `providers.json`, `wallets.json`, and `grants.json`
in the state directory. The wallet document holds the key, the wallet
id, the holder DID, and the key thumbprint. Pending logins and the deny
list live in memory. The shared store package of the services module
will replace the local file store.

## Tests

The test suite runs the full flow against a fake OpenID Provider on
`httptest` and a fake holder backend. It checks three things. The
persisted documents hold no `iss`, `sub`, or access token in plain text.
The grant binds to one issuer. The rate limit applies. Every package has
90 percent statement coverage or more.
