# vc-core: the shared pure library

`vca/core` holds the pure functions every service shares. The packages
parse, check and build data. They do not serve HTTP, store data or
keep global state. Callers inject network fetches as functions and caches
as interfaces.

This implements ADR-002 decision 7 and ADR-030 decisions 1, 4 and 5.

## Rules

- Every package has 100 percent statement coverage. `make cover` enforces it.
- Every decoder has a Go fuzz test named `FuzzParse...`.
- No `init()`, no package level mutable state, no vendor names.
- The suite keeps legacy test cases as regression tests. Each carries a
  `Regression:` marker.

## Packages

| Package | Purpose | Standard |
|---|---|---|
| `core/jose` | Compact JWS sign (ES256, EdDSA) and check (plus RS256), JWK and JWKS parse, `kid` selection, thumbprints. Wraps go-jose v4. | [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515), [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517), [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518), [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) |
| `core/statuslist/bitstring` | Bitstring status list: allocate, set and get bits. Gzip and multibase base64url encode and decode it. The minimum size is 131072 entries. It supports the purposes revocation, suspension and message. It has credential and entry builders. | [W3C Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/) |
| `core/statuslist/token` | Token status list: 1, 2, 4 and 8 bit statuses, zlib and base64url, JWT (`statuslist+jwt`) and CWT (`statuslist+cwt`) claim sets, minimal COSE_Sign1 encoder and verifier. | [draft-ietf-oauth-status-list](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/), [RFC 8392](https://www.rfc-editor.org/rfc/rfc8392), [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052) |
| `core/sdjwt` | SD-JWT parse, disclosure digests, disclosure resolution for objects and arrays, key binding JWT build and check (`cnf`, `typ`, `aud`, `nonce`, `iat`, `sd_hash`). | [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901) |
| `core/did` | DID resolution for `did:web` (injected fetcher and cache), `did:key` (Ed25519, P-256) and `did:jwk`. Verification method key extraction. | [DID Core 1.0](https://www.w3.org/TR/did-core/), [did:web](https://w3c-ccg.github.io/did-method-web/), [did:key](https://w3c-ccg.github.io/did-key-spec/), [did:jwk](https://github.com/quartzjer/did-jwk/blob/main/spec.md) |
| `core/trust` | Trust entry model, pure lookup, signed trust list JWT build and check (ES256, EdDSA). | [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) |
| `core/delegation` | Delegated access evaluator: linkage, invocation, `capability`, status and advisory trust. `Capability` extraction for JSON-LD `termsOfUse` and SD-JWT `delegation` claims. Issuance side builders. | [W3C VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/) (termsOfUse), [ZCAP-LD](https://w3c-ccg.github.io/zcap-spec/) vocabulary |
| `core/oidc` | PKCE S256 generation and verification. Discovery document parsing and endpoint rebasing. Authorisation URL support. ID token verification against a JWKS (RS256, ES256). | [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636), [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html), [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) |
| `core/pixelpass` | PixelPass QR payload encode and decode: JSON to CBOR, zlib, base45. | [RFC 9285](https://www.rfc-editor.org/rfc/rfc9285), [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949), [MOSIP PixelPass](https://github.com/mosip/pixelpass) |
| `core/vc` | Normalised credential and presentation views, temporal bounds. VCDM and SD-JWT normalisation. Wire format detection from bytes (SD-JWT, JWT, JSON-LD, JSON, mdoc CBOR prefix). Schema types. | [W3C VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/), [VC Data Model 1.1](https://www.w3.org/TR/vc-data-model/), [SD-JWT VC](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/), [ISO/IEC 18013-5](https://www.iso.org/standard/69084.html) |
| `core/summary` | The credential card of a verification result: type, issuer, display claims, validity window, decoded JSON, trust word and checks. The results service and the combined service share it. | Internal (ADR-025, ADR-026) |

## Dependencies

| Module | Version | Use |
|---|---|---|
| `github.com/go-jose/go-jose/v4` | v4.1.5 | JWS, JWK |
| `github.com/fxamacker/cbor/v2` | v2.9.1 | CWT, COSE, PixelPass |

GitHub hosts both modules. On a restricted network
`hack/bootstrap.sh` downloads them with `GOPROXY=direct`.

## Changes from the legacy code

- `core/jose` replaces the hand-rolled JWS in `internal/statuslist/jws.go`,
  `internal/trust/jwt.go` and `internal/jose`. It drops the trust registry
  HS256 mode. A trust list JWT carries `typ: trust-list+jwt`.
- `core/sdjwt` rejects a disclosure that matches no `_sd` digest. The legacy
  `vp.FromCompactSDJWT` merged every disclosure without a digest check.
  It now checks the key binding JWT. The legacy code did not check it.
- `core/statuslist/bitstring` requires the multibase `u` prefix on
  `encodedList`, both when it encodes and when it decodes. `New` raises a
  size below 131072 to 131072. `Get` returns an error for an index out of
  range instead of `false`.
- `core/statuslist/token` supports 2, 4 and 8 bit statuses and the CWT
  form. The legacy code supported 1 bit JWT lists only.
- `core/did` accepts a `did:web` port in the `%3A` form and resolves
  `did:key` and `did:jwk` locally. The legacy resolver resolved `did:web`
  only.
- `core/vc` labels SD-JWT credentials `dc+sd-jwt`. The legacy label was
  `vc+sd-jwt`. Format detection is new.
- `core/trust.Entry` drops the legacy `VerifierAPIKey` field. A secret does
  not belong in a published list.
- `core/oidc.VerifyToken` returns the full claim set. The legacy code
  returned string claims only. `StringClaims` gives the old view.
- The library does not lift file backed key storage (`selfsigned.go`,
  `ldproof.go`) or the JSON-LD Data Integrity proof. Key storage is a
  service concern. The `Ed25519Signature2020` proof needs `json-gold` and
  bundled contexts. The status-bitstring service takes on that proof.
- The vendor descriptors in `vctypes` (`DPG`, `Capability`, the wallet
  `Credential` view) are not lifted. They belong to the UI shells and the
  DPG adapters.
