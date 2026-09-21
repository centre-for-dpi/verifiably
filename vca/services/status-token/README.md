# `status-token`

The token status service publishes IETF Token Status Lists for the issuer role.

## What it does

- It allocates a random index for each new credential, then writes the status value of that index on request.
- It works with every DPG: walt.id, Inji, and CREDEBL put the URI and the index in the `status_list` claim of an SD-JWT VC or an mdoc.
- It owns two sets of files under the state directory: `lists/` with the bit arrays and the signed copies, and `keys/` with the signing key ring of each issuer.
- It follows these standards: [draft-ietf-oauth-status-list](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/), [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html), [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html), [RFC 8392](https://www.rfc-editor.org/rfc/rfc8392.html), and [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html).

It does not issue credentials. The issuance service calls `AllocateIndex` for that.

## How to run

Planned (ADR-007, ADR-008):

```sh
vca setup --role issuer --dpg inji
vca deploy --role issuer --dpg inji
```

Now:

```sh
cd services/status-token
VCA_STATUS_TOKEN_STATE_DIR=/var/lib/vca/status-token go run .
```

Configuration comes from environment variables. The table lists each one.

| Variable | Meaning | Default |
|---|---|---|
| `VCA_STATUS_TOKEN_LISTEN` | The address the service listens on. | `:8085` |
| `VCA_STATUS_TOKEN_BASE_URL` | The public root URL. A list URL is this value, then `/status/`, then the list id. It is the `sub` claim too. | `http://localhost:8085` |
| `VCA_STATUS_TOKEN_ISSUER_DIDS` | The issuer DIDs, comma separated. The first one is the default. | empty: one `did:jwk` issuer |
| `VCA_STATUS_TOKEN_SIGNING_ALG` | The algorithm of a generated key: `ES256` or `EdDSA`. | `ES256` |
| `VCA_STATUS_TOKEN_SIGNING_KEY_FILE` | A PEM file with PKCS #8 keys for the default issuer. The service reads it once, then keeps the ring in the store. | empty: one new key |
| `VCA_STATUS_TOKEN_STATE_DIR` | The directory of the store files. | empty: in memory |
| `VCA_STATUS_TOKEN_LIST_SIZE` | The number of entries of a new list. | `131072` |
| `VCA_STATUS_TOKEN_DEFAULT_BITS` | The status width of a new list when the request gives none: `1`, `2`, `4`, or `8`. | `1` |
| `VCA_STATUS_TOKEN_LIST_TTL` | How long one signature stays valid. | `24h` |
| `VCA_STATUS_TOKEN_TOKEN_TTL` | The `ttl` claim, the time a verifier can cache the list. Zero leaves the claim out. | `5m` |
| `VCA_STATUS_TOKEN_HTTP_MAX_AGE` | The `Cache-Control` max-age of the served list. | `5m` |
| `VCA_STATUS_TOKEN_AGGREGATION_URI` | The optional `aggregation_uri` claim. | empty |
| `VCA_STATUS_TOKEN_PAGE_SIZE_MAX` | The maximum page size of `ListLists`. | `50` |

The container image is `ghcr.io/centre-for-dpi/vca-status-token`. It listens on
one port and runs as a non-root user with a read-only file system.
Mount a volume at `/data` to keep the lists and the keys across a restart.

To rotate the signing key, call `RotateKey`. The service signs every list again with the new key. The old key stays in the JWKS, so an old copy of a list stays verifiable.

## How to check it works

1. Open `http://localhost:8085/healthz`. The response is `200 OK`.
2. Open `http://localhost:8085/readyz`. The response is `200 OK`.
3. Run this command to allocate an index:

```sh
curl -X POST -H 'Content-Type: application/json' \
  -d '{"purpose":"PURPOSE_REVOCATION","kind":"KIND_TOKEN","bits":1}' \
  http://localhost:8085/vca.status.v1.StatusService/AllocateIndex
```

4. Look for a `listId`, an `index`, and a `url` in the response.
5. Run this command to revoke that index, with the values from step 4:

```sh
curl -X POST -H 'Content-Type: application/json' \
  -d '{"listId":"<listId>","index":<index>,"value":1,"reason":"lost card"}' \
  http://localhost:8085/vca.status.v1.StatusService/SetStatus
```

6. Open the `url` from step 4. The response is a compact JWS with the media type `application/statuslist+jwt`.
7. Run this command for the same list in CBOR:

```sh
curl -H 'Accept: application/statuslist+cwt' <url> --output list.cwt
```

8. Open `http://localhost:8085/.well-known/jwks.json` for the key that signed both.

If a step fails, see [errors.md](../../docs/errors.md) for the message and the next step.

## Reference

- API: [`proto/vca/status/v1/status.proto`](../../proto/vca/status/v1/status.proto)
- OpenAPI: [`docs/openapi`](../../docs/openapi/README.md)
- Decision record: [ADR-019](../../docs/adr.md#adr-019-token-status-list)
- Service document: [docs/status-token.md](../../docs/status-token.md)
- Error codes: VCA-102 (the verifier policy service returns it after it reads a set status from a published list)
- Standards: [draft-ietf-oauth-status-list](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/), [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html), [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html), [RFC 8392](https://www.rfc-editor.org/rfc/rfc8392.html), [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html), [did:jwk](https://github.com/quartzjer/did-jwk/blob/main/spec.md)
