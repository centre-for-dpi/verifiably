# `status-bitstring`

The bitstring status service publishes W3C Bitstring Status List credentials for the issuer role.

## What it does

- It allocates a random index for each new credential, then flips that index when the issuer revokes or suspends.
- It works with every DPG: walt.id, Inji, and CREDEBL embed the list URL and the index it returns.
- It owns two sets of files under the state directory: `lists/` with the bit arrays and the signed copies, and `keys/` with the signing key ring of each issuer.
- It follows these standards: [Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/), [VCDM 2.0](https://www.w3.org/TR/vc-data-model-2.0/), [VC JOSE COSE](https://www.w3.org/TR/vc-jose-cose/), [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html), and [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html).

It does not issue credentials. The issuance service calls `AllocateIndex` for that.

## How to run

Planned (ADR-007, ADR-008):

```sh
vca setup --role issuer --dpg waltid
vca deploy --role issuer --dpg waltid
```

Now:

```sh
cd services/status-bitstring
VCA_STATUS_BITSTRING_STATE_DIR=/var/lib/vca/status go run .
```

Configuration comes from environment variables. The table lists each one.

| Variable | Meaning | Default |
|---|---|---|
| `VCA_STATUS_BITSTRING_LISTEN` | The address the service listens on. | `:8084` |
| `VCA_STATUS_BITSTRING_BASE_URL` | The public root URL. A list URL is this value, then `/status/`, then the list id. | `http://localhost:8084` |
| `VCA_STATUS_BITSTRING_ISSUER_DIDS` | The issuer DIDs, comma separated. The first one is the default. | empty: one `did:jwk` issuer |
| `VCA_STATUS_BITSTRING_SIGNING_ALG` | The algorithm of a generated key: `ES256` or `EdDSA`. | `ES256` |
| `VCA_STATUS_BITSTRING_SIGNING_KEY_FILE` | A PEM file with PKCS #8 keys for the default issuer. The service reads it once, then keeps the ring in the store. | empty: one new key |
| `VCA_STATUS_BITSTRING_STATE_DIR` | The directory of the store files. | empty: in memory |
| `VCA_STATUS_BITSTRING_LIST_SIZE` | The number of entries of a new list. The minimum is `131072`. | `131072` |
| `VCA_STATUS_BITSTRING_LIST_TTL` | How long one signature stays valid. | `24h` |
| `VCA_STATUS_BITSTRING_HTTP_MAX_AGE` | The `Cache-Control` max-age of the served list. | `5m` |
| `VCA_STATUS_BITSTRING_SECURING_METHOD` | The securing method: `jose` or `eddsa-rdfc-2022`. | `jose` |
| `VCA_STATUS_BITSTRING_PAGE_SIZE_MAX` | The maximum page size of `ListLists`. | `50` |

The `eddsa-rdfc-2022` method is a follow-up. The service refuses to start with it and names the reason. See [docs/status-bitstring.md](../../docs/status-bitstring.md).

The container image is `ghcr.io/centre-for-dpi/vca-status-bitstring`. It listens on
one port and runs as a non-root user with a read-only file system.
Mount a volume at `/data` to keep the lists and the keys across a restart.

To rotate the signing key, call `RotateKey`. The service signs every list again with the new key. The old key stays in the JWKS, so an old copy of a list stays verifiable.

## How to check it works

1. Open `http://localhost:8084/healthz`. The response is `200 OK`.
2. Open `http://localhost:8084/readyz`. The response is `200 OK`.
3. Run this command to allocate an index:

```sh
curl -X POST -H 'Content-Type: application/json' \
  -d '{"purpose":"PURPOSE_REVOCATION","kind":"KIND_BITSTRING"}' \
  http://localhost:8084/vca.status.v1.StatusService/AllocateIndex
```

4. Look for a `listId`, an `index`, and a `url` in the response.
5. Run this command to revoke that index, with the values from step 4:

```sh
curl -X POST -H 'Content-Type: application/json' \
  -d '{"listId":"<listId>","index":<index>,"value":1,"reason":"lost card"}' \
  http://localhost:8084/vca.status.v1.StatusService/SetStatus
```

6. Open the `url` from step 4. The response is a compact JWS with the media type `application/vc+jwt`.
7. Open `http://localhost:8084/.well-known/jwks.json` for the key that signed it.

If a step fails, see [errors.md](../../docs/errors.md) for the message and the next step.

## Reference

- API: [`proto/vca/status/v1/status.proto`](../../proto/vca/status/v1/status.proto)
- OpenAPI: [`docs/openapi`](../../docs/openapi/README.md)
- Decision record: [ADR-018](../../docs/adr.md#adr-018-bitstring-status-list)
- Service document: [docs/status-bitstring.md](../../docs/status-bitstring.md)
- Error codes: VCA-102 (the verifier policy service returns it after it reads a set bit from a published list)
- Standards: [Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/), [VC JOSE COSE](https://www.w3.org/TR/vc-jose-cose/), [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html), [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html), [did:jwk](https://github.com/quartzjer/did-jwk/blob/main/spec.md)
