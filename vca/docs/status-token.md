# Token status list

This page describes the `status-token` service (ADR-019). The service
README at [`services/status-token/README.md`](../services/status-token/README.md)
says how to run it. This page says how it works.

The service shares the allocation, the storage, the key ring, the HTTP
endpoints, and the RPCs with `status-bitstring` (ADR-019 decision 4). Read
[status-bitstring.md](status-bitstring.md) for those parts. This page
covers what differs: the status width, the two representations, and the
claims.

## Status width

One entry is 1, 2, 4, or 8 bits wide (ADR-019 decision 3). The width is a
property of the list, not of a representation. `AllocateIndex` takes the
width in the `bits` field. A request with no width takes
`VCA_STATUS_TOKEN_DEFAULT_BITS`.

A wider entry carries more than the two states of a bit.

| Width | Values | Use |
|---|---|---|
| 1 | 0 and 1 | Valid or revoked. |
| 2 | 0 to 3 | Valid, invalid, suspended, and one spare value. |
| 4 | 0 to 15 | The states above and an application range. |
| 8 | 0 to 255 | A full application range. |

The draft reserves 0 for "VALID", 1 for "INVALID", and 2 for "SUSPENDED".
The service writes the value the caller sends and checks only the width.
The issuer decides what a value above 2 means.

## Two representations from one bit array

The service keeps one bit array per list and signs it twice (ADR-019
decision 2).

| Media type | Envelope | Header |
|---|---|---|
| `application/statuslist+jwt` | Compact JWS | `typ` is `statuslist+jwt`, `alg` is ES256 or EdDSA. |
| `application/statuslist+cwt` | COSE_Sign1, that is RFC 9052 | `typ` is `statuslist+cwt`, `alg` is -7 or -8. |

Both carry the same bits, the same issuer, the same subject, and the same
times. A verifier reaches the same answer from either one. A constrained
verifier reads the CBOR form and needs no JSON parser.

`GET /status/{listID}` serves the JWT by default. A request with the
`Accept` header `application/statuslist+cwt` gets the CWT. A request that
accepts neither type gets `406 Not Acceptable`. The `GetList` RPC takes
the same value in its `accept` field.

## Claims

The compressed bit array sits in the `status_list` claim with its width.

| JWT claim | CWT label | Meaning |
|---|---|---|
| `iss` | 1 | The issuer DID. |
| `sub` | 2 | The list URL. It is the URI in the credential. |
| `iat` | 6 | The signature time. |
| `exp` | 4 | The expiry of this signature. |
| `ttl` | 65534 | How long a verifier can cache the list. |
| `status_list` | 65533 | A map with `bits` and `lst`. |
| `aggregation_uri` | 65535 | The optional list of every status list of the issuer. |

The `lst` value is the bit array in DEFLATE, that is RFC 1951, then
base64url with no padding. The CWT holds the same array as raw bytes.

## How a DPG uses the list

The service returns a list URL and an index from `AllocateIndex`. The DPG
puts both in the credential (ADR-019 decision 3). An SD-JWT VC carries
this claim.

```json
{"status": {"status_list": {"idx": 94567, "uri": "https://status.example/status/6f2a"}}}
```

An mdoc carries the same two values in its `status` element. The wallet
and the verifier then fetch the URI and read the index.

## Test vectors

`services/status-token/testdata/vectors/` holds the 1 bit example of
draft-ietf-oauth-status-list (ADR-019 decision 5). The test decodes the
`lst` value, builds the same array from the listed statuses, and compares
both. A second test publishes a list through the RPCs. It reads the list
as a JWT and as a CWT. It verifies each signature and reads every index
back.

The draft is in the RFC Editor queue at draft 21. Each vector file names
its source. A later draft revision is then a new file and a failing test,
not a silent change.
