# Bitstring status list

This page describes the `status-bitstring` service (ADR-018). The service
README at [`services/status-bitstring/README.md`](../services/status-bitstring/README.md)
says how to run it. This page says how it works.

The `status-token` service (ADR-019) shares every part of this page except
the securing step. See [status-token.md](status-token.md) for the
differences.

## Data model

The service keeps one record per list under the `lists/` prefix of the
store. A record has these fields.

| Field | Meaning |
|---|---|
| `id` | The list id. The service makes a random hexadecimal id. |
| `kind` | `bitstring` for this service. |
| `purpose` | `revocation`, `suspension`, or `message` (ADR-018 decision 3). |
| `bits` | The width of one entry. A bitstring list always uses 1. |
| `size` | The number of entries. The minimum is 131072. |
| `values` | The bit array itself. |
| `allocated` | The set of allocated indices and their count. |
| `changed` | The time of the last write of each index. |
| `issuer_slug` | The issuer that signs this list. |
| `created_at` | The creation time. |

A second record under the `signed/` prefix holds the signed copy: the
bytes, the media type, the ETag, the key id, the signature time, and the
expiry time.

## Allocation

`AllocateIndex` picks a random free index of a list with the requested
purpose (ADR-018 decision 4). The service reads random bytes from the
operating system and rejects an index that is already allocated. A
verifier cannot infer the issuance order from an index.

The service never reuses an index. A list that has no free index is full,
so the service creates a new list for the next request. One process serves
many lists of the same purpose at the same time.

`SetStatus` writes a value at an allocated index and signs the list again.
It refuses an index that no caller allocated, so a typing error cannot
revoke a credential of another holder. `GetStatus` reads one value and the
time of its last change.

## Publication

A list is a VCDM 2.0 `BitstringStatusListCredential` (ADR-018 decision 1).
The `credentialSubject` holds the `statusPurpose` and the `encodedList`:
the bit array in gzip, then base64url, with the multibase prefix `u`.

The service secures the credential through a `Securer` interface. The
interface takes the record, the issuer, the list URL, and the two times.
It returns one or more media types with their bytes. One interface serves
both status services (ADR-019 decision 4).

| Method | Media type | State |
|---|---|---|
| `jose` | `application/vc+jwt` | Ready. A compact JWS with the `typ` header `vc+jwt`, signed with ES256 or EdDSA. |
| `eddsa-rdfc-2022` | `application/vc` | A follow-up. The securer returns a clear error. |

The `eddsa-rdfc-2022` method needs RDF canonicalisation, that is URDNA2015
(ADR-018 decision 2). The module carries no canonicaliser yet, and a wrong
canonicalisation makes a proof that no other verifier accepts. For this
reason the service refuses to start with the method and names the reason.
Use `jose` until a canonicaliser arrives. Any VCDM 2.0 verifier that reads
VC JOSE COSE accepts the `jose` output today.

## HTTP endpoints

These endpoints are plain `net/http` handlers, not RPCs (ADR-003
decision 7).

| Path | Response |
|---|---|
| `GET /status/{listID}` | The signed list with its media type. |
| `GET /.well-known/jwks.json` | The public keys of every issuer. |
| `GET /healthz`, `GET /readyz` | The health of the process. |

Every list response carries an `ETag` and a `Cache-Control` header with
the configured max-age (ADR-018 decision 5). A request with a matching
`If-None-Match` gets `304 Not Modified`. The ETag is a hash of the signed
bytes, so it changes only when a write changes the list.

The handler reads the `Accept` header and picks a media type the securer
offers. A request that accepts no offered type gets `406 Not Acceptable`.
This service offers one type. The token service offers two.

## Signatures and restart

The service stores the signed bytes next to the record. A restart reads
the copy and serves it, so the process does not sign again (ADR-018
decision 5). The service signs again in two cases: a write changes the bit
array, or the signature passed its expiry time.

The expiry time is the signature time plus `LIST_TTL`. The credential
carries it as `validUntil`, so a verifier sees when a newer copy is due.

## Keys and issuers

Each issuer has its own key ring under the `keys/` prefix (ADR-018
decision 6). The first key of a ring is the active key. The others stay in
the ring so an old list stays verifiable.

A key id is the JWK thumbprint of the public key, that is RFC 7638. The
`kid` header of each signature names it, and the JWKS at
`/.well-known/jwks.json` lists every key of every issuer.

An issuer without a configured DID takes the `did:jwk` of its first key as
its identity. The ADR names `did:web` and `did:key`. A `did:jwk` needs no
hosting and no extra resolution step, so the service can start with no
setup at all. Set `ISSUER_DIDS` to use `did:web`, `did:key`, or any other
method. The service then keeps the configured DID as the issuer of the
credential.

`RotateKey` makes a new key, puts it first in the ring, and signs every
list of that issuer again. The old key stays in the JWKS. A verifier that
holds an old copy of a list can still check it. Remove the old key after
the last copy expires.

## Test vectors

`services/status-bitstring/testdata/vectors/` holds the example of the
specification. The test decodes it, then publishes a list through the
RPCs and verifies the result with the service JWKS. The token service
holds the vectors of the IETF draft in the same layout (ADR-019
decision 5).
