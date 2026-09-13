# Trust registry

This page describes the `trust-registry` service (ADR-011). The service
README at [`services/trust-registry/README.md`](../services/trust-registry/README.md)
says how to run it. This page says how it works.

## Data model

The service keeps one canonical trust entry per entity (ADR-011 decision 1).
An entry has these fields.

| Field | Meaning |
|---|---|
| `did` or `x509_subject` | The entity identifier. The caller sets exactly one. ETSI imports set the x509 subject. |
| `display_name` | The name shown to people. |
| `role` | `issuer`, `holder`, or `verifier`. |
| `status` | `active`, `suspended`, or `revoked`. |
| `valid_from`, `valid_until` | The validity window. Empty means open. |
| `credential_types` | The VCDM types or SD-JWT VC `vct` values the entity can use. Empty means every type. |
| `service_endpoint` | The base URL of the entity deployment. |
| `status_list_endpoints` | The public status list URLs of the entity. |
| `version` | The count of changes of this entry. |
| `source` | `admin` or `etsi-import`. |

The store raises the entry version on each edit. It also raises one
revision counter for the whole store. The revision is the sequence number
of the next publication.

## Publication

Every edit republishes every enabled method (ADR-011 decision 4). The
`Publish` RPC forces a new publication. Each method is a
`TrustListPublisher` in `internal/publish`. A publisher builds the files
of its method and also checks a published set of files.

| Method | Files | Signature |
|---|---|---|
| `etsi` | `/trust-list/etsi.json`, `/trust-list/etsi.jws` | Compact JWS with `typ` `trust-list+jwt`. |
| `dedi` | `/.well-known/dedi.index.json`, `/dedi/dedi.issuers.json`, `/dedi/dedi.holders.json`, `/dedi/dedi.verifiers.json` | Each file carries a `proof.jws` over its `document`. |

The keys are at `/.well-known/jwks.json`. Every served file carries an
`ETag` and a `Cache-Control` header. A request with `If-None-Match` gets
`304 Not Modified` when the file did not change.

### The etsi method

The JSON list follows the data model of ETSI TS 119 602 V1.1.1 with plain
camelCase names: `schemeInformation` with the list issuer, the sequence
number, the issue time, and the next update; and `entities` with
`serviceDigitalIdentities`, `status`, `statusUri`, and the validity. The
`statusUri` uses the ETSI TS 119 612 service status URIs `granted` and
`withdrawn`.

`ImportEtsi` reads an ETSI TS 119 612 XML trusted list. It reads
`SchemeInformation`, each `TrustServiceProvider`, each `TSPService`, and
the `ServiceDigitalIdentity`. An `X509Certificate` gives the subject and
the expiry. An `X509SubjectName` gives the subject only. The import skips a
service with no x509 identity and records the reason. The status `granted`,
`recognisedatnationallevel`, and `setbynationallaw` become `active`. Every
other status becomes `revoked`. The import sets the role to `issuer`.

### The dedi method

The build network could not reach the Decentralized Directory protocol
repository. The file layout in `internal/dedi/schema.go` follows the ADR
description with plain names. `SchemaVersion` is `vca-dedi-draft-1`. To
adopt the vendored schema, replace `schema.go`, set `SchemaVersion` to the
schema version and commit hash, and keep the exported type names. The
publisher and the verifier in `dedi.go` use the exported types only.

The manifest declares the signing key as a JWK and the JWKS URL. It has
one row per directory file. A row holds the URL, the SHA-256 digest, and
the entry count of the file.

## Keys

The service signs with ES256 or Ed25519 only (ADR-011 decision 5). There
is no HS256 mode. Every key has a `kid`: the RFC 7638 thumbprint. The PEM
file can hold more than one PKCS #8 key. The first key signs. The others
stay in the JWKS. Relying parties use them to check older lists. Without a
key file the service generates one key per process and logs a warning.

## Lookup

`TrustLookup` (ADR-011 decision 7) does not read the store. It reads the
published files and checks their signatures with the JWKS. It keeps one
checked copy per method with the time of the check. The answer carries
the outcome, the entry, and the provenance: method, list URL, key id, and
check time.

| Outcome | Meaning |
|---|---|
| `TRUSTED` | An enabled list names the entity with the role, status `active`, and a valid window. |
| `UNTRUSTED` | A list names the entity, but the role, status, window, or credential type does not match. |
| `UNKNOWN` | No enabled list names the entity. |
| `UNAVAILABLE` | No checked copy exists, or the copy is stale and the policy is `fail-closed`. |

A copy is stale when it is older than `VCA_TRUST_LOOKUP_MAX_AGE` or when
the list expired. With `fail-open` the service answers from the stale
copy. With `fail-closed` it answers `UNAVAILABLE`.

## DID resolution

`UpsertEntry` resolves the DID of the entry through `core/did` (ADR-011
decision 6). `did:key` and `did:jwk` resolve offline. `did:web` uses an
injected fetcher that accepts `https` URLs only and caps the document at
1 MiB. Set `VCA_TRUST_RESOLVE_DIDS=false` to skip resolution, for example
in a test network.

## Layout

| Package | Content |
|---|---|
| `internal/entry` | The canonical entry, validation, proto conversion, and lookup evaluation. |
| `internal/store` | The versioned store with memory and file backends. |
| `internal/keys` | The key ring with `kid`, rotation, and JWKS. |
| `internal/publish` | The `TrustListPublisher` interface and the published snapshot. |
| `internal/etsi` | The etsi publisher and the TS 119 612 XML import. |
| `internal/dedi` | The dedi publisher. The file layout is in `schema.go`. |
| `internal/lookup` | The signature checked cache and the stale policy. |
| `internal/httpapi` | The plain HTTP endpoints with `ETag` and cache headers. |
| `internal/service` | The Connect handler of `TrustService`. |
| `internal/app` | The wiring from configuration to handler. |
| `internal/config`, `internal/serve` | Local stand-ins for the shared config and server packages. |
