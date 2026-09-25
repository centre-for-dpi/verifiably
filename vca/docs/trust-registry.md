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
| `status` | `active`, `suspended`, `revoked`, or `pending`. A pending entry waits for review. The lists never carry it. |
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

### Pending entries

The service publishes every entry except the pending ones. An admin
approves a pending entry, which sets it to `active`, or rejects it, which
removes it. The lookup reads the published lists, so a pending entry
gives `UNKNOWN`. The entry evaluation also answers `UNTRUSTED` for a
pending entry, so no path trusts it.

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

## Federation

The service can read the trust lists of external registries (ADR-011
decision 7). An admin adds a registry with a name, a format, a list URL,
a trust anchor, and a refresh interval. The service reads the list at
once and then on each refresh. `internal/federation` holds the code.

| Format | What the service reads | Anchor |
|---|---|---|
| `etsi-lote-json` | An ETSI TS 119 602 list as a compact JWS. | A JWKS URL, or an X.509 certificate whose key signs the list. |
| `etsi-tsl-xml` | An ETSI TS 119 612 XML list with an enveloped XML signature. | An X.509 certificate that signs the list or issued its signer. |
| `dedi` | A DeDi manifest and every directory file it lists. | A JWKS URL, or an X.509 certificate whose key signs the files. |

Every read goes through `core/fetchguard`. The guard refuses private,
loopback, and link local addresses and plain http unless the settings
allow them. A DeDi directory file must sit on the host of its manifest.
The service checks every signature against the anchor. A changed list
fails the check. The service keeps the last good copy of each registry
with the time of the check. A failed read puts its reason in
`last_error`. The copies live in `registries.json` beside the store
file, so a lookup works offline after a restart.

`internal/xmldsig` checks the XML signature. It supports the profile
that trusted lists use. That is exclusive canonicalization without
comments and the enveloped signature transform. The digest is SHA-256,
SHA-384 or SHA-512, and the signature is RSA or ECDSA. One reference must cover the document element. Any other
shape is an error. The test fixtures come from `testdata/gen.py`, which
signs with lxml, so the Go code checks a signature it did not make.

`TrustLookup` asks the local lists first. When they do not name the
entity, it asks the copies of the external registries. A trusted answer
wins. The provenance then carries `registry_id` and `registry_name`,
the list URL, the key id or certificate subject, and the check time. An
expired copy gives no answer.

`ExportSnapshot` signs every entry a lookup reads with the key of the
lists. The snapshot holds the published local entries first. Then it
holds the copy of each external registry. Each copy names its registry,
list URL, signer, check time, and anchor certificates. The verifier policy service
checks the signature and keeps the snapshot for checks with no network
(ADR-041 decision 1). The RPC stays on the compose network.

Nobody edits the entries of an external registry here. `UpsertEntry` and
`DeleteEntry` refuse an entity that an external registry names, and
`ImportEtsi` skips it.

## Audit log

The service writes one audit event for each trust entry change and each registry change (ADR-039 decision 1).
The event names the actor, the action, the target, the outcome, and the
request id. It never holds a claim value. A failure names the Connect
code of the answer, never the text of the error. The service checks no
session itself, so the actor is the one its caller names in the
`X-Vca-Actor` header.

The events live in an append only store under `VCA_TRUST_AUDIT_DIR`.
The CLI sets it to `/data/audit`. The service serves the store as
`vca.audit.v1.AuditService` on the internal network. Only the admin
opens it: an admin session that the key set at `VCA_TRUST_ADMIN_JWKS_URL`
signed, or the token in `VCA_TRUST_ADMIN_TOKEN`. The pair proxy does not
route the service. `SetRetention` keeps the events of the last days the
admin sets and removes older ones.

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
| `internal/store` | The versioned store over the shared store document. |
| `internal/keys` | The key ring with `kid`, rotation, and JWKS. |
| `internal/publish` | The `TrustListPublisher` interface and the published snapshot. |
| `internal/etsi` | The etsi publisher and the TS 119 612 XML import. |
| `internal/dedi` | The dedi publisher. The file layout is in `schema.go`. |
| `internal/lookup` | The signature checked cache and the stale policy. |
| `internal/federation` | The external registries, their checked copies, and the external lookup. |
| `internal/xmldsig` | The XML signature check of ETSI TS 119 612 lists. |
| `internal/httpapi` | The plain HTTP endpoints with `ETag` and cache headers. |
| `internal/service` | The Connect handler of `TrustService`. |
| `internal/app` | The wiring from configuration to handler. |
| `internal/config` | The environment settings, read with the shared config package. |
