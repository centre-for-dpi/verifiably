# `trust-registry`

The trust registry publishes the signed list of trusted issuers, holders, and verifiers for the admin role.

## What it does

- It keeps one canonical trust entry per entity and publishes it as an ETSI list and as DeDi directory files.
- It works with every DPG: walt.id, Inji, and CREDEBL read the same lists.
- It owns two files: the trust store `trust.json` with the entries and their versions, and `registries.json` with the external registries and their checked copies.
- It federates with external registries: ETSI TS 119 602 JSON lists, ETSI TS 119 612 XML lists, and DeDi directories.
- It follows these standards: [ETSI TS 119 602](https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf), [ETSI TS 119 612](https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.03.01_60/ts_119612v020301p.pdf), [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html), [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html), [DID Core 1.0](https://www.w3.org/TR/did-1.0/), and the [Decentralized Directory protocol](https://github.com/LF-Decentralized-Trust-labs/decentralized-directory-protocol).

It does not check credentials. The verifier policy service calls `TrustLookup` for that.

## How to run

Planned (ADR-007, ADR-008):

```sh
vca setup --role admin --dpg waltid
vca deploy --role admin --dpg waltid
```

Now:

```sh
cd services/trust-registry
VCA_TRUST_SIGNING_KEY_FILE=/keys/trust.pem go run .
```

Configuration comes from environment variables. The table lists each one.

| Variable | Meaning | Default |
|---|---|---|
| `VCA_TRUST_LISTEN` | The address the service listens on. | `:8080` |
| `VCA_TRUST_BASE_URL` | The public root URL of the service. The lists carry it. | `http://localhost:8080` |
| `VCA_TRUST_ISSUER_ID` | The DID or URL of the registry operator. | The base URL |
| `VCA_TRUST_ISSUER_NAME` | The display name of the operator. | `VCA trust registry` |
| `VCA_TRUST_TERRITORY` | The ISO 3166-1 code of the scheme, for example `KE`. | empty |
| `VCA_TRUST_METHODS` | The enabled methods, comma separated: `etsi`, `dedi`. | `etsi,dedi` |
| `VCA_TRUST_SIGNING_KEY_FILE` | A PEM file with PKCS #8 keys. The first key signs. The others stay in the JWKS. | empty: one key per process |
| `VCA_TRUST_SIGNING_ALG` | The algorithm of a generated key: `ES256` or `EdDSA`. | `ES256` |
| `VCA_TRUST_STORE_FILE` | The JSON file of the store. | empty: in memory |
| `VCA_TRUST_LIST_TTL` | The validity of a published list. | `24h` |
| `VCA_TRUST_HTTP_MAX_AGE` | The `Cache-Control` max-age of the served files. | `5m` |
| `VCA_TRUST_LOOKUP_POLICY` | What `TrustLookup` does with a stale cache: `fail-open` or `fail-closed`. | `fail-closed` |
| `VCA_TRUST_LOOKUP_MAX_AGE` | How long the lookup cache stays fresh. | `1h` |
| `VCA_TRUST_RESOLVE_DIDS` | Resolve the DID of an entry on `UpsertEntry`. | `true` |
| `VCA_TRUST_PAGE_SIZE_MAX` | The maximum page size of `ListEntries`. | `200` |
| `VCA_TRUST_AUDIT_DIR` | The directory of the audit store. | empty: in memory |
| `VCA_TRUST_ADMIN_JWKS_URL` | The key set of the admin service. An admin session it signed opens the audit store. | empty: no admin session is accepted |
| `VCA_TRUST_ADMIN_TOKEN` | The admin service token. It opens the audit store too. | empty: no token is accepted |
| `VCA_TRUST_REGISTRIES_FILE` | The JSON file of the external registries and their cached copies. | `registries.json` beside the store file, or in memory |
| `VCA_TRUST_FEDERATION_ALLOW_PRIVATE` | Let the federation reach private and loopback addresses. For development only. | `false` |
| `VCA_TRUST_FEDERATION_ALLOW_HTTP` | Let the federation read lists over plain http. | `false` |
| `VCA_TRUST_FEDERATION_ALLOWED_HOSTS` | The hosts of external lists, comma separated. A leading dot matches a domain. | empty: every public host |
| `VCA_TRUST_FEDERATION_TICK` | How often the service looks for registries whose refresh passed. | `1m` |

The container image is `ghcr.io/centre-for-dpi/vca-trust-registry`. It listens on
one port and runs as a non-root user with a read-only file system.
Mount a volume at `/data` and set `VCA_TRUST_STORE_FILE=/data/trust.json` to keep entries.

To rotate the signing key, put the new key first in the PEM file. Keep the old key after it. Restart the service. The JWKS then lists both keys. Remove the old key after the last list signed with it expires.

## How to check it works

1. Open `http://localhost:8080/healthz`. The response is `200 OK`.
2. Open `http://localhost:8080/readyz`. The response is `200 OK`.
3. Run this command to add an entry:

```sh
curl -X POST -H 'Content-Type: application/json' \
  -d '{"entry":{"identifier":{"did":"did:web:issuer.example"},"role":"ROLE_ISSUER","status":"STATUS_ACTIVE"}}' \
  http://localhost:8080/vca.trust.v1.TrustService/UpsertEntry
```

4. Open `http://localhost:8080/trust-list/etsi.json`. Look for `did:web:issuer.example` under `entities`.
5. Run this command to check the entity:

```sh
curl -X POST -H 'Content-Type: application/json' \
  -d '{"identifier":{"did":"did:web:issuer.example"},"role":"ROLE_ISSUER"}' \
  http://localhost:8080/vca.trust.v1.TrustService/TrustLookup
```

6. Look for `"outcome":"OUTCOME_TRUSTED"` and a `provenance` object with the method, the list URL, and the key id.

If a step fails, see [errors.md](../../docs/errors.md) for the message and the next step.

## Reference

- API: [`proto/vca/trust/v1/trust.proto`](../../proto/vca/trust/v1/trust.proto)
- OpenAPI: `gen/openapi/trust.yaml`
- Decision record: [ADR-011](../../../ADR.md#adr-011-signed-trust-registry-with-dedi-and-etsi-as-distinct-methods)
- Service document: [docs/trust-registry.md](../../docs/trust-registry.md)
- Error codes: VCA-201 (the verifier policy service returns it from a `TrustLookup` result)
- Standards: [ETSI TS 119 602](https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf), [ETSI TS 119 612](https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.03.01_60/ts_119612v020301p.pdf), [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html), [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html), [did:web](https://w3c-ccg.github.io/did-method-web/)
