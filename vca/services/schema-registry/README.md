# `schema-registry`

The schema registry keeps the credential schemas of one issuer. It serves the public documents wallets and verifiers read.

## What it does

- It stores each schema as a JSON Schema 2020-12 document with an immutable version. An update creates a new version.
- Each version is `draft`, `published`, or `retired`. Only a draft can publish. Only a published version can retire.
- Publish registers the version with the DPG through `RegisterCredentialConfiguration`. No HOCON file and no container restart.
- It generates the OID4VCI issuer metadata `credential_configurations_supported` from the published versions.
- It generates one SD-JWT VC type metadata document per published schema.
- It serves staff pages for list, search, filter, detail, version history, publish, and retire. Every action is an RPC.
- It owns one file: the schema store `schemas.json` with every version.
- It follows these standards: [JSON Schema 2020-12](https://json-schema.org/draft/2020-12/json-schema-core), [VC JSON Schema](https://www.w3.org/TR/vc-json-schema/), [OID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html), and the [SD-JWT VC draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/).

It does not build schemas. The `schema-builder-ui` service does that and saves a draft here.

## How to run

Planned (ADR-007, ADR-008):

```sh
vca setup --role issuer --dpg waltid
vca deploy --role issuer --dpg waltid
```

Now:

```sh
cd services/schema-registry
VCA_SCHEMA_STORE_FILE=/data/schemas.json go run .
```

Configuration comes from environment variables. The table lists each one.

| Variable | Meaning | Default |
|---|---|---|
| `VCA_SCHEMA_LISTEN` | The address the service listens on. | `:8080` |
| `VCA_SCHEMA_BASE_URL` | The public root URL of the service. The documents carry it. | `http://localhost:8080` |
| `VCA_SCHEMA_STORE_FILE` | The JSON file of the store. | empty: in memory |
| `VCA_SCHEMA_BACKEND_URL` | The base URL of the DPG adapter that registers a published version. | empty: no registration |
| `VCA_SCHEMA_BACKEND_TIMEOUT` | The timeout of one call to the DPG adapter. | `10s` |
| `VCA_SCHEMA_CREDENTIAL_ISSUER` | The OID4VCI `credential_issuer` value. | The base URL |
| `VCA_SCHEMA_CREDENTIAL_ENDPOINT` | The OID4VCI `credential_endpoint` value. | The issuer plus `/credential` |
| `VCA_SCHEMA_AUTHORIZATION_SERVERS` | The OAuth authorization servers, comma separated. | empty |
| `VCA_SCHEMA_SIGNING_ALGS` | The `credential_signing_alg_values_supported` values, comma separated. | `ES256,EdDSA` |
| `VCA_SCHEMA_HTTP_MAX_AGE` | The `Cache-Control` max-age of the public documents. | `5m` |
| `VCA_SCHEMA_PORTAL_PREFIX` | The URL prefix of the staff pages. | `/portal` |
| `VCA_SCHEMA_BUILDER_URL` | The schema builder URL the portal links to. | empty |
| `VCA_SCHEMA_PAGE_SIZE_MAX` | The maximum page size of `List` and `Search`. | `200` |
| `VCA_SCHEMA_AUTH_JWKS_URL` | The JWKS URL of `issuer-auth`. The staff pages accept only a session it signed. | empty: the staff pages accept no session |
| `VCA_SCHEMA_AUTH_JWKS_FILE` | A JWKS file that replaces the URL, for a test. | empty |
| `VCA_SCHEMA_AUTH_JWKS_TTL` | How long a fetched key set stays fresh. | `10m` |
| `VCA_SCHEMA_AUTH_ISSUER` | The `iss` claim every session must carry. | empty: any issuer of the key set |
| `VCA_SCHEMA_LOGIN_URL` | The sign in chooser a page request without a session goes to, with `return_to`. | empty: answer 401 |

The container image is `ghcr.io/centre-for-dpi/vca-schema-registry`. It listens on
one port and runs as a non-root user with a read-only file system.
Mount a volume at `/data` and set `VCA_SCHEMA_STORE_FILE=/data/schemas.json` to keep versions.

## How to check it works

1. Open `http://localhost:8080/healthz`. The response is `200 OK`.
2. Open `http://localhost:8080/readyz`. The response is `200 OK`.
3. Run this command to create a draft:

```sh
curl -sS -H 'Content-Type: application/json' \
  -d '{"schema":{"type":"UniversityDegree","json_schema":"{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"}},\"required\":[\"name\"]}","formats":["FORMAT_DC_SD_JWT"],"display":[{"name":"Degree","locale":"en"}]}}' \
  http://localhost:8080/vca.schema.v1.SchemaService/Create
```

4. Publish the draft. Use the schema id the last step returned.

```sh
curl -sS -H 'Content-Type: application/json' -d '{"id":"<id>"}' \
  http://localhost:8080/vca.schema.v1.SchemaService/Publish
```

5. Open `http://localhost:8080/api/schemas`. The list holds the published version.
6. Open `http://localhost:8080/.well-known/openid-credential-issuer`. The document holds one `credential_configurations_supported` entry per format.
7. Open `http://localhost:8080/.well-known/vct/UniversityDegree`. The document is the SD-JWT VC type metadata.
8. Open `http://localhost:8080/portal/`. The page lists the schema. Search, filter, and open the detail page.
9. Run `go test ./services/schema-registry/...` from `vca/`. Every test passes.

## Reference

- ADR-013 in [`docs/adr.md`](../../docs/adr.md).
- The service document: [`docs/schema-registry.md`](../../docs/schema-registry.md).
- The proto: [`proto/vca/schema/v1/schema.proto`](../../proto/vca/schema/v1/schema.proto).
- The UI kit: [`docs/ui.md`](../../docs/ui.md).
