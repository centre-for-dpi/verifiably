# `schema-builder-ui`

The schema builder is the page where issuer staff build a credential schema. It shows what a citizen will see while the author types.

## What it does

- It builds a JSON Schema 2020-12 document from a form. Field types, required flags, enums, formats, and selective disclosure flags are first class.
- It renders a live preview on every edit. The form posts to the preview endpoint with the htmx trigger `input changed delay:250ms`.
- The live view holds three tabs: the sample credential JSON, the wallet card from the OID4VCI display metadata, and the PDF preview.
- The preview comes from the pure function `PreviewCredential` in `core/preview`. The service holds no preview logic of its own.
- The preview region is an `aria-live="polite"` region. Every control is a labelled form control, so the pages work with the keyboard.
- Save stores a draft version in the schema registry. The DPG learns nothing until staff publish the version there.
- Import reads an existing JSON Schema document, or a credential type of the DPG through `CatalogBackendService`.
- It keeps no state on disk. The only state is a small cache of rendered PDF preview documents.
- It follows these standards: [JSON Schema 2020-12](https://json-schema.org/draft/2020-12/json-schema-core), [OID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html), and [WAI-ARIA 1.2](https://www.w3.org/TR/wai-aria-1.2/).

It does not store schemas. The `schema-registry` service does that.

## How to run

Planned (ADR-007, ADR-008):

```sh
vca setup --role issuer --dpg waltid
vca deploy --role issuer --dpg waltid
```

Now:

```sh
cd services/schema-builder-ui
VCA_SCHEMABUILDER_REGISTRY_URL=http://localhost:8080 go run .
```

Configuration comes from environment variables. The table lists each one.

| Variable | Meaning | Default |
|---|---|---|
| `VCA_SCHEMABUILDER_LISTEN` | The address the service listens on. | `:8081` |
| `VCA_SCHEMABUILDER_REGISTRY_URL` | The Connect base URL of the schema registry. Required. | none |
| `VCA_SCHEMABUILDER_REGISTRY_TIMEOUT` | The timeout of one call to the schema registry. | `10s` |
| `VCA_SCHEMABUILDER_CATALOG_URL` | The Connect base URL of the DPG adapter that serves `CatalogBackendService`. | empty: no catalogue import |
| `VCA_SCHEMABUILDER_CATALOG_TIMEOUT` | The timeout of one call to the DPG catalogue. | `10s` |
| `VCA_SCHEMABUILDER_PORTAL_URL` | The schema registry portal URL the pages link to. | empty |
| `VCA_SCHEMABUILDER_PREFIX` | The URL prefix of the builder pages. | `/builder` |
| `VCA_SCHEMABUILDER_ISSUER` | The issuer identifier the preview credential carries. | The preview default |
| `VCA_SCHEMABUILDER_PDF_CACHE_SIZE` | The number of PDF preview documents the cache holds. | `64` |

The container image is `ghcr.io/centre-for-dpi/vca-schema-builder-ui`. It listens on
one port and runs as a non-root user with a read-only file system.

## How to check it works

1. Start a `schema-registry` on port 8080. Start this service with `VCA_SCHEMABUILDER_REGISTRY_URL=http://localhost:8080`.
2. Open `http://localhost:8081/healthz`. The response is `200 OK`.
3. Open `http://localhost:8081/readyz`. The response is `200 OK`.
4. Open `http://localhost:8081/builder/`. The page shows the form and the preview.
5. Change the display name. The preview region changes after 250 milliseconds.
6. Open the tab `PDF preview`. Follow the link. The browser shows a one page PDF.
7. Press `Save the draft`. The page moves to the saved version. The schema registry holds a draft.
8. Open `http://localhost:8081/builder/import`. Paste a JSON Schema document. Press `Import the document`. The builder opens the draft.
9. Run this command to render a preview through the RPC:

```sh
curl -sS -H 'Content-Type: application/json' \
  -d '{"schema":{"type":"UniversityDegree","json_schema":"{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"}}}","display":[{"name":"Degree","locale":"en"}]},"sample":"{\"name\":\"Ada\"}"}' \
  http://localhost:8081/vca.schemabuilder.v1.SchemaBuilderService/PreviewCredential
```

10. Run `go test ./services/schema-builder-ui/...` from `vca/`. Every test passes.

## Reference

- ADR-014 in [`docs/adr.md`](../../docs/adr.md).
- The service document: [`docs/schema-builder-ui.md`](../../docs/schema-builder-ui.md).
- The proto: [`proto/vca/schemabuilder/v1/schemabuilder.proto`](../../proto/vca/schemabuilder/v1/schemabuilder.proto).
- The schema registry: [`services/schema-registry/README.md`](../schema-registry/README.md).
- The UI kit: [`docs/ui.md`](../../docs/ui.md).
