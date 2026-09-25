# `data-source`

The data source service keeps the CSV files, HTTP APIs, and databases that issuer staff issue credentials from.

## What it does

- It stores one typed `Source` per connector: `CsvSource`, `HttpSource`, or `SqlSource`.
- It holds a secret reference for every credential. It never stores or returns a secret value.
- It checks a role rule per source before it reads one row. The session comes from `issuer-auth`.
- It draws the bulk issuance pages of the issuer at `/sources/`: sources, masked preview, field map, run, and progress.
- It returns the field names with inferred types, and at most 20 masked rows.
- It stores one `FieldMap` per source and schema pair, with the pure transforms of `core/mapping`.
- It guards every HTTP source with a scheme check, a host allowlist, and a private address check.
- It owns one file: the source store `sources.json` with the sources and the field maps.

It does not issue credentials. A bulk run calls `IssueBatch` of the issuance service (ADR-015 decision 7).

## How to run

```sh
cd services/data-source
VCA_DATASOURCE_ALLOW_HOSTS=api.example.org go run .
```

Configuration comes from environment variables. The table lists each one.

| Variable | Meaning | Default |
|---|---|---|
| `VCA_DATASOURCE_LISTEN` | The address the service listens on. | `:8080` |
| `VCA_DATASOURCE_STORE_FILE` | The JSON file of the store. | empty: in memory |
| `VCA_DATASOURCE_CSV_DIR` | The directory of uploaded CSV files. | empty: inline data URLs only |
| `VCA_DATASOURCE_SECRETS_DIR` | The directory of file secrets. | empty: the file store is off |
| `VCA_DATASOURCE_ALLOW_HOSTS` | The host names HTTP sources can reach, comma separated. A leading dot matches sub domains. | empty: no host |
| `VCA_DATASOURCE_ALLOW_HTTP` | Permit the plain `http` scheme. Set it only for a local test. | `false` |
| `VCA_DATASOURCE_ALLOW_PRIVATE` | Permit private, loopback, and link local addresses. Set it only for a local test. | `false` |
| `VCA_DATASOURCE_HTTP_MAX_BYTES` | The size cap of one HTTP source response. | `8388608` |
| `VCA_DATASOURCE_HTTP_TIMEOUT` | The time limit of one HTTP source read. | `30s` |
| `VCA_DATASOURCE_CSV_MAX_BYTES` | The size cap of one CSV file. | `33554432` |
| `VCA_DATASOURCE_SQL_MAX_ROWS` | The row cap of one SQL query. | `10000` |
| `VCA_DATASOURCE_PAGE_SIZE_MAX` | The maximum page size of `List`. | `50` |
| `VCA_DATASOURCE_AUTH_JWKS_URL` | The key set of `issuer-auth`. | empty: no session passes |
| `VCA_DATASOURCE_AUTH_JWKS_FILE` | A JWKS file in place of the URL, for a test. | empty |
| `VCA_DATASOURCE_AUTH_JWKS_TTL` | How long a fetched key set stays fresh. | `10m` |
| `VCA_DATASOURCE_AUTH_ISSUER` | The `iss` claim every session must carry. | empty: any issuer of the key set |
| `VCA_DATASOURCE_LOGIN_URL` | The sign in chooser of the pair. A page without a session goes there. | empty: `401` |
| `VCA_DATASOURCE_PUBLIC_URL` | The public URL of the pair. | empty |
| `VCA_DATASOURCE_SCHEMA_URL` | The schema registry of the pair. | empty: no schema |
| `VCA_DATASOURCE_ISSUANCE_URL` | The issuance service of the pair. A bulk run calls it. | empty: no run |
| `VCA_DATASOURCE_TIMEOUT` | The time limit of one call to another service. | `30s` |
| `VCA_DATASOURCE_RUN_TIMEOUT` | The time limit of one bulk run. | `2h` |
| `VCA_THEME_FILE` | The theme file of the pages. | empty: the embedded default |
| `VCA_PEERS` | The pairs of the deployment, for the issuer shell. | empty |

Every RPC and every page needs a session JWT of `issuer-auth`. The staff guard checks it against the key set of `issuer-auth` and reads the `roles` claim.
No header stands in for a session. Without a key set the service accepts no call.

The service draws the bulk issuance pages at `/sources/`. The document [`docs/data-source.md`](../../docs/data-source.md) lists them.

The container image is `ghcr.io/centre-for-dpi/vca-data-source`.
It listens on one port and runs as a non-root user with a read-only file system.
Mount a volume at `/data` for the store file and the uploaded CSV files.

SQL sources need a driver. The binary registers no driver by default, so `SqlSource` reports `VCA-401` until an operator builds an image with one.
This keeps the default image free of a database client.

## How to check it works

1. Open `http://localhost:8080/healthz`. The response is `200 OK`.
2. Open `http://localhost:8080/readyz`. The response is `200 OK`.
3. Sign in to the issuer pair and copy the session token into `TOKEN`. Run this command to add a CSV source:

```sh
curl -X POST http://localhost:8080/vca.datasource.v1.DataSourceService/Create \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"source":{"displayName":"Staff","csv":{"fileRef":"data:text/csv;base64,bmFtZSxhZ2UKQWRhLDM2Cg==","hasHeader":true},"access":{"viewFields":["issuer-viewer"],"previewRows":["issuer-operator"],"issue":["issuer-operator"]}}}'
```

4. Call `PreviewFields` with the returned id. The response names `name` and `age` with the types `string` and `integer`.
5. Call `PreviewRows`. The service masks every value, for example `A*a`.
6. Repeat step 4 without the `Authorization` header. The response is `unauthenticated`.
7. Open `http://localhost:8080/sources/` in a browser with a session. The page lists the source.

## Reference

- ADR-015 in [`docs/adr.md`](../../docs/adr.md).
- The service document: [`docs/data-source.md`](../../docs/data-source.md).
- The API: [`proto/vca/datasource/v1/datasource.proto`](../../proto/vca/datasource/v1/datasource.proto).
- The transforms: [`core/mapping`](../../core/mapping).
