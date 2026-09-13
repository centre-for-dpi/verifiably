# `issued-credentials`

The issued credentials service keeps the tamper evident log of every credential the deployment issued.

## What it does

- It appends one record per issuance to a hash chain.
- Each record holds the id, the schema, the schema version, and the salted subject reference.
- It also holds the format, the status list binding, the DPG, the time, and the hashes.
- It stores no personal data. It stores a salted subject reference and only the claims the issuer marks as searchable.
- It answers `List`, `Search`, `Get`, and `Export`. The export is RFC 4180 CSV or one JSON object per line.
- `Revoke` and `Reinstate` call the status service first.
- They then record the reason in the log. A revoked credential stays revoked.
- It signs the chain head once a day with an ES256 key.
- An auditor reads the signed head and proves that no record went missing.
- It prunes records whose per schema retention ended. The chain keeps every entry, so the head stays provable.
- It owns one file: the log `issued.json` with every chain entry.

It does not issue credentials. The issuance service writes the records.

## How to run

```sh
cd services/issued-credentials
VCA_ISSUED_STATUS_URL=http://localhost:8085 go run .
```

Configuration comes from environment variables. The table lists each one.

| Variable | Meaning | Default |
|---|---|---|
| `VCA_ISSUED_LISTEN` | The address the service listens on. | `:8080` |
| `VCA_ISSUED_STORE_FILE` | The JSON file of the log. | empty: in memory |
| `VCA_ISSUED_SALT` | The salt of the subject reference. | empty |
| `VCA_ISSUED_SALT_FILE` | A file that holds the salt. It wins over `VCA_ISSUED_SALT`. | empty |
| `VCA_ISSUED_HEAD_KEY_FILE` | The PKCS 8 PEM file of the ES256 head signing key. | empty: a new key at every start |
| `VCA_ISSUED_HEAD_ISSUER` | The name of the deployment in the signed head. | empty |
| `VCA_ISSUED_HEAD_PERIOD` | The time between two signatures of an unchanged head. | `24h` |
| `VCA_ISSUED_RETENTION` | The per schema retention rules, for example `default=5y,visitor=30d`. The units are s, m, h, d, w, and y. | empty: keep every record |
| `VCA_ISSUED_PRUNE_INTERVAL` | The time between two prune runs. `0` turns the job off. | `24h` |
| `VCA_ISSUED_STATUS_URL` | The base URL of the status service. | empty: no status change |
| `VCA_ISSUED_STATUS_TIMEOUT` | The time limit of one status service call. | `10s` |
| `VCA_ISSUED_PAGE_SIZE_MAX` | The maximum page size of `List` and `Search`. | `50` |

Set `VCA_ISSUED_SALT_FILE` in production. Without a salt the subject reference is not hard to guess.
Set `VCA_ISSUED_HEAD_KEY_FILE` in production. A generated key changes at every restart, so an old head no longer verifies.

The container image is `ghcr.io/centre-for-dpi/vca-issued-credentials`.
It listens on one port and runs as a non-root user with a read-only file system.
Mount a volume at `/data` for the log.

## How to check it works

1. Open `http://localhost:8080/healthz`. The response is `200 OK`.
2. Open `http://localhost:8080/readyz`. The response is `200 OK`.
3. Run this command to list the records:

```sh
curl -X POST http://localhost:8080/vca.issued.v1.IssuedService/List \
  -H 'Content-Type: application/json' -d '{}'
```

4. Run `GET http://localhost:8080/issued/chain-head`. The response is a compact JWS.
5. Run `GET http://localhost:8080/issued/jwks.json`. The response holds the public key of step 4.
6. Call `VerifyChain` with an empty request. The field `ok` is `true` and `checked` counts every entry.

```sh
curl -X POST http://localhost:8080/vca.issued.v1.IssuedService/VerifyChain \
  -H 'Content-Type: application/json' -d '{}'
```

## Reference

- ADR-017 in [`docs/adr.md`](../../docs/adr.md).
- The service document: [`docs/issued-credentials.md`](../../docs/issued-credentials.md).
- The API: [`proto/vca/issued/v1/issued.proto`](../../proto/vca/issued/v1/issued.proto).
- The hash chain: [`core/hashchain`](../../core/hashchain).
