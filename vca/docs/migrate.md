# Data migration from verifiably-go

`vca migrate` carries the data of a legacy verifiably-go deployment into the
services (ADR-030 decision 8).
It moves three things: the issued credential log, the status lists, and the
trust registry.
The source is `vca/internal/migrate` and `vca/internal/cli/migrate.go`.

## What it does

- `vca migrate export` reads one legacy deployment and writes import files.
- `vca migrate import` writes the import files into a service state directory.

Every transform is a pure function.
The export never writes into the legacy database.
The export opens the legacy database read only through `database/sql`.

## What is not migrated

- Sessions. Each operator and each holder signs in again after the cutover.
- Caches. The status list cache and the schema cache fill again by themselves.
- Bulk jobs. A job that did not finish must run again.
- Verification events. The new verifier services keep their own results.
- API keys and the verifier API key of a trust entry. Each is a secret.
  Issue a new key in the admin service after the cutover.
- Signing keys of the legacy status lists. Each status service holds its own
  key ring, so it signs a migrated list with its own key.

## Sources

### A state directory

```sh
vca migrate export --from-state-dir ./state --out ./migration --salt "$SALT"
```

The command reads these files under the state directory:

| File | What it holds |
|---|---|
| `issued-credentials.json` | The legacy issuance log with its hash chain. |
| `status-list-<id>.json` | One status list with its bits and its counter. |
| `trusted-issuers.json` | An optional trust registry export. |

The legacy file mode keeps no trust registry, so `trusted-issuers.json` exists
only when an operator wrote it.
The file holds the JSON array of `internal/trust` entries.
A state directory file whose id ends in `-key` holds a signing key, so the
export skips it.
An id that holds the word `token` names an IETF Token Status List.
Every other id names a W3C Bitstring Status List.

### A PostgreSQL database

```sh
vca migrate export --from-pg "postgres://user:pass@host/db" \
  --out ./migration --salt "$SALT"
```

The command reads three tables: `issued_credentials`, `status_lists`, and
`trusted_issuers`.
It reads no other table.
It needs a `database/sql` driver with the name of `--pg-driver`, and
`postgres` is the default name.
The released `vca` binary links no PostgreSQL driver.
Use one of these two ways:

1. Export the legacy state to a state directory and use `--from-state-dir`.
2. Build a `vca` binary that imports a driver, for example
   `github.com/jackc/pgx/v5/stdlib`, then run the export with that binary.

## The subject salt

The issued credential records hold no holder identifier (ADR-017 decision 2).
Each record holds an HMAC-SHA256 of the subject with a deployment salt.
The export needs that salt:

- `--salt <value>` names it on the command line.
- `--salt-file <path>` reads it from a file.
- `VCA_ISSUED_SALT` holds it in the environment.

Give the same salt to the issued-credentials service in
`VCA_ISSUED_SALT`.
A different salt makes every reference different, so a search by subject
finds nothing.

The export takes the legacy subject from the first value that is not empty:
the `id` subject field, the holder hint, the owner key, then the credential id.

## Subject claims

The legacy log holds every issued claim.
The export keeps no claim by default.
Name each claim to keep as a searchable claim:

```sh
vca migrate export --from-state-dir ./state --out ./migration \
  --salt "$SALT" --keep-claim fullName --keep-claim licenceNumber
```

Keep the shortest list that the operator list page needs.

## What the export writes

| File | Service | Setting |
|---|---|---|
| `issued-credentials.json` | issued-credentials | `VCA_ISSUED_STORE_FILE` |
| `trust-registry.json` | trust-registry | `VCA_TRUST_STORE_FILE` |
| `status-bitstring/lists/<id>.json` | status-bitstring | `VCA_STATUS_BITSTRING_STATE_DIR` |
| `status-token/lists/<id>.json` | status-token | `VCA_STATUS_TOKEN_STATE_DIR` |

The export refuses to replace a file that exists. Add `--force` to replace it.

### The issued credential log

The export writes one issue event per credential, in the order of the legacy
log.
It then writes one status event per revoked credential, oldest first.
The export builds the hash chain again over the new events.
The head then proves that no event went missing (ADR-017 decisions 1 and 4).
The legacy chain covered other fields, so the new hashes differ from the old
hashes.

Each record keeps its id, its schema, its format, its DPG, and its issuance
time.
Each record keeps the status list binding: the kind, the list id, and the
index.
Add `--status-base-url https://status.example` to write the publish URL of
each binding.

### The status lists

The bit array of each list moves byte for byte.
The bitstring service and the token service each keep their own bit order, and
each order matches the legacy order.
The legacy allocator gave out the indices 0 to `nextFree - 1`, so the export
marks those indices allocated.
Every other index stays free, so a new credential never takes an index that a
legacy credential holds.

The migrated list has no signature yet.
The status service signs it with its own key on the first request.

### The trust registry

Each legacy issuer becomes one entry with the role `issuer` and the status
`active`.
The accreditation time becomes `valid_from`.
The schemas become the credential types.
The status list policy of the legacy hub has no field in the new registry, so
the export drops it.

## The import

```sh
vca migrate import --from ./migration --into /var/lib/vca
```

The command reads every document first, so a broken export writes nothing.
It writes the files in the layout above.
It refuses to replace a file that exists. Add `--force` to replace it.

Point each service at its file or its directory:

```sh
VCA_ISSUED_STORE_FILE=/var/lib/vca/issued-credentials.json
VCA_ISSUED_SALT=$SALT
VCA_TRUST_STORE_FILE=/var/lib/vca/trust-registry.json
VCA_STATUS_BITSTRING_STATE_DIR=/var/lib/vca/status-bitstring
VCA_STATUS_TOKEN_STATE_DIR=/var/lib/vca/status-token
```

Stop each service before the import. Start it again after the import.

## The order of a cutover

1. Stop the legacy deployment, or stop its issuance.
2. Copy the legacy state directory, or take a database dump.
3. Run `vca migrate export` against the copy.
4. Read the counts the export prints. Compare them with the legacy counts.
5. Run `vca migrate import` into the state directory of the services.
6. Start the services and check `/healthz` and `/readyz`.
7. Check one migrated credential: read it in the issued-credentials service,
   then fetch its status list.
8. Revoke one test credential and fetch the list again.

## How to check it works

Run the tests of both packages:

```sh
go test ./internal/migrate/ ./internal/cli/
```

Export a state directory and read the counts:

```sh
go run ./cmd/vca migrate export --from-state-dir ./state \
  --out /tmp/migration --salt test-salt
```

## Reference

- ADR-030 decision 8: the data migration and what it leaves behind.
- ADR-017: the issued credential log, its hash chain, and its subject
  reference.
- ADR-018 and ADR-019: the status list records and their allocation.
- ADR-011: the trust registry entry.
- `docs/issued-credentials.md`: the log service.
- `docs/status-bitstring.md` and `docs/status-token.md`: the status services.
- `docs/trust-registry.md`: the trust registry service.
