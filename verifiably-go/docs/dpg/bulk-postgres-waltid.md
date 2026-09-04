# walt.id — "Bulk from PostgreSQL"

> **DPG:** walt.id (`walt_community`). **Bulk source key:** `db` (declared in `scripts/gen-backends.sh`, walt.id stanza).
> **Connector:** `queryDBRows` in `internal/handlers/bulk.go` — a read-only pgx connection; only statements whose first token is `SELECT` are accepted; a 15 s query timeout applies.

walt.id already declares the `db` bulk source, so the chip renders and works with any Postgres the
verifiably-go container can reach. This page is the operator recipe for the repo's demo database.

## 1. Demo database (config only, no code)

The fixture in `testdata/bulk-issuance/docker-compose.yml` brings up a seeded Postgres 16
(`ministry-citizens-db`, 201 synthetic citizens from `deploy/compose/stack/citizens-db/init.sql`,
published on host port **5437**) plus a small JSON API (`ministry-citizens-service`, host port **8199**).
The compose file joins both containers to the external network **`waltid_default`** (the compose
project name of the main stack), so the verifiably-go container reaches them by **container name**:

```bash
cd verifiably-go/testdata/bulk-issuance && docker compose up -d
# (the compose already attaches to waltid_default; if it was created before the main stack, re-attach:)
docker network connect waltid_default ministry-citizens-db      2>/dev/null || true
docker network connect waltid_default ministry-citizens-service 2>/dev/null || true
docker exec ministry-citizens-db psql -U citizens -c 'SELECT count(*) FROM citizens'   # → 201
```

## 2. What to type in the UI

Issuer → walt.id DPG → pick a schema → **Bulk** → **Bulk from PostgreSQL**.

| Field | Value |
|---|---|
| Postgres connection string | `postgres://citizens:citizens@ministry-citizens-db:5432/citizens?sslmode=disable` (same host, verifiably-go in Docker) |
| | `postgres://citizens:citizens@localhost:5437/citizens?sslmode=disable` (verifiably-go run on bare metal with `go run`) |
| SELECT query | one of the paste-ready recipes in `testdata/bulk-issuance/db/queries.sql`, e.g. below |

DSN pattern: `postgres://<user>:<pass>@<container>:5432/<db>?sslmode=disable` — `<container>` is the
Postgres container's name on the shared Docker network (host port publication is only for humans).

Sample SELECT (works with any schema that has a `holder`-like field; the column aliases become the
source columns you map to credential fields in the next step):

```sql
SELECT
  first_name || ' ' || last_name AS holder
FROM citizens
ORDER BY id
LIMIT 20;
```

**Expected:** "db — 20 rows · map columns → fields", one column `holder`; **Issue 20 credentials →**
renders 20 offer URIs/QR codes. The `VerifiableId` recipe in `queries.sql` (`WHERE address IS NOT NULL … LIMIT 15`)
yields 15 rows with the eight walt.id VerifiableId field names pre-mapped by exact name.

## 3. Failure messages you may see

| Message | Cause |
|---|---|
| `Connection string and SELECT query are both required.` | a field is empty |
| `Fetch failed: only SELECT queries allowed` | first token of the query is not `SELECT` |
| `Fetch failed: failed to connect …` | DSN unreachable from the container (wrong host, not on `waltid_default`) |
| `Fetch failed: query returned 0 rows` | the WHERE clause matched nothing |

Tests: `TestBulkPreview_DB_WaltID` (`internal/handlers/bulk_test.go`) and `TestQueryDBRows_FailsBeforeConnecting`;
the walt.id capability list is pinned by `scripts/ci/test-gen-backends.sh`.
