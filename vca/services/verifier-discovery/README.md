# `verifier-discovery`

The verifier discovery service crawls the trusted issuers and lets staff build presentation requests by clicking claims.

## What it does

- It reads the trusted issuers from the trust registry, then fetches `/.well-known/openid-credential-issuer` and `/api/schemas` of each one.
- It caches every fetched document with a time to live and an entity tag, so a crawl costs little.
- It guards every fetch against server side request forgery. It accepts https only, an allowed host list, and public addresses only.
- It stores a presentation template as a DCQL query. It also generates a Presentation Exchange 2.0 definition for a Digital Public Good that needs the older language.
- It serves the same catalogue read only at `GET /catalog`, so a wallet reads what a verifier sees.
- It works with every DPG, because it reads standard metadata.
- It owns one directory: the state directory with the crawled issuers and the template versions.
- It follows these standards: [OpenID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html), [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html), [Presentation Exchange 2.0](https://identity.foundation/presentation-exchange/spec/v2.0.0/), and [VC JSON Schema](https://www.w3.org/TR/vc-json-schema/).

It does not check a presentation. The verifier policy service does that.

## How to run

Planned (ADR-007, ADR-008):

```sh
vca setup --role verifier --dpg waltid
vca deploy --role verifier --dpg waltid
```

Now:

```sh
cd services/verifier-discovery
VCA_DISCOVERY_TRUST_URL=http://localhost:8080 go run .
```

Configuration comes from environment variables. The table lists each one.

| Variable | Meaning | Default |
|---|---|---|
| `VCA_DISCOVERY_LISTEN` | The address the service listens on. | `:8090` |
| `VCA_DISCOVERY_BASE_URL` | The public root URL of the service. | `http://localhost:8090` |
| `VCA_DISCOVERY_STATE_DIR` | The directory of the catalogue and the templates. | empty: in memory |
| `VCA_DISCOVERY_TRUST_URL` | The base URL of the trust registry. | empty: the crawler is off |
| `VCA_DISCOVERY_TRUST_TIMEOUT` | The time limit of one trust registry call. | `10s` |
| `VCA_DISCOVERY_CRAWL_INTERVAL` | The time between two scheduled crawls. | `1h`, `0s` turns the job off |
| `VCA_DISCOVERY_CACHE_TTL` | How long a fetched document stays fresh. | `15m` |
| `VCA_DISCOVERY_FETCH_TIMEOUT` | The time limit of one issuer fetch. | `10s` |
| `VCA_DISCOVERY_MAX_DOCUMENT_BYTES` | The size limit of one fetched document. | `1048576` |
| `VCA_DISCOVERY_ALLOWED_HOSTS` | The host names the fetcher may reach, comma separated. An entry that starts with a dot matches the domain and every name below it. | empty: every public host |
| `VCA_DISCOVERY_ALLOW_PRIVATE_NETWORK` | Let the fetcher reach private and loopback addresses. Development only. | `false` |
| `VCA_DISCOVERY_ALLOW_PLAIN_HTTP` | Let the fetcher use `http`. Development only. | `false` |
| `VCA_DISCOVERY_PAGE_SIZE_MAX` | The maximum page size of every list RPC. | `50` |
| `VCA_DISCOVERY_CATALOG_MAX_AGE` | The `Cache-Control` max-age of `GET /catalog`. | `5m` |
| `VCA_DISCOVERY_PORTAL_PREFIX` | The URL prefix of the staff pages. | `/portal` |

The container image is `ghcr.io/centre-for-dpi/vca-verifier-discovery`. It listens on
one port and runs as a non-root user with a read-only file system.
Mount a volume at `/data` to keep the catalogue and the templates.

## How to check it works

1. Open `http://localhost:8090/healthz`. The response is `200 OK`.
2. Open `http://localhost:8090/readyz`. The response is `200 OK`.
3. Run a crawl:

```sh
curl -sS -X POST http://localhost:8090/vca.discovery.v1.DiscoveryService/Crawl \
  -H 'Content-Type: application/json' -d '{}'
```

4. Read the catalogue:

```sh
curl -sS http://localhost:8090/catalog/types | head
```

5. Open `http://localhost:8090/portal/`. The page lists the trusted issuers.
6. Open a credential type, tick the claims, and save the template. The
   template page then shows the DCQL query and the Presentation Exchange
   2.0 definition.

## Reference

| Item | Value |
|---|---|
| Service | `vca.discovery.v1.DiscoveryService` |
| Proto | [`proto/vca/discovery/v1/discovery.proto`](../../proto/vca/discovery/v1/discovery.proto) |
| Service document | [`docs/verifier-discovery.md`](../../docs/verifier-discovery.md) |
| ADR | ADR-022 decisions 1 to 5 |
| Catalogue endpoints | `GET /catalog`, `GET /catalog/issuers`, `GET /catalog/types` |
| Pages | `GET /portal/`, `GET /portal/types`, `GET /portal/fields`, `GET /portal/templates` |
| Health | `GET /healthz`, `GET /readyz` |
