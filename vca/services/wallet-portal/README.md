# `wallet-portal`

The wallet portal is the citizen web wallet: discover, claim, view, present, and delete credentials (ADR-021).

## What it does

- It lists the credentials that issuers publish. The list comes from the catalogue of the `verifier-discovery` service.
- It lists the credentials the logged in citizen can get. An eligibility hook answers yes or no per schema and nothing more.
- It claims, scans, pastes, accepts, rejects, and deletes credentials. Every one of these actions goes to the holder backend of the DPG.
- It keeps the credentials in the DPG wallet when the deployment names one adapter. Without an adapter the browser keeps them: the server holds ciphertext only.
- It answers a presentation request with OpenID for Verifiable Presentations 1.0. A consent screen lists every claim before the citizen agrees.
- It shows the issuer trust status, the validity window, and the withdrawal state of every credential in plain language.
- Every page passes the structural WCAG 2.2 AA assertions of `ui/a11ytest`.

It issues no credential and signs no credential. The DPG does that.

## How to run

```sh
cd services/wallet-portal
VCA_WALLET_PORTAL_AUTH_JWKS_URL=http://localhost:8091/.well-known/jwks.json \
VCA_WALLET_PORTAL_DISCOVERY_URL=http://localhost:8085 \
VCA_WALLET_PORTAL_REQUEST_HOSTS=verifier.example go run .
```

Configuration comes from environment variables. The table lists each one.

| Variable | Meaning | Default |
|---|---|---|
| `VCA_WALLET_PORTAL_LISTEN` | The address the service listens on. | `:8092` |
| `VCA_WALLET_PORTAL_STATE_DIR` | The directory of the pending records and the ciphertext blobs. | empty: in memory |
| `VCA_WALLET_PORTAL_PORTAL_PREFIX` | The URL prefix of the citizen pages. | `/wallet` |
| `VCA_WALLET_PORTAL_LOGIN_URL` | The login page of the wallet authentication service. | empty: answer 401 |
| `VCA_WALLET_PORTAL_AUTH_JWKS_URL` | The JWKS URL of the wallet authentication service. | empty |
| `VCA_WALLET_PORTAL_AUTH_JWKS_FILE` | A JWKS file. It replaces the JWKS URL. | empty |
| `VCA_WALLET_PORTAL_AUTH_JWKS_TTL` | How long the service keeps a fetched key set. | `10m` |
| `VCA_WALLET_PORTAL_AUTH_ISSUER` | The issuer a session token must name. | empty: any issuer |
| `VCA_WALLET_PORTAL_CSRF_KEY` | The key of the page tokens. It needs 16 bytes or more. | empty: a random key |
| `VCA_WALLET_PORTAL_DPG` | The adapter name that holds the credentials. | empty: browser storage |
| `VCA_WALLET_PORTAL_DPG_ADAPTERS` | The adapter base URLs, as `name=url` items. | empty |
| `VCA_WALLET_PORTAL_DPG_TIMEOUT` | The time limit of one adapter call. | `30s` |
| `VCA_WALLET_PORTAL_DISCOVERY_URL` | The base URL of the verifier discovery service. | empty: no catalogue |
| `VCA_WALLET_PORTAL_TRUST_URL` | The base URL of the trust registry service. | empty: trust not checked |
| `VCA_WALLET_PORTAL_ELIGIBILITY_URL` | The URL of the eligibility hook. | empty: the default answer |
| `VCA_WALLET_PORTAL_ELIGIBILITY_DEFAULT` | The answer when no hook exists. | `false` |
| `VCA_WALLET_PORTAL_ELIGIBILITY_SALT` | The salt of the subject reference the hook reads. | empty |
| `VCA_WALLET_PORTAL_REQUEST_HOSTS` | The host allowlist of a presentation request URI. | empty: block every URI |
| `VCA_WALLET_PORTAL_FETCH_TIMEOUT` | The time limit of one outbound fetch. | `10s` |
| `VCA_WALLET_PORTAL_FETCH_MAX_BYTES` | The size limit of one outbound fetch. | `1048576` |
| `VCA_WALLET_PORTAL_STATUS_TTL` | How long the service keeps a status list. | `5m` |
| `VCA_WALLET_PORTAL_STATUS_CACHE_MAX` | The number of status lists the cache holds. | `64` |
| `VCA_WALLET_PORTAL_MAX_PASTE_BYTES` | The size limit of a scanned or pasted text. | `65536` |
| `VCA_WALLET_PORTAL_MAX_BLOB_BYTES` | The size limit of one ciphertext blob. | `262144` |
| `VCA_WALLET_PORTAL_PENDING_TTL` | How long an offer or a request stays readable. | `15m` |
| `VCA_WALLET_PORTAL_PAGE_SIZE_MAX` | The maximum page size of a list RPC. | `50` |
| `VCA_WALLET_PORTAL_CLIENT_ID` | The client id of the wallet at the authorization server of an issuer. | `vca-wallet` |
| `VCA_WALLET_PORTAL_CRAWL_TTL` | How long the service keeps the issuer metadata it reads with no discovery service. | `5m` |
| `VCA_WALLET_PORTAL_CRAWL_ALLOWED_HOSTS` | The hosts of the trusted issuers the service reads. | empty: every public host |
| `VCA_WALLET_PORTAL_CRAWL_ALLOW_PRIVATE_NETWORK` | Read a trusted issuer at a private address. For development only. | `false` |
| `VCA_WALLET_PORTAL_CRAWL_ALLOW_PLAIN_HTTP` | Read a trusted issuer over http. For development only. | `false` |
| `VCA_PEERS` | The candidate pairs of the deployment. The CLI writes it. | empty: no stack switcher |

The container image is `ghcr.io/centre-for-dpi/vca-wallet-portal`. It listens on one port and runs as a non-root user with a read-only file system. Mount a volume at `/data` to keep the pending records and the blobs across a restart.

## How to check it works

1. Open `http://localhost:8092/healthz`. The response is `200 OK`.
2. Open `http://localhost:8092/readyz`. The response is `200 OK`.
3. Log in through the `wallet-auth` service. The browser gets the session cookie `vca_wallet_session`.
4. Open `http://localhost:8092/wallet/discover`. The table lists the credentials issuers publish.
5. Open `http://localhost:8092/wallet/discover?claim=1`. The claim card shows the ways the issuer allows.
6. Open `http://localhost:8092/wallet/claim`. Paste a credential offer and its transaction code. The wallet claims it.
7. Open `http://localhost:8092/wallet/`. Each card shows the trust badge, the state badge, and the fields.
8. Paste a presentation request on the claim page. The consent screen lists every field before you send it.
9. Run this command to read the catalogue over the API:

```sh
curl -s -X POST http://localhost:8092/vca.walletportal.v1.WalletPortalService/ListDiscoverable \
  -H 'Content-Type: application/json' -H "Authorization: Bearer $SESSION" -d '{}'
```

## Reference

- [ADR-021 and ADR-020](../../../ADR.md) for the decisions this service implements.
- [docs/wallet-portal.md](../../docs/wallet-portal.md) for the flows and the browser storage format.
- [proto/vca/walletportal/v1/walletportal.proto](../../proto/vca/walletportal/v1/walletportal.proto) for the API.
