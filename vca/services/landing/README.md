# `landing`

The landing is the front door of a VCA deployment. It runs once per deployment and serves every role.

## What it does

- It explains what VCA is in short text: the Digital Public Goods, the verifiable credential, and the triangle of trust. Links go deeper.
- It lists the stacks that run on this deployment, with their components, pinned versions, and links to the repository and the documentation of each. The data comes from the `GetCapabilities` answer of each live DPG adapter, so no vendor name lives in this service.
- It shows only what runs. It probes every candidate pair of `VCA_PEERS`, hides an absent pair, marks a pair that resolves but is not ready as `Starting`, and calls a ready pair `Live` (ADR-034).
- It offers a role picker with the live roles only. With one live role it sends the browser to that role.
- It shows one intro page per role with step cards for the live features, then a sign in action on the pair of the role.
- It keeps no state. It is one static Go binary in a distroless image.

## How to run

```sh
vca setup --role issuer --dpg waltid
vca deploy --role issuer --dpg waltid
```

Every pair profile starts the one `vca-landing` container. It reads `deploy/landing/.env`, which `vca setup` writes. On a laptop it answers at `http://localhost:17900`. Under a base domain it answers at `https://vca.<domain>`.

By hand:

```sh
cd services/landing
VCA_PEERS='issuer-waltid|http://localhost:18006|schema-registry=http://localhost:8080,dpg-adapter-waltid=http://localhost:8090' go run .
```

Configuration comes from environment variables. The table lists each one.

| Variable | Meaning | Default |
|---|---|---|
| `VCA_LANDING_LISTEN` | The address the service listens on. | `:8080` |
| `VCA_LANDING_PUBLIC_URL` | The address a browser opens for the landing. | empty |
| `VCA_LANDING_PROBE_TIMEOUT` | The time one peer probe may take. | `1s` |
| `VCA_LANDING_PROBE_TTL` | The life of one probe result. | `15s` |
| `VCA_LANDING_REPOSITORY_URL` | The source repository the page links to. | The VCA repository |
| `VCA_LANDING_DOCS_URL` | The documentation the page links to. | The VCA docs folder |
| `VCA_PEERS` | Every candidate pair of the deployment, as `vca setup` writes it (ADR-034). | empty: no pair |
| `VCA_VERSION` | The image version the page and the descriptor show. | `latest` |
| `VCA_THEME_FILE` | The theme file of the deployment (ADR-032). | empty: the embedded default |

The container image is `ghcr.io/centre-for-dpi/vca-landing`. It listens on one port and runs as a non-root user with a read-only file system.

## How to check it works

1. Start the service as above.
2. Open `http://localhost:8080/healthz`. The response is `200 OK`.
3. Open `http://localhost:8080/readyz`. The response is `200 OK`.
4. Run `go test ./services/landing/...` from `vca/`. Every test passes.

## Reference

- ADR-033 and ADR-034 in [`docs/adr.md`](../../docs/adr.md).
- The peer package: [`internal/topology`](../../internal/topology).
- The UI kit: [`docs/ui.md`](../../docs/ui.md).
