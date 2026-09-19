# How to deploy the Verifiable Credentials Adapters

One role plus one digital public good is one deployment.
The whole stack is the four roles together.
This page covers Docker Compose and Kubernetes (ADR-008).

## What it does

- `deploy/vca/compose.yaml` holds one profile per role and DPG pair.
- `deploy/vca/dpg/*.yaml` hold the DPG stacks, pinned to one version each.
- `deploy/vca/helm/*` hold one chart per service and one umbrella chart.
- `deploy/<role>-<dpg>/` holds the files that `vca setup` wrote.

## How to run

### Step 1: set up the role

```sh
go build -o vca ./cmd/vca
./vca setup --role issuer --dpg waltid
```

The command writes `deploy/issuer-waltid/.env` and the DPG configuration.
See `docs/cli.md` for the questions and the order of the sources.

### Step 2: start the containers

```sh
./vca deploy --role issuer --dpg waltid
```

That runs this command for you:

```sh
docker compose --project-name vca \
  --file deploy/vca/compose.yaml \
  --env-file deploy/issuer-waltid/.env \
  --profile issuer-waltid up -d
```

Add `--all` to start every role of one DPG.
Add `--dry-run` to print the rendered file and the commands.

### Step 3: configure the DPG

```sh
./vca dpg bootstrap waltid --role issuer
```

The command calls the DPG HTTP API. It runs again with no harm.

### Step 4: check the deployment

```sh
./vca status --role issuer --dpg waltid
```

Stop it with `./vca down --role issuer --dpg waltid`.
The volumes stay, so the data survives.

## The compose file

`vca/internal/cli/compose.go` renders `deploy/vca/compose.yaml`.
A Go test fails when the committed file and the renderer differ.
To write the file again:

```sh
VCA_WRITE_COMPOSE=1 go test -run TestComposeFileIsCurrent ./internal/cli/
```

### Profiles

One profile exists per role and DPG pair.
The names are `issuer-waltid`, `holder-inji`, `admin-credebl`, and so on.
Compose starts only the services of the profile you name
(ADR-008 decisions 1 and 2).

### Ports

Several services share a port in their `EXPOSE` line.
The CLI gives each service of a pair its own listen port.
It also gives each service its own host port, so two pairs never collide.
The `.env` file of the pair carries both numbers:

| Variable | What it holds |
|---|---|
| `VCA_<SERVICE>_LISTEN` | The listen address inside the container. |
| `VCA_PORTS_PORTAL` | The port of the role portal. |
| `VCA_PORTS_AUTH` | The port of the auth service. |
| `VCA_PORTS_ADAPTER` | The port of the DPG adapter. |
| `VCA_PORTS_<SERVICE>` | The port of every other service, from 8100 up. |
| `VCA_HOST_PORT_<SERVICE>` | The port on the machine that runs compose. |

### Service links

Some services need the URL of another service.
The CLI reads the port plan and writes each URL into the .env file:

| Variable | What it points at |
|---|---|
| `VCA_WALLET_PORTAL_AUTH_JWKS_URL` | The JWKS of the wallet auth service. |
| `VCA_WALLET_PORTAL_LOGIN_URL` | The login page of the wallet auth service. |
| `VCA_WALLET_PORTAL_DISCOVERY_URL` | The verifier discovery service. |
| `VCA_WALLET_PORTAL_TRUST_URL` | The trust registry service. |
| `VCA_WALLET_PORTAL_DPG_ADAPTERS` | The DPG adapter of the pair. |
| `VCA_ADMIN_PUBLIC_URL` | The public base URL of the deployment. |
| `VCA_ADMIN_TRUST_URL` | The trust registry service. |
| `VCA_ADMIN_SERVICES` | Every other service of the same DPG, for the health page. |

A link can name a service of another role.
The container names carry the pair, for example
`verifier-waltid-verifier-discovery`.
Every profile joins the same `vca` network, so one role reaches another
role of the same DPG.
Start the other role, or edit the value by hand.

Each role and DPG pair owns a block of one hundred host ports.
The first block starts at 18000.

### Hardening

Every VCA service in the compose file:

- runs with a read only root file system,
- runs as the non-root user 65532,
- drops every Linux `cap_drop` entry and sets `no-new-privileges`,
- mounts no Docker socket and restarts no other container.

Those four rules come from ADR-005 decisions 2 and 3.

## The DPG stacks

`deploy/vca/compose.yaml` pulls in the DPG files with `include`
(ADR-008 decision 3).
The versions come from `verifiably-go/docs/dpg-matrix.md`:

| File | What it holds | Version |
|---|---|---|
| `dpg/waltid.yaml` | Issuer API, verifier API, wallet API | 0.18.2 |
| `dpg/inji.yaml` | Inji Certify | 0.14.0 |
| `dpg/inji.yaml` | Inji Web and Mimoto | 0.16.0 and 0.21.0 |
| `dpg/inji.yaml` | Inji Verify UI and service | 0.16.0 |
| `dpg/inji.yaml` | eSignet and mock identity | 1.5.1 and 0.10.1 |
| `dpg/credebl.yaml` | API gateway and agent provisioning | `CREDEBL_VERSION` |
| `dpg/inji.yaml` and `dpg/credebl.yaml` | Keycloak | 25.0 |

CREDEBL publishes no version tag.
The DPG matrix records `ghcr.io/credebl/*:latest`.
The compose file reads the tag from `CREDEBL_VERSION`.
Set it to a digest before you go to production.

A VCA service never needs a DPG rebuild.
A DPG upgrade is a version change in one file.

## The resource floor

One role with one DPG stays under 4 GB of memory (ADR-008 decision 7).
The whole legacy stack needed 8 GB to 12 GB and about 25 ports.

| Role and DPG | VCA services | VCA memory | DPG memory | Total memory | CPUs |
|---|---|---|---|---|---|
| `issuer-waltid` | 9 | 864 MiB | 1536 MiB | 2400 MiB | 3.25 |
| `issuer-inji` | 9 | 864 MiB | 2560 MiB | 3424 MiB | 3.25 |
| `issuer-credebl` | 9 | 864 MiB | 2560 MiB | 3424 MiB | 3.25 |
| `holder-waltid` | 3 | 288 MiB | 1536 MiB | 1824 MiB | 1.75 |
| `holder-inji` | 3 | 288 MiB | 2560 MiB | 2848 MiB | 1.75 |
| `holder-credebl` | 3 | 288 MiB | 2560 MiB | 2848 MiB | 1.75 |
| `verifier-waltid` | 6 | 576 MiB | 1536 MiB | 2112 MiB | 2.5 |
| `verifier-inji` | 6 | 576 MiB | 2560 MiB | 3136 MiB | 2.5 |
| `verifier-credebl` | 6 | 576 MiB | 2560 MiB | 3136 MiB | 2.5 |
| `admin-waltid` | 2 | 192 MiB | 256 MiB | 448 MiB | 1.5 |
| `admin-inji` | 2 | 192 MiB | 256 MiB | 448 MiB | 1.5 |
| `admin-credebl` | 2 | 192 MiB | 256 MiB | 448 MiB | 1.5 |

The VCA figure is 96 MiB per service.
The admin role runs the admin service and the trust registry.
The holder role runs the wallet portal, the wallet auth service, and one
DPG adapter.
Each service is one static Go binary in a distroless image.
The DPG figure is the floor of the stack in `deploy/vca/dpg/`.
The admin role talks to no DPG, so it needs only its own database.

## Kubernetes

One chart per service lives in `deploy/vca/helm/<service>`.
Each chart holds a Deployment, a Service, and a ConfigMap.
The pod reads its secrets from the Secret that `existingSecret` names.
The probes are `/healthz` and `/readyz`.
The container runs as a non-root user.
Nothing can write to its root file system.
It drops every `cap_drop` entry and it forbids privilege escalation.

The umbrella chart is `deploy/vca/helm/vca`.
Turn one role on and pick its DPG adapter:

```sh
helm upgrade --install vca deploy/vca/helm/vca \
  --set roles.issuer.enabled=true \
  --set dpg.waltid.enabled=true
```

Check the charts:

```sh
helm lint deploy/vca/helm/issuance
helm template test deploy/vca/helm/vca --set roles.admin.enabled=true
go test -run TestHelm ./internal/cli/
```

The Go test checks every chart against the service catalog.
It runs `helm lint` and `helm template` when helm is on the path.
The packaged dependencies of the umbrella chart sit in
`deploy/vca/helm/vca/charts/`, so helm needs no network.
After you change a service chart, package the dependencies again:

```sh
cd deploy/vca/helm/vca && helm dependency build
```

`vca/hack/k8s-smoke.sh` lints, renders, and installs every chart into a
kind cluster (ADR-006 decision 7).

## How to check it works

```sh
go run ./cmd/vca deploy --role issuer --dpg waltid --dry-run
docker compose --file deploy/vca/compose.yaml config --profile issuer-waltid
go test ./internal/cli/
```

## Reference

- ADR-005: one image per service, non-root, read only, no Docker socket.
- ADR-007: the setup CLI and the files it writes.
- ADR-008: the profiles, the DPG includes, the bootstrap, and the charts.
- `verifiably-go/docs/dpg-matrix.md`: the DPG versions.
- [Compose profiles](https://docs.docker.com/compose/how-tos/profiles/)
- [Helm charts](https://helm.sh/docs/topics/charts/)
