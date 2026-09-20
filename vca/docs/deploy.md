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

New to the project? Read [Get started](getting-started.md) first.
It lists the prerequisites and the three ways to get the `vca` binary.

### Step 0: check the host

```sh
vca doctor --role <role> --dpg <dpg>
```

`<dpg>` is one of `waltid`, `inji`, `credebl`; the three are equal.
`<role>` is one of `issuer`, `holder`, `verifier`, `admin`.
Leave either flag out and the command asks for it with a numbered menu.
A run that is not a terminal, or that passes `--non-interactive`, fails
and names the missing flag.

The command prints one line per prerequisite with a pass or a fail.
It checks Docker, the compose plugin, the free memory, the host ports,
and the public URL. It exits with status 1 on any fail.
`vca doctor --suggest` prints the selection that fits the free memory.

### Step 1: set up the role

```sh
cd vca && go mod tidy && go build -o vca ./cmd/vca
./vca setup --role <role> --dpg <dpg>
```

The command writes `deploy/<role>-<dpg>/.env` and the DPG configuration.
See `docs/cli.md` for the questions and the order of the sources.

### Step 2: start the containers

```sh
./vca deploy --role <role> --dpg <dpg>
```

That runs this command for you:

```sh
docker compose --project-name vca \
  --file deploy/vca/compose.yaml \
  --env-file deploy/<role>-<dpg>/.env \
  --profile <role>-<dpg> up -d
```

Add `--all` to start every role of every DPG. Add `--all --dpg <dpg>` to start every role of one DPG.
Add `--dry-run` to print the rendered file and the commands.
Add `--build` before the first release. See "Images from source".

### Step 3: configure the DPG

```sh
./vca dpg bootstrap <dpg> --role <role>
```

The command calls the DPG HTTP API. It runs again with no harm.

### Step 4: check the deployment

```sh
./vca status --role <role> --dpg <dpg>
```

Stop it with `./vca down --role <role> --dpg <dpg>`.
The volumes stay, so the data survives.

## The compose file

`vca/internal/cli/compose.go` renders `deploy/vca/compose.yaml`.
A Go test fails when the committed file and the renderer differ.
To write the file again:

```sh
VCA_WRITE_COMPOSE=1 go test -run TestComposeFileIsCurrent ./internal/cli/
```

### Images from source

The compose file names the image
`ghcr.io/centre-for-dpi/vca-<service>:${VCA_VERSION:-latest}`.
No release has published those images yet, so a plain `vca deploy` fails
with `pull access denied`.
Build the images from the source in this repository instead:

```sh
vca deploy --role <role> --dpg <dpg> --build
```

That adds a second file to the compose command:

```sh
docker compose --project-name vca \
  --file deploy/vca/compose.yaml \
  --file deploy/vca/compose.build.yaml \
  --env-file deploy/<role>-<dpg>/.env \
  --profile <role>-<dpg> up -d --build
```

The repository holds `deploy/vca/compose.build.yaml`.
The renderer in `vca/internal/cli/build.go` writes it, and a Go test
fails when the committed file and the renderer differ.
Each service gets `context: ../../vca` and
`dockerfile: services/<name>/Dockerfile`.

To build the images without compose:

```sh
vca images build --role <role> --dpg <dpg>
```

Each image gets the tag `local`.
The command then sets `VCA_VERSION=local` in the `.env` file of the pair,
so the next `vca deploy` starts the local images.
After the first tagged release, drop `--build` and set `VCA_VERSION` to
the release tag.

### Profiles

One profile exists per role and DPG pair.
The name is `<role>-<dpg>`, so the twelve names run from `issuer-waltid`
to `admin-credebl`.
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
The container names carry the pair, as in
`verifier-<dpg>-verifier-discovery`.
Every profile joins the same `vca` network, so one role reaches another
role of the same DPG.
Start the other role, or edit the value by hand.

Each role and DPG pair owns a block of one hundred host ports.
The first block starts at 18000.
`vca ports --role <role> --dpg <dpg>` prints the ports of one pair.
`vca doctor` checks that each one is free.

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
| Every `dpg/*.yaml` file | Keycloak | 25.0 |

CREDEBL publishes no version tag.
The DPG matrix records `ghcr.io/credebl/*:latest`.
The compose file reads the tag from `CREDEBL_VERSION`.
Set it to a digest before you go to production.

A VCA service never needs a DPG rebuild.
A DPG upgrade is a version change in one file.

### The identity provider

Every stack ships Keycloak 25.0.
A laptop deployment then needs no other identity provider.
`vca setup` fills `VCA_OIDC_DISCOVERY_URL` with the Keycloak of the
stack, on the compose network:

| DPG | Keycloak container | Host port | Default `VCA_OIDC_DISCOVERY_URL` |
|---|---|---|---|
| `waltid` | `waltid-keycloak` | 17010 | `http://waltid-keycloak:8080/realms/vca/.well-known/openid-configuration` |
| `inji` | `inji-keycloak` | 17080 | `http://inji-keycloak:8080/realms/vca/.well-known/openid-configuration` |
| `credebl` | `credebl-keycloak` | 17180 | `http://credebl-keycloak:8080/realms/vca/.well-known/openid-configuration` |

A browser cannot reach a container name, so `VCA_OIDC_PUBLIC_URL` points
at `http://localhost` with the host port of the table.
The login page opens there.
`vca doctor` checks that the host port is free.

`vca setup` writes `deploy/<role>-<dpg>/keycloak-realm.json`.
The realm is `vca`.
It holds one client with the id `vca-<role>`, a generated client secret,
the authorization code flow, and PKCE.
Keycloak imports the file on its first start.
It reads the directory of the issuer pair of the stack.
Set `WALTID_REALM_DIR`, `INJI_REALM_DIR`, or `CREDEBL_REALM_DIR` to
another pair directory when you run one other role alone.

A production deployment replaces this Keycloak with the national
identity provider.
Set `VCA_OIDC_DISCOVERY_URL`, `VCA_OIDC_CLIENT_ID`, and
`VCA_OIDC_CLIENT_SECRET` to the values of that provider.
Register the redirect URI of `VCA_OIDC_REDIRECT_URI` there.

### The DPG API URL

`vca setup` fills `VCA_DPG_URL` from the role and the DPG.
The value is the container URL of the DPG API on the `vca` network:

| Role and DPG | Default `VCA_DPG_URL` |
|---|---|
| `issuer-waltid` | `http://waltid-issuer-api:7002` |
| `issuer-inji` | `http://inji-certify:8090` |
| `issuer-credebl` | `http://credebl-api-gateway:5000` |
| `holder-waltid` | `http://waltid-wallet-api:7001` |
| `holder-inji` | `http://inji-web:3000` |
| `holder-credebl` | `http://credebl-api-gateway:5000` |
| `verifier-waltid` | `http://waltid-verifier-api:7003` |
| `verifier-inji` | `http://inji-verify-service:8000` |
| `verifier-credebl` | `http://credebl-api-gateway:5000` |

The admin role calls no DPG, so it has no default.
Set `VCA_DPG_URL` yourself when the DPG runs on another host.
Your value always wins over the default.

## The resource floor

One role with one DPG stays under 4 GB of memory (ADR-008 decision 7).
The whole legacy stack needed 8 GB to 12 GB and about 25 ports.

| Role and DPG | VCA services | VCA memory | DPG memory | Total memory | CPUs |
|---|---|---|---|---|---|
| `issuer-waltid` | 9 | 864 MiB | 2048 MiB | 2912 MiB | 3.25 |
| `issuer-inji` | 9 | 864 MiB | 2560 MiB | 3424 MiB | 3.25 |
| `issuer-credebl` | 9 | 864 MiB | 2560 MiB | 3424 MiB | 3.25 |
| `holder-waltid` | 3 | 288 MiB | 2048 MiB | 2336 MiB | 1.75 |
| `holder-inji` | 3 | 288 MiB | 2560 MiB | 2848 MiB | 1.75 |
| `holder-credebl` | 3 | 288 MiB | 2560 MiB | 2848 MiB | 1.75 |
| `verifier-waltid` | 6 | 576 MiB | 2048 MiB | 2624 MiB | 2.5 |
| `verifier-inji` | 6 | 576 MiB | 2560 MiB | 3136 MiB | 2.5 |
| `verifier-credebl` | 6 | 576 MiB | 2560 MiB | 3136 MiB | 2.5 |
| `admin-waltid` | 2 | 192 MiB | 512 MiB | 704 MiB | 1.5 |
| `admin-inji` | 2 | 192 MiB | 512 MiB | 704 MiB | 1.5 |
| `admin-credebl` | 2 | 192 MiB | 512 MiB | 704 MiB | 1.5 |

One stack is the four roles of one DPG together:

| Selection | `waltid` | `inji` | `credebl` |
|---|---|---|---|
| `--all --dpg <dpg>` | 8576 MiB | 10112 MiB | 10112 MiB |

`--all` alone starts every role of every DPG and needs 28800 MiB.

The VCA figure is 96 MiB per service.
The admin role runs the admin service and the trust registry.
The holder role runs the wallet portal, the wallet auth service, and one
DPG adapter.
Each service is one static Go binary in a distroless image.
The DPG figure is the floor of the stack in `deploy/vca/dpg/`.
The admin role talks to no DPG.
Its profile starts only the Keycloak of the stack.

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
  --set roles.<role>.enabled=true \
  --set dpg.<dpg>.enabled=true
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
go run ./cmd/vca deploy --role <role> --dpg <dpg> --dry-run
docker compose --file deploy/vca/compose.yaml config --profile <role>-<dpg>
go test ./internal/cli/
```

## Reference

- [Get started](getting-started.md): the prerequisites and the first run.
- ADR-005: one image per service, non-root, read only, no Docker socket.
- ADR-007: the setup CLI and the files it writes.
- ADR-008: the profiles, the DPG includes, the bootstrap, and the charts.
- `verifiably-go/docs/dpg-matrix.md`: the DPG versions.
- [Compose profiles](https://docs.docker.com/compose/how-tos/profiles/)
- [Helm charts](https://helm.sh/docs/topics/charts/)
