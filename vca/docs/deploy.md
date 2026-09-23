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

`vca deploy` ends with the addresses to open: the public URL of every
pair, which is its portal, and the login page of each stack.
A public host also gets the three lines that hand the reverse proxy the
`vca proxy` snippet.

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
| `VCA_BIND` | The address the host ports bind to. See "Hardening". |

### Service links

Every service reads its settings under its own prefix, for example
`VCA_ISSUANCE_`.
The CLI writes each value a service needs into the .env file under
that name.
The service catalogue in `internal/cli/services.go` holds the list, and
`TestLinkValuesFeedEveryService` keeps it in step with the services.
The values come in five kinds:

| Kind | Example | Value |
|---|---|---|
| Service URL | `VCA_ISSUANCE_SCHEMA_URL` | The container name and port of another service, from the port plan. |
| Adapter URL | `VCA_ISSUANCE_ADAPTER_URL` | The DPG adapter of the pair. |
| Public URL | `VCA_SCHEMA_BASE_URL`, `VCA_TRUST_BASE_URL` | `VCA_PUBLIC_URL`, plus a prefix when the route table gives the service one. |
| Copy | `VCA_ADMIN_SIGNING_KEY`, `VCA_WALTID_ISSUER_URL` | A shared value under the name the service reads: the signing key, the session key, the bootstrap token, or `VCA_DPG_URL`. |
| Fixed | `VCA_ISSUER_AUTH_STATE_DIR=/data` | A path under the data volume. |

The public URL kind follows the route table of the pair.
The `Caddyfile` of the pair comes from the same table, so a service and
its public URL agree.
The routes come in three kinds:

| Route kind | Example | Public URL of the service |
|---|---|---|
| Root | `/portal/*` of `schema-registry`, `/oid4vp/*` of `verifier-ingest` | The bare `VCA_PUBLIC_URL`. The service sees the full path. |
| Prefix | `/status-token/*`, `/trust-registry/*` | `VCA_PUBLIC_URL` plus the prefix. The proxy removes the prefix. |
| Home | `/` and every path no route names | The home service of the role answers. |

A service with HTML pages gets root routes, because its pages link
with absolute paths.
The staff pages of `verifier-discovery` move to `/discovery` through
`VCA_DISCOVERY_PORTAL_PREFIX`, because `verifier-results` holds
`/portal`.
"Where each page lives" in `getting-started.md` lists every path.

A link can name a service of another role.
The container names carry the pair, as in
`verifier-<dpg>-verifier-discovery`.
Every profile joins the same `vca` network, so one role reaches another
role of the same DPG.
Start the other role, or edit the value by hand.

A variable that no setting declares passes through from `--set` or the
env file when its name starts with `VCA_`.
The CREDEBL adapter needs four such values: `VCA_CREDEBL_EMAIL`,
`VCA_CREDEBL_PASSWORD`, `VCA_CREDEBL_CRYPTO_KEY`, and
`VCA_CREDEBL_ORG_ID`.

Each role and DPG pair owns a block of one hundred host ports.
The first block starts at 18000.
`vca ports --role <role> --dpg <dpg>` prints the ports of one pair.
`vca doctor` checks that each one is free.

### The signing key

`vca setup` writes the ES256 key to `deploy/<pair>/signing-key.pem`
with mode 0600, and writes the same PEM as base64 into
`VCA_SECRETS_SIGNING_KEY`, with the prefix `base64:`.
The .env file has mode 0600 too.
A file on the host belongs to the operator.
The container user 65532 cannot read it, so the key travels in the
variable.
Every service accepts the PEM text, `base64:` and the PEM, `file:` and
a path, or a bare path.
A second run of setup upgrades a pair that an earlier version wrote
with `file:signing-key.pem`.

### Data volumes

A stateful service keeps its files under `/data` on a named volume,
`vca_<pair>-<service>-data`.
The image holds `/data` with owner 65532, and Docker copies that owner
into a new named volume, so the service can write.
A volume that an older image created belongs to root and every write
fails with `permission denied`.
Remove those volumes once, before the first deploy with the new images:

```sh
vca down --all
docker volume rm $(docker volume ls -q --filter name=vca_)
```

To keep the data instead, change the owner:

```sh
for v in $(docker volume ls -q --filter name=vca_); do
  docker run --rm -v "$v:/v" alpine chown 65532:65532 /v
done
```

### The theme file

Every service that draws pages reads `VCA_THEME_FILE` at start
(ADR-032 decision 1).
The compose file sets it to `/etc/vca/theme.yaml` and mounts
`deploy/vca/theme.yaml` there, read only.
Set `VCA_THEME_HOST_FILE` in the `.env` file, or in the environment of the
`vca` command, to mount another file, for example `deploy/theme.local.yaml`.
A service that reads a file with a problem stops before it listens and
prints every problem.
See the section "Change the look after deployment" in `ui.md`.

### Hardening

Every VCA service in the compose file:

- runs with a read only root file system,
- runs as the non-root user 65532,
- drops every Linux `cap_drop` entry and sets `no-new-privileges`,
- mounts no Docker socket and restarts no other container.

Those four rules come from ADR-005 decisions 2 and 3.

Every published port of the compose file and of the DPG stack files
binds to `VCA_BIND`.
`vca setup` writes `VCA_BIND=127.0.0.1` into the `.env` file of a pair
whose public URL names a public host.
The reverse proxy of the machine then reaches the services and the DPG
components on the loopback address. No other machine reaches them.
A laptop deployment with a localhost public URL gets no `VCA_BIND`, so
compose keeps its default, `0.0.0.0`.
Set `VCA_BIND` by hand in the `.env` file to change it.

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

A browser cannot reach a container name, so `VCA_OIDC_PUBLIC_URL` names
the address the browser uses.
A local deployment gets `http://localhost` with the host port of the
table.
A base domain gets `https://<dpg>-keycloak.<domain>`.
The Caddyfile of the issuer pair of the stack sends that host name to
the host port.
Keycloak reads the `X-Forwarded` headers of the proxy
(`KC_PROXY_HEADERS=xforwarded`), so its login page and its redirects
carry the public address.
A public `VCA_PUBLIC_URL` with no base domain gets `http://<public host>`
with the host port, with no TLS. Use it for a test only.
`vca doctor` checks that the host port is free and that the host name
resolves.

`vca deploy` reads the container names of the pair from
`docker compose config`.
When another compose project or a hand-started container holds one of
them, it stops before it starts anything.
The message prints the `docker rm -f` line that clears them.

`vca setup` writes `deploy/<role>-<dpg>/keycloak/vca-realm.json`.
The realm is `vca`.
It holds one client with the id `vca-<role>`, a generated client secret,
the authorization code flow, and PKCE.
Keycloak imports the file on its first start.
It reads the `keycloak` directory of the issuer pair of the stack.
That directory holds the realm alone.
Keycloak parses every JSON file of its import directory, and one other
file stops the import.
The directory has mode 0755 and the file has mode 0644, so the
Keycloak user inside the container reads them.
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
| `--all --dpg <dpg>` | 3968 MiB | 4480 MiB | 4480 MiB |

`--all` alone starts every role of every DPG and needs 12928 MiB.
The four roles of one DPG share one DPG stack and one Keycloak, so a
stack counts once.

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
`TestPackagedChartsMatchTheSource` fails when a package differs from its
chart directory.
After you change a service chart, package the dependencies again:

```sh
cd vca && VCA_WRITE_HELM=1 go test ./internal/cli/ -run TestPackagedCharts
```

The umbrella chart holds the theme file of every page in the ConfigMap
`<release>-theme` (ADR-032 decision 1).
Its default is `files/theme.yaml`, a copy of `deploy/vca/theme.yaml`.
Every UI chart mounts the ConfigMap at `/etc/vca` and rolls its pods when
the file changes:

```sh
helm upgrade vca deploy/vca/helm/vca --set-file global.theme.file=theme.yaml
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
