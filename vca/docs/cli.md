# The vca command line tool

The `vca` tool sets up, deploys, and administers one deployment.
It replaces the shell wizard of the legacy stack (ADR-007 decision 1).
The source is `vca/cmd/vca` and `vca/internal/cli`.

## What it does

- `vca doctor` checks that the host meets every prerequisite.
- `vca ports` prints the host ports of one role and one DPG.
- `vca setup` asks the setup questions of one role and one DPG.
- `vca deploy` starts the services of one role and one DPG.
- `vca images build` builds the service images from this source.
- `vca status` shows the containers. `vca down` stops them.
- `vca dpg bootstrap` configures a DPG after it boots.
- `vca admin` calls the admin service.
- `vca migrate` carries the data of a legacy deployment into the services.
- `vca man` writes the man pages.

## How to run

Build the tool from the `vca` directory:

```sh
go mod tidy
go build -o vca ./cmd/vca
./vca --help
```

`go mod tidy` writes `go.sum`, which the repository does not ship yet.
`make install` builds the same binary into your `GOBIN` directory.
[Get started](getting-started.md) lists the other two ways to get it.

### Where the tool looks for the repository

You can run `vca` in any directory.
The tool reads `deploy/vca/compose.yaml` under the repository root.
It finds that root in this order:

| Order | Source | How to set it |
|---|---|---|
| 1 | The `--repo` flag | `vca deploy --repo /srv/verifiably ...` |
| 2 | The `VCA_REPO` variable | `export VCA_REPO=/srv/verifiably` |
| 3 | A walk up from your working directory | Nothing to do |

The walk stops at the first directory that holds `ADR.md`.

## doctor

```sh
vca doctor --role issuer --dpg waltid
vca doctor --all --from-source
```

`doctor` prints one line per prerequisite with a pass or a fail.
A fail line names the fix.
The command exits with status 1 when one check fails.

| Check | What it needs |
|---|---|
| `go` | Go 1.25 or newer. Only `--from-source` turns this check on. |
| `docker` | Docker 24 or newer with a daemon that answers. |
| `docker compose` | The compose plugin, version 2 or newer. |
| `memory` | The memory floor of the selection, from `docs/deploy.md`. |
| `port <n>` | Every host port of the pair and of the Keycloak is free. |
| `public url` | `VCA_PUBLIC_URL` resolves when it is not localhost. |
| `port 80`, `port 443` | Both are free when you use a public URL. |

The public URL comes from the environment, or from the `.env` file of the
pair.

## ports

```sh
vca ports --role issuer --dpg waltid
```

The command prints one line per service with the host port and the
container port.
Open those host ports in the firewall of a server.

## setup

```sh
vca setup --role {issuer|holder|verifier|admin} --dpg {waltid|inji|credebl}
```

The command asks only for a required value that no source and no default
filled.
A verifier operator never sees an issuer question.
A laptop deployment answers no question, because every value has a
default (ADR-008 decision 7).
Each question shows the help text and the rule.
A bad answer repeats the question with the reason.
Set an optional value with `--set` or with the `--env-file` file.

The questions come from one place: the `Config` message in
`proto/vca/config/v1/config.proto`.
Each field carries a `setting` option.
The option names the variable, the default, the rule, the roles, and the DPGs.
The CLI reads the generated descriptor.
Nobody writes a question twice (ADR-007 decision 6).

### Where a value comes from

The CLI takes the first value it finds, in this order:

| Order | Source | How to set it |
|---|---|---|
| 1 | A command line flag | `--set VCA_PUBLIC_URL=https://issuer.example` |
| 2 | The process environment | `export VCA_PUBLIC_URL=...` |
| 3 | The `--env-file` file | `--env-file base.env` |
| 4 | The answer you type | The interactive question |
| 5 | The default in the proto | Nothing to do |

A secret that an earlier run generated comes before the default.
A second run keeps every secret (ADR-007 decision 5).

### Flags

| Flag | What it does |
|---|---|
| `--role` | The deployment role. |
| `--dpg` | The digital public good. |
| `--all` | Every role of every DPG. Add `--dpg` to limit it to one stack. |
| `--env-file` | A dotenv file that prefills the answers. |
| `--non-interactive` | Ask nothing. The run fails and lists every missing value. |
| `--set NAME=value` | One value. Repeat the flag for more values. |
| `--out` | The directory that holds one folder per pair. |
| `--yes` | Write the files without the last question. |

### What it writes

The command writes one folder per role and DPG pair:

```
deploy/issuer-waltid/.env                  mode 0600
deploy/issuer-waltid/signing-key.pem       mode 0600
deploy/issuer-waltid/Caddyfile             mode 0644
deploy/issuer-waltid/waltid-onboard.json   mode 0644
```

Every pair gets `keycloak-realm.json`, because every DPG stack ships a
Keycloak. Only a walt.id pair gets `waltid-onboard.json`.
The CLI shows a summary of every value and its source before it writes.
A secret never appears in the summary.

### Examples

One role, with every answer on the command line:

```sh
vca setup --role issuer --dpg waltid --non-interactive \
  --set VCA_PUBLIC_URL=https://issuer.example \
  --set VCA_DPG_URL=http://waltid-issuer-api:7002 \
  --set VCA_OIDC_DISCOVERY_URL=https://idp.example/.well-known/openid-configuration
```

`VCA_DATABASE_URL` is optional.
The PostgreSQL backend keeps it for later.
No service reads it yet. Every service keeps its data in the file store
under `/data` (ADR-002 decision 3).

Every role of one stack in one run (ADR-007 decision 7):

```sh
vca setup --all --dpg waltid --env-file base.env --non-interactive
```

## deploy, status, and down

```sh
vca deploy --role issuer --dpg waltid
vca status --role issuer --dpg waltid
vca down   --role issuer --dpg waltid
```

`deploy` runs `docker compose` with the profile of the pair against
`deploy/vca/compose.yaml`.
`--all` starts every role of every DPG. Add `--dpg` to start every role of one DPG.
`--dry-run` prints the rendered compose file and the commands.
It starts nothing.
`--build` adds `deploy/vca/compose.build.yaml` and the `--build` flag of
compose, so compose builds every image from this source.
Use `--build` before the first tagged release.
No release has published the images yet.
See `docs/deploy.md` for the compose layout and the resource floor.

## images build

```sh
vca images build --role issuer --dpg waltid
vca images build --all --dpg waltid --dry-run
```

The command runs `docker build` once per service of the selection.
Each image gets the tag `local`.
The command then sets `VCA_VERSION=local` in the `.env` file of each
pair, so the next `vca deploy` starts the local images.

## dpg bootstrap

```sh
vca dpg bootstrap waltid --role issuer
vca dpg bootstrap inji --role holder
vca dpg bootstrap credebl --role issuer
```

The command calls the HTTP API of the DPG (ADR-008 decision 4).
It writes into no DPG database and it restarts no container.

| DPG | What the command does |
|---|---|
| `waltid` | Provisions a `did:web` issuer and its key. Saves `waltid-issuer.json`. |
| `inji` | Creates or updates the `vca` realm in Keycloak. |
| `credebl` | Signs in and creates the organisation of the deployment. |

Each run checks first, so a second run changes nothing.
The command reads the `.env` file of the pair.
Four more variables steer the run:

| Variable | What it holds |
|---|---|
| `VCA_BOOTSTRAP_URL` | The DPG URL for this run. It beats `VCA_DPG_URL`. |
| `VCA_BOOTSTRAP_ADMIN_USER` | The DPG administrator name. |
| `VCA_BOOTSTRAP_ADMIN_PASSWORD` | The DPG administrator password. |
| `VCA_BOOTSTRAP_ORG` | The CREDEBL organisation name. |

No service reads these four variables, so they are not in the `Config`
message.

## admin

The admin commands are clients of `vca.admin.v1.AdminService`.
The admin portal calls the same service.
No action exists in one place only (ADR-009 decision 1).

Log in first. The admin service holds the OpenID Connect client, so the
CLI needs no client id and no client secret:

```sh
vca admin login --url https://admin.example
vca admin login --url https://admin.example --bootstrap-token "$TOKEN"
vca admin login --url https://admin.example --device
```

`login` asks the admin service for an authorization URL at `/cli/login`.
It waits on a loopback port and sends the one time code to `/cli/token`.
No token travels in a URL.
`--device` posts to `/device_authorization` and polls `/token` instead.
Use it on a host with no browser.
`--bootstrap-token` binds the first super admin in one login.
The service prints that token once at its first start.
The session token goes to `deploy/.vca/admin-token` with mode 0600.

Then call an RPC:

```sh
vca admin tenant list --json '{"pageSize":20}'
vca admin trust add --file entry.json
vca admin health
```

| Command | RPC |
|---|---|
| `tenant create`, `get`, `list`, `update`, `delete` | The tenant RPCs |
| `trust add`, `get`, `list`, `remove` | The trust entry RPCs |
| `onboard` | `CreateAuthProvider` |
| `provider get`, `list`, `update`, `remove` | The provider RPCs |
| `apikey create`, `list`, `revoke` | The API key RPCs |
| `health` | `GetServiceHealth` |
| `audit` | `QueryAuditLog` |
| `bind` | `OnboardAdmin` |
| `help` | `ListCommands` |

The table is the same table that the admin service renders on its help
page at `/admin/help`.
A test fails when the two differ, so the CLI and the portal never drift
(ADR-009 decision 3).

The help text of each command is the `description` option of the RPC.
One sentence written once reaches the CLI, the man pages, the portal help
page, and the OpenAPI file (ADR-009 decision 4).

`--url` names the admin service. `VCA_ADMIN_URL` is the default.
`--token` names the bearer token. The saved token is the default.

## migrate

```sh
vca migrate export --from-state-dir ./state --out ./migration --salt "$SALT"
vca migrate import --from ./migration --into /var/lib/vca
```

The migrate commands carry the data of a legacy verifiably-go deployment into
the services (ADR-030 decision 8).
`export` reads one legacy source and writes four import files.
`import` writes those files into the state directory of the services.
Sessions and caches are not migrated.

`export` reads a PostgreSQL database with `--from-pg`, or a state directory
with `--from-state-dir`.
Name exactly one source.
The database source needs a `database/sql` driver with the name of
`--pg-driver`, and the released binary links none.

| Flag | What it does |
|---|---|
| `--from-pg` | The DSN of the legacy database. |
| `--from-state-dir` | The legacy state directory. |
| `--pg-driver` | The `database/sql` driver name. The default is `postgres`. |
| `--out` | The directory that receives the import files. |
| `--salt` | The salt of the subject reference. |
| `--salt-file` | A file that holds the salt. |
| `--keep-claim` | A subject claim to keep. Repeat the flag for more. |
| `--issuer-did` | The DID that signs the migrated status lists. |
| `--status-base-url` | The public root URL of the status services. |
| `--force` | Replace the files that exist. |

`import` takes `--from`, `--into`, and `--force`.
It checks every document first, so a broken export writes nothing.

`docs/migrate.md` holds the file layout, the salt rules, and the order of a
cutover.

## man

```sh
go run ./cmd/vca man --dir docs/man
```

The command writes one man page per command with `doc.GenManTree`
(ADR-009 decision 2).
The release workflow ships the pages, so `man vca-admin-trust-upsert`
works on any Linux host.

## How to check it works

Run the tests of the package:

```sh
go test ./internal/cli/
```

Print the rendered compose file without a Docker daemon:

```sh
go run ./cmd/vca deploy --role issuer --dpg waltid --dry-run
```

Write the man pages and read one:

```sh
go run ./cmd/vca man --dir /tmp/man
man /tmp/man/vca-setup.1
```

Check that the CLI tree and the admin portal agree:

```sh
go test -run TestAdminTreeMatchesTheAdminService ./internal/cli/
```

## Reference

- [Get started](getting-started.md): the prerequisites and the first run.
- ADR-007: the setup CLI, its inputs, its outputs, and its order of sources.
- ADR-008: the deploy commands, the compose profiles, and the Helm charts.
- ADR-009: the admin command tree and the generated man pages.
- ADR-010: the OpenID Connect login of the super admin.
- ADR-030 decision 8: the data migration of the migrate commands.
- `docs/migrate.md`: the migration files and the order of a cutover.
- `services/admin/README.md`: the login endpoints the CLI calls.
- `proto/vca/config/v1/config.proto`: every setup variable.
- `proto/vca/admin/v1/admin.proto`: every admin RPC.
- [Twelve factor config](https://12factor.net/config)
- [RFC 7636 PKCE](https://www.rfc-editor.org/rfc/rfc7636.html)
- [RFC 8628 device grant](https://www.rfc-editor.org/rfc/rfc8628.html)
- [RFC 8252 native apps](https://www.rfc-editor.org/rfc/rfc8252.html)
