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

## The role and the DPG

Most commands take `--role` and `--dpg`.
`<role>` is one of `issuer`, `holder`, `verifier`, `admin`.
`<dpg>` is one of `waltid`, `inji`, `credebl`; the three are equal.

Leave a flag out and a terminal run asks for it with a numbered menu.
The menu lists every value in the order of the proto enum, and adds
`all` where `--all` is valid.
Pick a line by its number or type the name.
A run that is not a terminal, and a run with `--non-interactive`, asks
nothing. It fails and names the missing flag.

```
Which role?
  1) issuer
  2) holder
  3) verifier
  4) admin
  5) all
Number [1-5]:
```

## doctor

```sh
vca doctor --from-source
vca doctor --role <role> --dpg <dpg>
vca doctor --all --from-source
vca doctor --suggest
```

`doctor` prints one line per prerequisite with a pass or a fail.
A fail line names the fix.
The command exits with status 1 when one check fails.
It then prints the memory floor of every selected pair and the total.
The memory check adds only the pairs you selected.

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

When the free memory is under the floor, `doctor` and `setup` print one
hint:

```
Use --all --dpg <dpg> for one stack (<n> MiB) or --role admin --dpg <dpg> for one pair (<n> MiB)
```

The hint names the largest DPG that fits and the memory it needs.
One stack needs 8576 MiB with `waltid` and 10112 MiB with `inji` or
`credebl`. One admin pair needs 704 MiB with any DPG.
`vca doctor --suggest` prints the selection that fits the free memory of
this host, with the two commands that start it.

## ports

```sh
vca ports --role <role> --dpg <dpg>
```

The command prints one line per service with the host port and the
container port.
Open those host ports in the firewall of a server.

## setup

```sh
vca setup
vca setup --role <role> --dpg <dpg>
```

### The questions

A terminal run asks two kinds of question, in this order:

1. Every setting the proto marks with `prompt: true`.
   The run asks for it even though it has a default.
   The question shows the default in brackets.
   An empty answer keeps the default.
   The public URL is the only such setting today:

   ```text
   The public base URL of the deployment. Leave blank for localhost.
   Enter https://issuer.example for a public host.
     Rule: An absolute https URL without a path or a trailing slash.
     Variable: VCA_PUBLIC_URL
   Public URL [http://localhost:18002]:
   ```

2. Every required value that no source and no default filled.
   There is none today, so a run that answers question 1 with enter is
   done.

A verifier operator never sees an issuer question.
A laptop deployment answers one question, because every other value has a
default (ADR-008 decision 7).
Each question shows the help text and the rule.
A bad answer repeats the question with the reason.
A value that a flag, the environment, or the env file supplied is not
asked for again.
Set an optional value with `--set` or with the `--env-file` file.
A run that is not interactive asks nothing.

A `--all` run asks the same questions once per pair.
The answer of one pair pre-fills the question of the next pair, so enter
repeats it.
A localhost answer does not carry over, because each pair has its own
host port.

The questions come from one place: the `Config` message in
`proto/vca/config/v1/config.proto`.
Each field carries a `setting` option.
The option names the variable, the default, the rule, the roles, and the
DPGs.
It also says whether the run prompts for the field.
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
| `--role` | The deployment role. A terminal run asks for it when the flag is absent. |
| `--dpg` | The digital public good. A terminal run asks for it when the flag is absent. |
| `--all` | Every role of every DPG. Add `--dpg` to limit it to one stack. |
| `--env-file` | A dotenv file that prefills the answers. |
| `--non-interactive` | Ask nothing. The run fails and names every missing value. |
| `--set NAME=value` | One value. Repeat the flag for more values. |
| `--out` | The directory that holds one folder per pair. |
| `--yes` | Write the files without the last question. |

### What it writes

The command writes one folder per role and DPG pair:

```
deploy/<role>-<dpg>/.env                mode 0600
deploy/<role>-<dpg>/signing-key.pem     mode 0600
deploy/<role>-<dpg>/Caddyfile           mode 0644
deploy/<role>-<dpg>/keycloak-realm.json mode 0644
```

Every pair gets `keycloak-realm.json`, because every DPG stack ships a
Keycloak. A pair also gets the extra file its DPG needs:

| DPG | Extra file |
|---|---|
| `waltid` | `waltid-onboard.json` |
| `inji` | None |
| `credebl` | None |
The CLI shows a summary of every value and its source before it writes.
A secret never appears in the summary.

### Examples

One role, with every answer on the command line:

```sh
vca setup --role <role> --dpg <dpg> --non-interactive \
  --set VCA_PUBLIC_URL=https://issuer.example \
  --set VCA_OIDC_DISCOVERY_URL=https://idp.example/.well-known/openid-configuration
```

`VCA_DPG_URL` has a default per role and DPG. `docs/deploy.md` holds the
table of the twelve values.

`VCA_DATABASE_URL` is optional.
The PostgreSQL backend keeps it for later.
No service reads it yet. Every service keeps its data in the file store
under `/data` (ADR-002 decision 3).

Every role of one stack in one run (ADR-007 decision 7):

```sh
vca setup --all --dpg <dpg> --env-file base.env --non-interactive
```

## deploy, status, and down

```sh
vca deploy --role <role> --dpg <dpg>
vca status --role <role> --dpg <dpg>
vca down   --role <role> --dpg <dpg>
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
vca images build --role <role> --dpg <dpg>
vca images build --all --dpg <dpg> --dry-run
```

The command runs `docker build` once per service of the selection.
Each image gets the tag `local`.
The command then sets `VCA_VERSION=local` in the `.env` file of each
pair, so the next `vca deploy` starts the local images.

## dpg bootstrap

```sh
vca dpg bootstrap
vca dpg bootstrap <dpg> --role <role>
```

The command calls the HTTP API of the DPG (ADR-008 decision 4).
It writes into no DPG database and it restarts no container.
A terminal run with no DPG name and no `--role` asks for both.

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
go run ./cmd/vca deploy --role <role> --dpg <dpg> --dry-run
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
