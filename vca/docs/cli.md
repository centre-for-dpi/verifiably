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
- `vca dpg realm` turns self registration of a realm on or off.
- `vca dpg upgrade-secrets` keeps the old passwords of volumes from an earlier release.
- `vca dpg rotate-authz-key` rotates the token key of the Inji holder authorization server.
- `vca dpg apply` shows the issuer identity in the wallet of the Inji stack.
- `vca admin` calls the admin service.
- `vca migrate` carries the data of a legacy deployment into the services.
- `vca theme` checks and applies the theme file of every page.
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
| `stack secrets <dpg>` | No volume of the stack is older than the secrets of `deploy/<dpg>/.env` with another password. |

The public URL comes from the environment, or from the `.env` file of the
pair.

When the free memory is under the floor, `doctor` and `setup` print one
hint:

```
Use --all --dpg <dpg> for one stack (<n> MiB) or --role admin --dpg <dpg> for one pair (<n> MiB)
```

The hint names the largest DPG that fits and the memory it needs.
One stack needs 4064 MiB with `waltid`, 7040 MiB with `inji`, and
7264 MiB with `credebl`. One admin pair needs 704 MiB with any DPG.
`vca doctor --suggest` prints the selection that fits the free memory of
this host, with the two commands that start it.

## ports

```sh
vca ports --role <role> --dpg <dpg>
```

The command prints one line per service with the host port and the
container port.
On a server the ports bind to the loopback address, and the reverse
proxy of the machine reaches them. See "Hardening" in `deploy.md`.
Open only port 80 and port 443 in the firewall of a server.

## setup

```sh
vca setup
vca setup --role <role> --dpg <dpg>
```

### The questions

A terminal run asks three kinds of question, in this order:

0. The base domain, once.
   The run asks it when it sets up more than one pair.
   A public URL from a flag, the environment, or an env file skips it.
   Every pair then gets `https://<role>-<dpg>.<domain>` and the
   Keycloak of each stack gets `https://<dpg>-keycloak.<domain>`.
   One wildcard DNS record, `*.<domain>`, serves them all.
   An empty answer asks one public URL per pair instead.
   `--domain` or `VCA_DOMAIN` answers it without a question.

   ```text
   The base domain of the deployment. Every pair gets its own host name
   under it, for example https://issuer-waltid.<domain>. One wildcard DNS
   record, *.<domain>, must point at this host.
   Leave blank to answer one public URL per pair instead.
     Variable: VCA_DOMAIN
   Base domain []:
   ```

1. Every setting the proto marks with `prompt: true`.
   The run asks for it even though it has a default.
   The question shows the default in brackets.
   An empty answer keeps the default.
   The public URL is one such setting.
   An Inji issuer or holder pair also answers the organisation name and
   unit of its key certificates.
   Their defaults are the public host and the role (ADR-055 decision 3).
   The public URL question looks like this:

   ```text
   The public base URL of the deployment. Leave blank for localhost.
   Enter https://issuer.example for a public host.
     Rule: An absolute https URL without a path or a trailing slash.
     Variable: VCA_PUBLIC_URL
   Public URL [http://localhost:18006]:
   ```

2. Every required value that no source and no default filled.
   There is none today, so a run that answers question 1 with enter is
   done.

A verifier operator never sees an issuer question.
A laptop deployment answers one question per pair (ADR-008 decision 7).
An Inji issuer or holder pair answers three.
Every other value has a default.
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

### The required values

The proto marks these settings `required: true`.
Each one has a value without an answer.
So `vca setup --role <role> --dpg <dpg> --non-interactive` passes
with no flag, no environment, and no env file.
It does so for each of the twelve pairs.

| Variable | Where the value comes from |
|---|---|
| `VCA_ROLE` | The `--role` flag or the menu |
| `VCA_DPG` | The `--dpg` flag or the menu |
| `VCA_OIDC_DISCOVERY_URL` | The Keycloak of the DPG stack |
| `VCA_OIDC_CLIENT_SECRET` | Generated, 32 random bytes |
| `VCA_DPG_URL` | The DPG API container of the pair |
| `VCA_SECRETS_SIGNING_KEY` | Generated, `signing-key.pem`, also in the variable as `base64:` |
| `VCA_SECRETS_SESSION_KEY` | Generated, 32 random bytes |
| `VCA_SECRETS_BOOTSTRAP_TOKEN` | Generated for the admin role |
| `VCA_PORTS_PORTAL` | `8080` |

`VCA_REDIS_URL` is optional (ADR-020 decision 6).
Empty selects the in-memory limiter, which is fine for one replica.

### Flags

| Flag | What it does |
|---|---|
| `--role` | The deployment role. A terminal run asks for it when the flag is absent. |
| `--dpg` | The digital public good. A terminal run asks for it when the flag is absent. |
| `--all` | Every role of every DPG. Add `--dpg` to limit it to one stack. |
| `--domain` | The base domain. Every pair gets `https://<role>-<dpg>.<domain>`. Also `VCA_DOMAIN`. |
| `--env-file` | A dotenv file that prefills the answers. |
| `--non-interactive` | Ask nothing. The run fails and names every missing value. |
| `--set NAME=value` | One value. Repeat the flag for more values. A `VCA_` name that no setting declares passes through to the .env file. |
| `--out` | The directory that holds one folder per pair. |
| `--yes` | Write the files without the last question. |

### What it writes

The command writes one folder per role and DPG pair:

```
deploy/<role>-<dpg>/.env                       mode 0600
deploy/<role>-<dpg>/signing-key.pem            mode 0600
deploy/<role>-<dpg>/Caddyfile                  mode 0644
deploy/keycloak-<dpg>/                         mode 0755
deploy/keycloak-<dpg>/vca-<role>-realm.json    mode 0644
deploy/keycloak-<dpg>/.env                     mode 0600
deploy/<dpg>/.env                              mode 0600
deploy/<dpg>/.gitignore                        mode 0600
```

Every DPG stack ships a Keycloak, and every role has its own realm
(ADR-035 decision 1). So every pair writes its realm into the
directory of the Keycloak of the stack. The `.env` of that directory holds
the generated administrator password of the Keycloak. The first run
of any role of the stack writes it, and every later run keeps it
(ADR-035 decision 7).

Every run also writes `deploy/<dpg>/.env` for each of the three stacks.
It holds the database and key store passwords of the stack file
(ADR-055 decision 1). The CREDEBL file also holds the platform admin of
`VCA_CREDEBL_PLATFORM_ADMIN_EMAIL`, and the generated
`CRYPTO_PRIVATE_KEY`, `CREDEBL_PLATFORM_ADMIN_PASSWORD`,
`PLATFORM_WALLET_PASSWORD` and `PLATFORM_SEED`. It holds the secrets of
the two clients of the platform realm, `CREDEBL_ADMIN_KEYCLOAK_SECRET`
and `CREDEBL_KEYCLOAK_MANAGEMENT_CLIENT_SECRET`.
It holds the wallet key and the API key of the shared Credo agent,
`CREDEBL_AGENT_WALLET_KEY` and `CREDEBL_AGENT_API_KEY`. It holds the
secret of the schema file server, `CREDEBL_SCHEMA_FILE_SERVER_SECRET`.
Setup signs the upload token of the platform with it, into
`CREDEBL_SCHEMA_FILE_SERVER_TOKEN`.
Every CREDEBL pair but the admin one needs the email. It has no
default. The same pairs need `VCA_CREDEBL_INDY_LEDGERS`, the Indy
networks of the shared agent. It has no default either. Setup writes it
as `CREDEBL_INDY_LEDGERS` and writes `deploy/credebl/credebl-agent.json`
from it (ADR-065). Each has 32 random letters and digits. A later run keeps
every value it finds. The main compose file includes every stack file.
Compose checks the values of each, so the run writes all three.
The `.gitignore` beside it keeps the file out of git.

A pair also gets the extra file its DPG needs:

| DPG | Extra file |
|---|---|
| `waltid` | `waltid-onboard.json`, and the files of the `config` folder below |
| `inji` | None |
| `credebl` | None |

The walt.id issuer pair gets `config/credential-issuer-metadata.conf`
with mode 0644. It is the catalogue of the issuer API: one entry per
wire format, with the prefix `vca_`. The walt.id holder pair gets the
wallet API files of the same folder (ADR-054):

| File | Mode | What it holds |
|---|---|---|
| `config/auth.conf` | 0600 | The generated login keys |
| `config/ktor-authnz.conf` | 0600 | The generated hash pepper |
| `config/registration-defaults.conf` | 0644 | The key and DID of a new wallet, and no issuer |
| `config/db.conf` | 0600 | The database with the password of the stack |
| `config/_features.conf` | 0644 | The developer mode off |

The keys live in `deploy/waltid/.env`, so a later run writes the same
files. The stack file mounts each folder read only.

The first run also writes `deploy/vca/theme.yaml` with mode 0644 when the
file is absent (ADR-032 decision 1).
A later run never replaces it, so an edited look survives.
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

Every pair on its own host name under one base domain:

```sh
vca setup --all --domain labs.example --yes
```

## proxy

```sh
vca proxy --all | sudo tee /etc/caddy/vca.caddy >/dev/null
```

`proxy` prints the Caddyfile of every selected pair as one snippet.
The reverse proxy of the host imports it.
VCA binds no port 80 or 443, so it shares the host with other projects.
Each site sends its requests to `127.0.0.1` and the host port of a
service.
The command names a pair with no Caddyfile on standard error and
leaves it out.

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
It writes into no DPG database. Only the `credebl` run restarts a
container: the shared agent and the adapter, after a new value of their
`.env` files.
A terminal run with no DPG name and no `--role` asks for both.

| DPG | What the command does |
|---|---|
| `waltid` | Asks the walt.id adapter of the issuer pair for its identity. The adapter provisions a `did:web` of the host and a key, and keeps the key. |
| `inji` | Creates or updates the realm of the role in Keycloak. An issuer or a holder pair with an eSignet authenticator then registers the VCA client in eSignet. The run adds no identity anywhere. |
| `credebl` | Creates the platform realm when Keycloak lacks it. Initialises the CREDEBL database once and signs in as the platform admin of setup. Creates the organisation of the deployment. Binds the shared agent and gives the organisation a wallet in it. Points the webhook of the agent at the gateway and writes the organisation into the `.env` of the pair. |

Each run checks first, so a second run changes nothing.
The command reads the `.env` file of the pair.

The `waltid` run calls `GetIssuerIdentity` and then
`ProvisionIssuerIdentity` of the adapter (ADR-046). The reverse proxy
does not publish the adapter services (ADR-047). So the run reaches the
adapter at `http://127.0.0.1` and its host port, as the `Caddyfile`
does. The port is `VCA_HOST_PORT_DPG_ADAPTER_WALTID` of the `.env` file
of the pair, or the port plan. Run the command on the machine that runs
compose. The CLI never holds the issuer key (ADR-001 decision 3). The identity page of the issuer shows the identity at
once. An older run left `waltid-issuer.json` beside the `.env` file.
A new run imports that file into the adapter and says the file can go.
A pair of another role needs no issuer identity.

The `inji` run of an issuer or a holder pair registers the VCA client
`vca-inji` in the eSignet of the stack. It does so only when the pair
names an authenticator in `VCA_ESIGNET_AUTHENTICATOR` (ADR-053). Without one, the
run asks no eSignet. The holder run still writes the key and the Mimoto
key store. eSignet 1.5.1 takes
`private_key_jwt` only, with an RS256 assertion from an RSA key. The
first run makes a 2048 bit RSA key in `deploy/esignet-inji/vca-client.pem`
with mode 0600, unless `vca setup` of the issuer pair made it first. The directory holds a `.gitignore` that ignores all of
it, so the key never reaches a tracked file. The run sends only the
public key, with `POST /v1/esignet/client-mgmt/oauth-client`. A later
run keeps the key. eSignet then answers `duplicate_client_id`, and the
run adds the redirect URI of its pair with a `PUT`. The file
`vca-client.json` keeps the redirect URIs of the runs.

The issuer run also adds the callback of the holder authorization
server, `VCA_INJI_AUTHZ_ISSUER` with `/callback`. Setup names eSignet
as the holder provider of that server, with the same key (ADR-053
decision 4). A holder or verifier run ends with the client, the key
file, and the eSignet issuer. The provider form of the admin portal
takes them.

The holder run also adds the redirect page of Inji Web,
`http://localhost:17085/redirect` or `VCA_INJI_WEB_URL` with
`/redirect`. It writes the same key into
`deploy/mimoto-inji/oidckeystore.p12` under the alias `vca-inji`.
Mimoto signs its token call with that key when a holder claims in Inji
Web. The password sits in `deploy/mimoto-inji/.env`. Both files have
mode 0600, and a later run keeps the password. The public half goes to
`deploy/mimoto-inji/vca-inji.jwk.json`. The setup run of the Inji issuer
pair reads it. It registers `vca-inji` with the holder authorization
server of its adapter (ADR-052). Run `vca setup` and `vca deploy` for
the issuer pair afterwards, and `vca deploy` for the holder pair, so
Mimoto reads the password.

Keycloak ignores the clients of a realm update. So a run on a realm
that already exists writes each client of the realm file through the
client API. It updates a client the realm has and adds one it lacks,
such as `vca-inji-authz` of the holder realm.

The run reaches eSignet at `http://127.0.0.1` and
`INJI_ESIGNET_HOST_PORT`, or 17082. An eSignet whose client API needs a
token answers 401. The run then names `VCA_BOOTSTRAP_ESIGNET_TOKEN`.

The `inji` run adds no identity anywhere. The people who claim a
credential come from the systems of the operator (ADR-050).

The `credebl` run starts with the realm `credebl-platform` of the
platform in the Keycloak of the stack (ADR-058 decision 3). It creates
the realm when Keycloak lacks it, with the client secrets of
`deploy/credebl/.env`. A later run sets the client secrets again. It
signs in with the administrator of `deploy/keycloak-credebl/.env` at
`http://127.0.0.1:17180`. `VCA_CREDEBL_KEYCLOAK_ADMIN_URL` changes the
address.

The run then starts the database initialisation of the
CREDEBL release (ADR-055 decision 4). The API gateway runs the
migrations only. So the run starts the initialisation image of the
release once with `docker compose run`, in the profile `credebl-init`.
The image of the API gateway lacks the tools of the script. That
container reads `deploy/credebl/.env`: the platform admin
`PLATFORM_ADMIN_EMAIL` and the generated secrets. The script makes the
platform admin, the roles, the agent types and the ledgers. The file
`deploy/credebl/initialised` records the run, so a later run skips it.
A failed run writes no such file.

The run then signs in as the platform admin. The name comes from
`VCA_BOOTSTRAP_ADMIN_USER`, else from `PLATFORM_ADMIN_EMAIL`. The
password comes from `VCA_BOOTSTRAP_ADMIN_PASSWORD`, else from the
generated `CREDEBL_PLATFORM_ADMIN_PASSWORD` of `deploy/credebl/.env`.
The master table of the initialisation carries that password (ADR-058
decision 1). No default user and no default password exist. The run never signs in as
the administrator of the Keycloak of the stack. The platform decrypts
the password of a sign in with `CRYPTO_PRIVATE_KEY`, so the run sends
it encrypted with that key.

The run then creates the organisation of the deployment when it is
missing. It binds the shared Credo agent of the stack file to the
organisation `Platform-admin` that the initialisation made. It calls
`POST /v1/orgs/{org}/agents/configure` with the address
`http://credebl-agent.vca.internal:8001` and `CREDEBL_AGENT_API_KEY`.
`VCA_CREDEBL_AGENT_ADMIN_URL` changes the address. It then gives the
organisation of the deployment a wallet in the shared agent with
`POST /v1/orgs/{org}/agents/wallet`. The platform answers a second
binding and a second wallet with the status conflict. The run then
reports each as present.

The shared agent sends each event to the api gateway at
`/wh/<organisation>`, with the id of `Platform-admin` (ADR-058
decision 4). The run writes that address into `deploy/credebl/.env` as
`CREDEBL_AGENT_WEBHOOK_URL`, with the id as `CREDEBL_PLATFORM_ORG_ID`.
It writes the id of the organisation of the deployment into the `.env`
of the pair as `VCA_CREDEBL_ORG_ID`. It then recreates the agent and the
adapter of the pair with `docker compose up -d --no-deps`. A run that
finds both values restarts nothing. A later setup run keeps them.

Seven more variables steer the run:

| Variable | What it holds |
|---|---|
| `VCA_BOOTSTRAP_URL` | The DPG URL for this run. It beats `VCA_DPG_URL`. |
| `VCA_BOOTSTRAP_ADMIN_USER` | The DPG administrator name. |
| `VCA_BOOTSTRAP_ADMIN_PASSWORD` | The DPG administrator password. |
| `VCA_BOOTSTRAP_ORG` | The CREDEBL organisation name. |
| `VCA_BOOTSTRAP_ADAPTER_URL` | The walt.id adapter address for this run. It beats the host port of the adapter. |
| `VCA_BOOTSTRAP_ESIGNET_URL` | The eSignet address for this run, without `/v1/esignet`. |
| `VCA_BOOTSTRAP_ESIGNET_TOKEN` | A bearer token with the scope `add_oidc_client`, when the eSignet client API needs one. |

No service reads these seven variables, so they are not in the `Config`
message.

## dpg realm

```sh
vca dpg realm --role <role> --dpg <dpg> --registration on|off
```

Every realm starts with self registration on (ADR-035 decision 1).
The first admin registers, binds with the bootstrap token, and then
closes the admin realm (ADR-035 decision 6):

```sh
vca dpg realm --role admin --dpg <dpg> --registration off
```

The command calls the Keycloak admin API of the stack at
`VCA_OIDC_PUBLIC_URL` of the pair, or at `VCA_BOOTSTRAP_URL`.
It reads the administrator password from `deploy/keycloak-<dpg>/.env`,
or from `VCA_BOOTSTRAP_ADMIN_PASSWORD`.
It writes the same value into `deploy/keycloak-<dpg>/vca-<role>-realm.json`,
so a later `vca dpg bootstrap` keeps it.
It never creates a realm. A missing realm names the bootstrap command.

The first run checklist of the admin portal has the step "Turn off self
registration". The step counts as done when no admin provider offers a register
action. Set `VCA_ADMIN_URL` and log in with `vca admin login` before the
run. The run then sets the register action of every Keycloak provider
record of that realm to none. The checklist step turns green.
Without the admin service the run changes the realm and prints how to
record the step.

## dpg upgrade-secrets

```sh
vca dpg upgrade-secrets --dpg <dpg>
```

A release before generated stack secrets ran every stack on fixed
passwords.
A database volume keeps the password of its first start.
So a volume of that release fails with the new passwords of setup.
The command reads the creation time of each volume from Docker.
It compares that time with `VCA_STACK_SECRETS_SINCE` of
`deploy/<dpg>/.env`.
For each older volume, it writes the old password into the `.env`.
It keeps every other value and prints no password.
No `--dpg` means every stack.
The first `vca setup` run already does this for a stack with no `.env`.
Run the command when the `.env` exists, before `vca deploy`.
`vca doctor` names each volume that needs it.
Rotate the old passwords later, as `docs/deploy.md` says.

## dpg rotate-authz-key

```sh
vca dpg rotate-authz-key inji
vca dpg rotate-authz-key inji --now
```

The Inji adapter of the issuer pair signs its access tokens with a
token key (ADR-056 decision 6). The command asks the adapter for a new
key. The adapter puts the new key in its key set at once. It signs with
it six minutes later, when the key set cache of Certify has ended. The
old key leaves the key set when its last token expires.

Use `--now` when somebody else holds the old key. The new key then signs at
once, and the old key leaves at once. Certify refuses new tokens until
its key set cache ends, five minutes at most. Restart
`inji-certify-authcode` to end that sooner.

The run reads the `.env` of the issuer pair. It reaches the adapter on
its host port, as `vca dpg bootstrap` does, or at
`VCA_BOOTSTRAP_ADAPTER_URL`. It proves that it holds the pair session
key with a token derived from it. The proxy of the pair does not publish
the rotation.

## dpg apply

```sh
vca dpg apply inji
```

Inji Web lists the issuer under the name and the logo of the issuer
list of Mimoto. `vca setup --role holder --dpg inji` writes that list.
Before the issuer names itself, the list shows "Issuer of" and the host
of the issuer pair.

Run the command after the issuer edits the identity in the issuer
portal. The run reads the identity from the adapter of the issuer pair
on its host port, or at `VCA_BOOTSTRAP_ADAPTER_URL`. It keeps it in
`deploy/issuer-inji/identity.json`, which a later holder setup reads.
It then writes the name into the issuer list and restarts `inji-mimoto`
and `inji-web`.

The logo is `/static/logo.svg` of the issuer pair when the theme file
has a logo. PNG and WebP logos keep their own extension. Without a
logo, the list carries an inline image of the wordmark. No file of the
list or of the credential template loads an image from another host.

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

## theme

```sh
vca theme check
vca theme check --file deploy/theme.local.yaml
vca theme apply
vca theme print-default > deploy/theme.local.yaml
```

The look of every page comes from one file, `deploy/vca/theme.yaml`
(ADR-032).
`check` reads the file and validates it.
It prints `theme file <path>: valid`, or one line per problem with the
YAML path of the value, and exits with status 1.
A colour pairing below WCAG AA appears with its name and its ratio, for
example `colors.light: pairing "primary button label": contrast 3.10:1 is
below 4.5:1`.
`apply` runs the check, then restarts the services that draw pages in
every deployed pair through `docker compose restart`.
A service with no pages keeps running.
`print-default` prints the shipped file.

The default path is `VCA_THEME_HOST_FILE`, else `deploy/vca/theme.yaml`.
Export the variable in the shell that runs `vca` and `docker compose`.
A relative value resolves against `deploy/vca`, as the bind mount of the
compose file does, so `deploy/theme.local.yaml` is `../theme.local.yaml`.
That file is git ignored, so a rebrand keeps the tree clean.
On Kubernetes, `apply` has no work to do; run
`helm upgrade vca deploy/vca/helm/vca --set-file global.theme.file=theme.yaml`
instead.
The section "Change the look after deployment" in `ui.md` lists the
values and the rules.

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
- ADR-032: the theme file and the theme commands.
- ADR-030 decision 8: the data migration of the migrate commands.
- `docs/migrate.md`: the migration files and the order of a cutover.
- `services/admin/README.md`: the login endpoints the CLI calls.
- `proto/vca/config/v1/config.proto`: every setup variable.
- `proto/vca/admin/v1/admin.proto`: every admin RPC.
- [Twelve factor config](https://12factor.net/config)
- [RFC 7636 PKCE](https://www.rfc-editor.org/rfc/rfc7636.html)
- [RFC 8628 device grant](https://www.rfc-editor.org/rfc/rfc8628.html)
- [RFC 8252 native apps](https://www.rfc-editor.org/rfc/rfc8252.html)
