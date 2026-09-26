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
The `waltid` run calls the adapter on its host port, so run it on the
machine that runs compose. See "What the proxy publishes".

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

One service runs once per deployment: the landing, `vca-landing`
(ADR-033 decision 2).
Every profile lists it, so the first pair you start brings it up and the
next pair finds it running.
It reads `deploy/landing/.env`, which every `vca setup` run writes again.
That file holds the listen address, the public URL, the peer list, and
the image version.
The landing publishes host port 17900.
Set `VCA_HOST_PORT_LANDING` in `deploy/landing/.env` to move it.
Under a base domain the landing answers at `https://vca.<domain>`.
On a laptop it answers at `http://localhost:17900`.
The deploy report names it first, under "Start here".

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
The values come in six kinds:

| Kind | Example | Value |
|---|---|---|
| Service URL | `VCA_ISSUANCE_SCHEMA_URL` | The container name and port of another service, from the port plan. |
| Adapter URL | `VCA_ISSUANCE_ADAPTER_URL` | The DPG adapter of the pair. |
| Public URL | `VCA_SCHEMA_BASE_URL`, `VCA_TRUST_BASE_URL` | `VCA_PUBLIC_URL`, plus a prefix when the route table gives the service one. |
| Copy | `VCA_ADMIN_SIGNING_KEY`, `VCA_WALTID_ISSUER_URL` | A shared value under the name the service reads: the signing key, the session key, the bootstrap token, or `VCA_DPG_URL`. |
| Fixed | `VCA_ISSUER_AUTH_STATE_DIR=/data` | A path under the data volume. |
| Peers | `VCA_PEERS` | Every candidate pair of the deployment. See "Peers". |

### Peers

A page must know three things about the pairs (ADR-034): which ones a
deployment can run, which ones run now, and what each can do.
The CLI writes `VCA_PEERS` for every service with pages, for
`issuer-auth`, for `wallet-auth`, for `verifier-auth`, and for `admin`.
The value lists all twelve pairs on one line.
Each item is `<pair>|<public URL>|<service>=<internal URL>,...` and a
semicolon separates the items.
The pair itself keeps the public URL of its own `.env` file.
Under a base domain, every other pair gets `https://<pair>.<domain>`.
Without one, a pair directory that names a public URL keeps it, and the
rest get `http://localhost:<host port>` of their home service.
The internal URLs follow the port plan of each pair.
Setup reads the `.env` file of every pair directory present, so a moved
port of another pair reaches the list.
Run setup again for a pair after you change the ports of another.

The package `internal/topology` parses the value and probes each pair.
It asks the home service of each pair for `/readyz` and the DPG adapter
for its capabilities.
The probes run in parallel with a timeout of one second.
The answer stays in a cache for fifteen seconds.
A pair whose host name does not resolve is absent, and no page shows
it.
A pair that resolves but is not ready is starting.
Only a ready pair with an answer from its adapter is live.

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
Export `VCA_THEME_HOST_FILE` in the shell that runs `vca` and
`docker compose` to mount another file, for example
`../theme.local.yaml` for the git ignored `deploy/theme.local.yaml`.
A relative value resolves against `deploy/vca`.
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
The reverse proxy publishes only the paths of "What the proxy
publishes".

## What the proxy publishes

The proxy publishes a path on the host name of a pair only for
a party outside the host (ADR-047).
That party is a browser, a wallet, an auditor, or the CLI.
A Connect service goes public only when every RPC of it checks the
caller.
Every other Connect service stays on the compose network.
The pages draw on the server and reach those services by container
name, so a browser never calls them.

The `Caddyfile` of every pair answers `404` to `/vca.*`, the path of
every Connect service that no route names.
The holder pair also refuses `/auth/vca.*`, because its `/auth/*` route
strips `/auth` before `wallet-auth` sees the path.
Without these blocks the last `handle` block would send the path to the
home service of the role.

### Connect services

| Service | Served by | Reach | Why |
|---|---|---|---|
| `vca.admin.v1.AdminService` | `admin` | Public | `vca admin` and `vca dpg realm` call it at `VCA_ADMIN_URL`. Each RPC needs an admin session or an API token. `ListCommands` returns the help text. `OnboardAdmin` needs the one time bootstrap token. |
| `vca.admin.v1.AdminService` | `issuer-auth`, `verifier-auth`, `wallet-auth` | Public | `vca admin --url` manages the providers and the API keys of the pair. Each RPC needs the admin token or an admin session. The auth services of the issuer and the verifier also take a session with their admin role. The other RPCs answer `unimplemented`. |
| `vca.issuerauth.v1.IssuerAuthService` | `issuer-auth` | Public | A portal that drives the login itself calls it. `ListProviders`, `LoginStart`, `LoginCallback`, and `Introspect` are the login flow, as the `/auth/` pages are. `Logout` needs a session. The role mapping RPCs need an admin. |
| `vca.verifierauth.v1.VerifierAuthService` | `verifier-auth` | Public | The same RPCs and the same checks as `IssuerAuthService`, for verifier staff. |
| `vca.walletauth.v1.WalletAuthService` | `wallet-auth` | Public | The login flow, as for `issuer-auth`. `RegisterHolderKey`, `GetAuthorizationGrant`, and `Logout` need a holder session. |
| `vca.audit.v1.AuditService` | `admin`, `issuance`, `issued-credentials`, `issuer-auth`, `trust-registry`, `verifier-auth`, `verifier-results`, `wallet-auth` | Compose network | It needs an admin session. The admin reads every audit log on the compose network (ADR-039). |
| `vca.backend.v1.CapabilityService` | `dpg-adapter-*` | Compose network | No caller check. The peer probe of each page service calls it. |
| `vca.backend.v1.IssuerBackendService` | `dpg-adapter-*` | Compose network | No caller check. `issuance` and `schema-registry` call it. `vca dpg bootstrap waltid` calls the host port of the adapter. |
| `vca.backend.v1.HolderBackendService` | `dpg-adapter-*` | Compose network | No caller check. `wallet-auth` and `wallet-portal` call it. |
| `vca.backend.v1.VerifierBackendService` | `dpg-adapter-*` | Compose network | No caller check. No party outside the host calls it. |
| `vca.backend.v1.CatalogBackendService` | `dpg-adapter-*` | Compose network | No caller check. `schema-builder-ui` calls it. |
| `vca.backend.v1.TenantBackendService` | `dpg-adapter-*` | Compose network | No caller check. The admin calls it for tenants and stack credentials. |
| `vca.backend.v1.NotificationBackendService` | `dpg-adapter-*` | Compose network | No caller check. The admin calls it for stack webhooks. |
| `POST /callbacks/issuance/*`, no RPC | `dpg-adapter-waltid` | Compose network | The walt.id issuer posts session events there. Each offer has its own random token in the path, and a wrong token answers 404. |
| `vca.combined.v1.CombinedService` | `verifier-combined` | Compose network | No caller check, and no party outside the host calls it. |
| `vca.datasource.v1.DataSourceService` | `data-source` | Compose network | Without a key set file it trusts the session header of a gateway. The data source pages call it in process. No other service calls it. |
| `vca.discovery.v1.DiscoveryService` | `verifier-discovery` | Compose network | No caller check. `verifier-ingest`, `verifier-combined`, and `wallet-portal` call it. A wallet reads `/catalog` instead. |
| `vca.ingest.v1.IngestService` | `verifier-ingest` | Compose network | No caller check. A wallet posts to `/oid4vp/response`. The scanner page posts to `/scan/ingest`. |
| `vca.issuance.v1.IssuanceService` | `issuance` | Compose network | No caller check. The issuer pages call it in process. |
| `vca.issued.v1.IssuedService` | `issued-credentials` | Compose network | No caller check. `issuance` and `schema-registry` call it. The issued credentials pages call it in process. An auditor reads `/issued/chain-head` instead. |
| `vca.policy.v1.PolicyService` | `verifier-policy` | Compose network | No caller check. `verifier-results` and `verifier-combined` call it. |
| `vca.results.v1.ResultsService` | `verifier-results` | Compose network | No caller check. `verifier-combined` calls it, and the verifier pages call it in process. |
| `vca.schema.v1.SchemaService` | `schema-registry` | Compose network | No caller check. `issuance` and `schema-builder-ui` call it. A wallet reads the metadata and the schema files instead. |
| `vca.schemabuilder.v1.SchemaBuilderService` | `schema-builder-ui` | Compose network | No caller check. The builder page calls it in process. |
| `vca.status.v1.StatusService` | `status-bitstring`, `status-token` | Compose network | No caller check. `issuance` and `issued-credentials` call it. A verifier reads the signed lists instead. |
| `vca.trust.v1.TrustService` | `trust-registry` | Compose network | No caller check. `admin`, `issuance`, `verifier-discovery`, `verifier-policy`, and `wallet-portal` call it. A verifier reads the signed lists instead. |
| `vca.walletportal.v1.WalletPortalService` | `wallet-portal` | Compose network | It checks the holder session, but no party outside the host calls it. The pages call it in process, and the browser reads `/wallet/blobs`. |

`TestNoUnguardedRPCIsPublic` in `internal/cli` holds the allowlist of
the public rows.
It fails when a route publishes a Connect service outside the list.
Each public row names a test in its own service,
`TestAnonymousRPCsAreRefused`.
That test calls every RPC with no credential through the handler of the
service.
Every RPC outside the login flow must answer `unauthenticated`,
`permission_denied`, or `unimplemented`.
`TestDeployDocClassifiesEveryRPC` keeps this table in step with the
generated code and the allowlist.

### Plain HTTP paths

The proxy keeps the paths that a protocol, a browser, or an auditor
needs.
Each one checks its caller or serves public data only.

| Path | Service | Why it stays public |
|---|---|---|
| `/auth/*`, `/token`, `/.well-known/jwks.json` | the auth service of the role | The login flow. PKCE, the `state`, and the client secret guard each step. The key set is public by design. |
| `/device_authorization`, `/cli/*` | `admin` | The login of `vca admin login`. |
| `/admin/*`, `/issuer/*`, `/identity/*`, `/issue/*`, `/notifications/*`, `/help/*`, `/portal/*`, `/builder/*`, `/discovery/*`, `/scan/*` | the page services | The staff pages. Each page needs a staff session of the role. |
| `/wallet/*` | `wallet-portal` | The wallet pages and `/wallet/blobs`. Each one needs a holder session. |
| `/verify/*` | `verifier-results` | The citizen check page. It keeps no result. |
| `/static/*` | the home service | The shared style sheet, fonts, and scripts. |
| `/issuance/pdf/*` | `issuance` | The document of a citizen. A random 128 bit reference names it, and it expires. |
| `/pdf/preview/*` | `schema-builder-ui` | The PDF preview of the values that the schema derives. A hash of the preview names it. |
| `/.well-known/openid-credential-issuer`, `/.well-known/vct/*`, `/vct/*`, `/schemas/*`, `/api/schemas` | `schema-registry` | The OID4VCI metadata and the published schema documents. `GET` only. |
| `/.well-known/did.json` | `issuance` | The DID document of a `did:web` issuer. |
| `/issued/chain-head`, `/issued/jwks.json` | `issued-credentials` | The signed chain head and its key for an auditor. `GET` only. |
| `/status-bitstring/status/*`, `/status-token/status/*` and the key set under each prefix | the status services | The signed status lists that a verifier reads. `GET` only. The proxy strips the prefix. |
| `/trust-registry/trust-list/*`, `/trust-registry/.well-known/*`, `/trust-registry/dedi/*`, `/trust-registry/trust/*` | `trust-registry` | The signed trust lists and their key set. `GET` and `HEAD` only. The proxy strips the prefix. |
| `/catalog`, `/catalog/*` | `verifier-discovery` | The read only catalogue that a wallet reads. |
| `/oid4vp/*` | `verifier-ingest` | The OID4VP request object and the direct post endpoint. The transaction id and the `state` guard the post. |
| `/offers/*` | `dpg-adapter-inji` | A hosted credential offer. A random id names it, and it expires. |
| `/authz/*` | `dpg-adapter-inji` | The holder authorization server (ADR-052): its metadata, key set, authorize, callback, and token endpoints. PKCE, the registered redirect URIs, one time codes, and the client check guard it. |
| `/.well-known/oauth-authorization-server/authz`, `/.well-known/openid-configuration/authz` | `dpg-adapter-inji` | The metadata of the holder authorization server where RFC 8414 section 3 puts it. |
| `/iar/presentation-definition.json` | `dpg-adapter-inji` | The proxy does not publish it. Certify reads it on the compose network. It is the presentation definition that a wallet sees anyway. `GET` only. |
| `/authorize`, `/login`, `/consent`, `/claim-details`, `/something-went-wrong`, `/page-not-found`, `/esignet-ui/*`, `/theme/*`, `/locales/*`, `/images/*`, `/v1/esignet/*`, `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server` | `inji-esignet-ui` of the `issuer-inji` pair, when eSignet runs | The eSignet login page is a browser page, not an RPC. A person signs in there at the identity system of the operator. eSignet checks the client, the PKCE code, and the transaction at each step. The rest is its metadata and the files of the page. |

### The CLI and the proxy

`vca admin` and `vca dpg realm` call the `AdminService` of the admin at
`VCA_ADMIN_URL`, with the token of `vca admin login`.
That service stays public, and each RPC checks the caller.
`vca dpg bootstrap waltid` reaches the walt.id adapter at
`http://127.0.0.1:<port>`.
The port is `VCA_HOST_PORT_DPG_ADAPTER_WALTID` of the `.env` file of the
pair, or the port plan when the file names none.
Run the command on the machine that runs compose.
Set `VCA_BOOTSTRAP_ADAPTER_URL` to reach the adapter at another address.
`vca dpg bootstrap inji` and `vca dpg bootstrap credebl` call the DPG,
not a VCA service.

## The DPG stacks

`deploy/vca/compose.yaml` pulls in the DPG files with `include`
(ADR-008 decision 3).
The versions come from `verifiably-go/docs/dpg-matrix.md`:

| File | What it holds | Version |
|---|---|---|
| `dpg/waltid.yaml` | Issuer API, verifier API, verifier API 2, wallet API | 0.18.2 |
| `dpg/inji.yaml` | Inji Certify | 0.14.0 |
| `dpg/inji.yaml` | Inji Web and Mimoto | 0.16.0 and 0.21.0 |
| `dpg/inji.yaml` | Inji Verify UI and service | 0.16.0 |
| `dpg/inji.yaml` | eSignet and its login page, with an authenticator only | 1.5.1 |
| `dpg/credebl.yaml` | The whole CREDEBL platform and its shared Credo agent | `main` at 2026-09-26, by digest |
| Every `dpg/*.yaml` file | Keycloak | 25.0 |

CREDEBL publishes from its main branch.
The stack file pins each platform image by the digest that `latest` named on 2026-09-26.
The release tag of the same image stands beside the digest.
Most images carry `v2.1.3-hotfix.2`.
The ecosystem and OpenID for Verifiable Credentials images carry `v2.2.1-alpha.4`.
The X.509 image carries `v2.2.1-alpha.3`.
The Credo agent carries `v2.2.1-alpha-jsonld-vc.2.1`.
The schema file server has only `latest`.
The adapter reports `main at 2026-09-26` and the digest of the API gateway.
Change a digest in the stack file and in the adapter together.
A test binds the two.

The file runs the 23 services of the upstream compose file.
It also runs the shared Credo agent in multi tenancy mode.
Upstream, agent provisioning starts that agent through the Docker socket.
Here compose starts it, and no container mounts the socket.
Without the socket, the platform cannot start a dedicated agent.
`vca dpg bootstrap credebl` binds the shared agent to the organisation `Platform-admin`.
It then gives the organisation of the deployment a wallet in the agent.
The platform checks an agent address with a pattern that needs dots.
So the agent has the network alias `credebl-agent.vca.internal`.
The agent reads its transports and Indy ledgers from `dpg/credebl-agent.json`.
Its keys come from `deploy/credebl/.env`.
Set `CREDEBL_AGENT_ENDPOINT` to the public address of its port 9001 on a public host.
The host port is 17182, and `CREDEBL_AGENT_HOST_PORT` changes it.

A VCA service never needs a DPG rebuild.
A DPG upgrade is a version change in one file.

### Stack secrets

`vca setup` writes `deploy/<dpg>/.env` for every stack with mode 0600
(ADR-055 decision 1).
It holds the database and key store passwords of the stack file.
Each value has 32 random letters and digits.
A later run of any role keeps every value it finds, so the passwords
of the volumes stay valid.
The main compose file reads the file as the `env_file` of the include.
The stack file requires each value with `${NAME:?set by vca setup}`.
No default password ships.
Compose checks the values of every included file, so every setup run
writes the file of every stack.
`vca deploy` stops before compose when a file is missing.
Each file records when its secrets began in `VCA_STACK_SECRETS_SINCE`.
A later run keeps that time.

| File | Variables |
|---|---|
| `deploy/waltid/.env` | `WALTID_DB_PASSWORD` and the four `WALTID_WALLET_*` keys |
| `deploy/inji/.env` | `INJI_DB_PASSWORD`, `INJI_CERTIFY_KEYSTORE_PASSWORD`, `INJI_ESIGNET_DB_PASSWORD`, `INJI_MIMOTO_DB_PASSWORD`, `INJI_MIMOTO_KEYSTORE_PASSWORD`, `INJI_VERIFY_DB_PASSWORD` |
| `deploy/credebl/.env` | `CREDEBL_DB_PASSWORD`, `CRYPTO_PRIVATE_KEY`, `PLATFORM_WALLET_PASSWORD`, `PLATFORM_SEED`, `CREDEBL_AGENT_WALLET_KEY`, `CREDEBL_AGENT_API_KEY`, `CREDEBL_SCHEMA_FILE_SERVER_SECRET`, `CREDEBL_SCHEMA_FILE_SERVER_TOKEN` |

A database volume keeps the password of its first start.
If you remove a stack `.env`, remove the volumes of that stack too.

### CREDEBL platform admin

A CREDEBL issuer, holder or verifier pair needs
`VCA_CREDEBL_PLATFORM_ADMIN_EMAIL` (ADR-055 decision 4).
It has no default, so setup stops without it.
Setup writes it as `PLATFORM_ADMIN_EMAIL` into `deploy/credebl/.env`.
Every platform service reads that file.
`vca dpg bootstrap credebl` initialises the CREDEBL database once.
It runs the initialisation image of the release in the profile `credebl-init` for that.
No pair names the profile, so `docker compose up` never starts it.
The run then signs in as that platform admin.
It encrypts the password with `CRYPTO_PRIVATE_KEY`, as the platform expects.
Set `VCA_BOOTSTRAP_ADMIN_PASSWORD` to the password of the platform admin
for that run.

### walt.id configuration

walt.id 0.18.2 reads the files of its `config` folder at start.
Code defaults fill every value that no file sets.
Without a file, the issuer API lists the example types of the release.
The wallet API then runs on the defaults of the release.
So `vca setup` writes both folders (ADR-054).

The issuer pair gets `deploy/issuer-waltid/config/credential-issuer-metadata.conf`.
It holds one entry per wire format: `vca_jwt_vc_json`, `vca_ldp_vc`,
`vca_vc_sd_jwt`, `vca_dc_sd_jwt` and `vca_mso_mdoc`.
The walt.id adapter signs each schema through the entry of its format.
The credential carries the type of the schema.
The portals list the schemas that the adapter registered.
They never list a catalogue entry.

The holder pair gets `auth.conf`, `ktor-authnz.conf`,
`registration-defaults.conf`, `db.conf` and `_features.conf` under
`deploy/holder-waltid/config`.
The login keys and the hash pepper come from `deploy/waltid/.env`.
`db.conf` holds the database password of the stack.
A new wallet gets no issuer, and the developer mode stays off.
The files with a key have mode 0600.
The release image runs as root, so the container reads them.
`vca dpg upgrade-secrets` writes `db.conf` again when it changes the
database password.

The stack file mounts `../issuer-waltid/config` at
`/waltid-issuer-api/config` and `../holder-waltid/config` at
`/waltid-wallet-api/config`, both read only.
The nightly contract run starts the wallet API on these files.

### Upgrade from shared passwords

An earlier release ran every stack on fixed passwords.
Its volumes still hold them, so the new passwords of setup fail there.
Run these steps once on a host with volumes of that release:

```sh
vca setup --role <role> --dpg <dpg>
vca dpg upgrade-secrets
vca doctor --role <role> --dpg <dpg>
vca deploy --role <role> --dpg <dpg>
```

The first `vca setup` run on such a host finds no stack `.env`.
It asks Docker for the volumes below.
For each volume it finds, it writes the old password into the new
stack `.env`.
It names the variable and asks you to rotate it.
It prints no password.
A host where setup cannot reach Docker gets new passwords and a line
that names `vca dpg upgrade-secrets`.

`vca dpg upgrade-secrets` handles a stack `.env` that already exists.
It reads the creation time of each volume below.
A volume older than `VCA_STACK_SECRETS_SINCE` gets its old password in
the stack `.env`.
Other values stay.
The command prints one line per value and no password.
`vca doctor` fails a volume older than the stamp with another password.
It passes a volume with its old password and asks you to rotate it.

| Volume | Variable |
|---|---|
| `vca_waltid-db` | `WALTID_DB_PASSWORD` |
| `vca_inji-certify-db` | `INJI_DB_PASSWORD` |
| `vca_inji-certify-keys` | `INJI_CERTIFY_KEYSTORE_PASSWORD` |
| `vca_inji-esignet-db` | `INJI_ESIGNET_DB_PASSWORD` |
| `vca_inji-mimoto-db` | `INJI_MIMOTO_DB_PASSWORD` |
| `vca_inji-mimoto-keys` | `INJI_MIMOTO_KEYSTORE_PASSWORD` |
| `vca_inji-verify-db` | `INJI_VERIFY_DB_PASSWORD` |
| `vca_credebl-db` | `CREDEBL_DB_PASSWORD` |

Rotate an old database password soon after the upgrade:

1. Delete the line of the variable from the stack `.env`.
2. Run `vca setup` for a pair of the stack. It generates a new value.
3. Set that value in the database with `ALTER USER <user> PASSWORD '<value>'`.
   Run it through `docker compose exec` on the Postgres container of the volume.
4. Run `vca deploy` for every pair of the stack.

A key store password protects the keys in its volume.
To rotate it, change the password of the store with `keytool -storepasswd`, then follow steps 1, 2 and 4.
You can also remove the key volume. The key manager then makes new keys, and credentials of the old keys fail their checks.

### Key certificates

The key managers of Inji Certify and Mimoto make self signed key
certificates (ADR-055 decision 3).
Their subject names the operator, not an example host.
`vca setup` asks two questions for an Inji issuer or holder pair:

| Setting | Default | What it sets |
|---|---|---|
| `VCA_ORGANISATION_NAME` | The public host | The organisation of the subject |
| `VCA_ORGANISATION_UNIT` | The role, for example `Issuer` | The organisational unit of the subject |

Each value has 64 characters or fewer.
Setup writes `INJI_KEY_CERT_CN` (the public host), `INJI_KEY_CERT_O`,
and `INJI_KEY_CERT_OU` to the `.env` of the pair.
The subject has no location, state, or country.
The key manager makes a certificate at its first start.
Remove the key volume to make a new one with another subject.

### The Inji issuer stack

The `issuer-inji` profile runs Inji Certify 0.14.0 as the injistack
compose file of the release does.
`deploy/vca/dpg/inji/certify/` holds its properties and the init
scripts of its database.
Its `SOURCE.md` cites each upstream file.
Certify checks every access token against one issuer, so the profile
runs it twice (ADR-049):

| Container | What it does | Host port |
|---|---|---|
| `inji-certify` | Its own authorization server. The adapter stages claims, issues, and presents here. | 17081, `INJI_CERTIFY_HOST_PORT` |
| `inji-certify-authcode` | It takes the tokens of the holder authorization server of the adapter. Inji Web claims here, and so does a wallet with an authorization code offer. | none |
| `inji-certify-postgres` | The database of both, from `certify_init.sql` of the release and `vca_claims.sql` | none |
| `inji-certify-nginx` | The issuer metadata of each Certify at the root | none |

Both containers sign with the keys of the volume `inji-certify-keys`.
`inji-certify-authcode` starts once `inji-certify` is ready.
`vca setup` sets `VCA_INJI_OFFER_ISSUER` of the issuer pair to
`http://inji-certify-nginx:8091`, the address of `inji-certify-authcode`.

Both containers issue from the VCA claims store (ADR-051).
The database starts with no credential configuration and no data row.
The adapter of the issuer pair writes one file per staged subject into
the volume `inji-claims`.
The Postgres of Certify reads the files through `file_fdw`.
The volume sits in memory, so a row lasts at most until the host
restarts.
An offer lives 15 minutes by default, so this loses nothing an issuer
needs.
`docs/dpg-adapter-inji.md` describes the table.

| Variable | Default | What it sets |
|---|---|---|
| `INJI_DB_PASSWORD` | Generated by `vca setup` | The password of the Certify database |
| `INJI_CERTIFY_KEYSTORE_PASSWORD` | Generated by `vca setup` | The password of the key store of the Certify key manager |
| `INJI_CERTIFY_DID` | Written by `vca setup` | The issuer DID of both containers: `did:web` of the public host of the issuer pair |
| `INJI_ADAPTER_URL` | Written by `vca setup` | The adapter of the issuer pair on the compose network |
| `VCA_INJI_IAR_IDENTITY_CLAIMS` | `vcaSubject` | The claims of a presented credential that name the holder of a presentation during issuance |

The host of `INJI_CERTIFY_DID` serves `/.well-known/did.json` over TLS.
A verifier outside the host resolves the DID there.
Change `VCA_INJI_IAR_IDENTITY_CLAIMS` with `vca setup`, then run
`vca deploy --role issuer --dpg inji`.
The database of an earlier release has another name.
It also lacks the table of the claims store.
Remove the volume `inji-certify-db` once, so the init scripts run.
Then publish each schema again, so the adapter registers it on the
claims store.

### eSignet with a real authenticator

eSignet 1.5.1 and its login page run only when the operator names a
real authenticator (ADR-053).
`vca setup` asks for it on an Inji issuer or holder pair.
The default is `none`, and then the stack runs no eSignet.
A holder then signs in at the holder realm of the stack Keycloak.
The holder authorization server of the adapter sends the holder there (ADR-052).

| `VCA_ESIGNET_AUTHENTICATOR` | What eSignet needs |
|---|---|
| `none` | Nothing. No eSignet container runs. |
| `mosip-ida` | MOSIP IDA with IdRepo, the auth manager, the audit manager, a MISP licence key, and `mosip.ida.client.secret`. The image plugin is `mosip-identity-plugin.jar`. |
| `sunbird-rc` | A Sunbird RC 1.0.0 registry with its search address and the fields of the knowledge based check. The image plugin is `sunbird-rc-plugin.jar`. |
| `custom` | A plugin jar of the operator in `VCA_ESIGNET_PLUGIN_FILE`. |

Every authenticator but `none` needs a properties file in
`VCA_ESIGNET_PROPERTIES_FILE`.
The file names `mosip.esignet.integration.authenticator`, the key
binder, the addresses, and the secrets of the plugin.
The READMEs of `mosip-identity-plugin` and `sunbird-rc-plugin` of
`esignet-plugins` 1.3.1 list the keys.
`vca setup` copies the file to `deploy/esignet-inji/esignet-integration.properties`
with mode 0600.
eSignet reads it as the profile `integration`.
`vca setup` copies a custom jar to `deploy/esignet-inji/vca/`.
The folder `deploy/esignet-inji` holds a `.gitignore` that ignores
everything, so no secret reaches git.
The eSignet image also holds a plugin for tests.
VCA does not offer it, and the stack runs no identity system of its own.

`vca deploy` adds the compose profile `esignet-inji` when the `.env` of
the pair names an authenticator.

| Container | What it does | Host port |
|---|---|---|
| `inji-esignet` | eSignet with the plugin of the authenticator | 17082, `INJI_ESIGNET_HOST_PORT` |
| `inji-esignet-ui` | The login page, oidc-ui 1.5.1 | 17089, `INJI_ESIGNET_UI_HOST_PORT` |
| `inji-esignet-postgres` | The database of eSignet | none |
| `inji-esignet-redis` | The cache of eSignet | none |

A browser opens the login page at `INJI_ESIGNET_PUBLIC_URL`.
eSignet puts that address in its tokens.
`vca setup` writes it into the `.env` of an Inji issuer or holder pair
that runs eSignet:

| Deployment | `INJI_ESIGNET_PUBLIC_URL` |
|---|---|
| Local | `http://localhost:17089` |
| Base domain | `https://issuer-inji.<domain>` |
| Issuer pair on a host of its own | The public URL of the Inji issuer pair |
| Holder pair with no issuer host | `http://<holder host>:17089` |

The Caddyfile of the Inji issuer pair publishes the login page on its
host when eSignet runs.
The routes are in the route table of the getting started guide.
The page keeps its files under `/esignet-ui`, so `/static` stays with
VCA.
eSignet names its key set under `/v1/esignet`, so the key set of the
pair host stays with the auth service.
An authorization code offer names the holder authorization server of
the adapter, not eSignet (ADR-052).
`vca setup` also writes `VCA_INJI_ESIGNET_URL`, so the adapter lists
eSignet among the components of the stack.

eSignet becomes the holder provider of the holder authorization server
of the issuer pair (ADR-053 decision 4).
`vca setup` of the issuer pair makes the key of the VCA client once, in
`deploy/esignet-inji/vca-client.pem` with mode 0600.
It writes the client and the key into the `.env` of the pair, the key
on one line.
The adapter then adds eSignet to its provider registry with
`private_key_jwt`.
It turns the seeded holder realm of the stack Keycloak off once.
The admin portal can turn that realm on again.
`vca dpg bootstrap inji` registers the VCA client in eSignet with the
same key.
The issuer run adds the callback of the holder authorization server as
a redirect URI.
The claims of a person come from the userinfo endpoint of eSignet, not
from the ID token.
The server reads that signed answer and checks it against the key set
of eSignet.
It keeps only the claims that the provider record vouches for.
eSignet sends `phone_number_verified` but no `email_verified`.
So list a claim such as `individual_id` in the admin portal to bind on
it.
The run adds no identity anywhere (ADR-050).
The people who sign in come from the identity system of the operator.
`INJI_ESIGNET_DB_PASSWORD` sets the password of the database.
`vca setup` generates it.

### The Inji holder stack

The `holder-inji` profile runs Mimoto 0.21.0 and Inji Web 0.16.0.
`deploy/vca/dpg/inji/mimoto/` holds their files, and its `SOURCE.md`
names the upstream files of each release.

| Container | What it does | Host port |
|---|---|---|
| `inji-mimoto` | The wallet backend of Inji Web | 17084, `INJI_MIMOTO_HOST_PORT` |
| `inji-mimoto-postgres` | The Mimoto database, from the init script of the release | none |
| `inji-mimoto-redis` | The Mimoto sessions | none |
| `inji-web` | The wallet of the holder in the browser | 17085, `INJI_WEB_HOST_PORT` |

Mimoto opens a wallet session from the ID token of the holder login.
Its token login provider `google` trusts the realm `vca-holder-realm`
of the stack Keycloak with the client `vca-holder`.
The browser signs in to Inji Web through the same realm.
`vca setup` adds the Mimoto callback of Inji Web to that client.

`vca dpg bootstrap inji --role holder` writes the key of the wallet
client `vca-inji` into `deploy/mimoto-inji/oidckeystore.p12`.
Mimoto signs its token call at the holder authorization server with
that key when the holder claims in Inji Web.
The password sits in `deploy/mimoto-inji/.env`, and both files have
mode 0600.
Run `vca deploy --role holder --dpg inji` again after the bootstrap, so
Mimoto reads the password.

The stack file reads these variables:

| Variable | Default | What it sets |
|---|---|---|
| `INJI_WEB_PUBLIC_URL` | `http://localhost:17085` | The address of Inji Web in the browser |
| `INJI_MIMOTO_HOLDER_LOGIN_URL` | `http://localhost:17080` | The address of the stack Keycloak in the browser |
| `INJI_MIMOTO_TOKEN_LOGIN_ISSUER` | `http://inji-keycloak:8080/realms/vca-holder-realm` | The issuer that the token login accepts |
| `INJI_MIMOTO_TOKEN_LOGIN_CLIENT_ID` | `vca-holder` | The audience that the token login accepts |
| `INJI_MIMOTO_DB_PASSWORD` | Generated by `vca setup` | The password of the Mimoto database |
| `INJI_MIMOTO_KEYSTORE_PASSWORD` | Generated by `vca setup` | The password of the key store of the Mimoto key manager |

`vca setup` writes the first two variables from the addresses of the
deployment, and `VCA_INJI_WEB_URL` of the adapter with the first one.
It adds `<Inji Web address>/v1/mimoto/oauth2/callback/google` to the
redirect URIs of the client `vca-holder`.
It also writes the issuer list and the trusted verifiers of Mimoto into
`deploy/mimoto-inji/` (P6-I7h):

| File | What it names |
|---|---|
| `mimoto-issuers-config.json` | `inji-certify-authcode` on the compose network. The redirect page and the token proxy of Inji Web. The audience is the token endpoint of the holder authorization server of the issuer pair. The proxy is that endpoint on the compose network. |
| `mimoto-trusted-verifiers.json` | The page of Inji Verify as the client. The answer endpoint and the key set of the Inji Verify service. |

The addresses follow the deployment:

| Container | Local | Base domain |
|---|---|---|
| `inji-web` | `http://localhost:17085` | `https://inji-web.<domain>` |
| `inji-verify-service` | `http://localhost:17086` | `https://inji-verify-service.<domain>` |
| `inji-verify-ui` | `http://localhost:17087` | `https://inji-verify-ui.<domain>` |

Under a base domain, the Caddyfile of the Inji holder pair publishes
the host of Inji Web.
The Caddyfile of the Inji verifier pair publishes the two hosts of
Inji Verify.
A pair on a public host with no base domain names the host port on
that host.
A holder setup reads the addresses of Inji Verify from the verifier pair
directory when it finds one.
Run `vca setup` for the holder pair again after the verifier pair moves.
`vca doctor` checks the Inji Web port of a holder pair.

### Presentation during issuance on the Inji stack

Certify 0.14.0 can ask the holder to present a credential before it
issues. It asks Inji Verify for the request and checks the answer there.
So the `issuer-inji` profile runs Inji Verify too, with its
database. Certify reads the presentation definition over HTTP from
`/iar/presentation-definition.json` of the Inji adapter (ADR-051
decision 6). The issuer sets the credential to present on the issuer
portal. Until then the adapter answers 404, and an offer that needs a
presentation fails. `vca setup` sets
`VCA_INJI_PRESENTATION_DURING_ISSUANCE=true` for the Inji issuer pair,
so the issue page offers the step. The folder `SOURCE.md` names the
upstream files.

Inji Verify listens on 8080 and its UI on 8000, as the release does.
The host ports stay 17086 and 17087. A wallet posts its answer to the
address of `INJI_VERIFY_PUBLIC_URL`. `INJI_VERIFY_DID_HOST` sets the
host of its `did:web`. The issuer and verifier profiles both run
Inji Verify, so `vca setup` writes both variables into the `.env` of
both pairs. The values follow the table of the Inji holder stack above.

### The identity provider

Every stack ships Keycloak 25.0.
A laptop deployment then needs no other identity provider.
`vca setup` fills `VCA_OIDC_DISCOVERY_URL` with the realm of the role at
the Keycloak of the stack, on the compose network.
`<role>` is `admin`, `issuer`, `holder`, or `verifier`:

| DPG | Keycloak container | Host port | Default `VCA_OIDC_DISCOVERY_URL` |
|---|---|---|---|
| `waltid` | `waltid-keycloak` | 17010 | `http://waltid-keycloak:8080/realms/vca-<role>-realm/.well-known/openid-configuration` |
| `inji` | `inji-keycloak` | 17080 | `http://inji-keycloak:8080/realms/vca-<role>-realm/.well-known/openid-configuration` |
| `credebl` | `credebl-keycloak` | 17180 | `http://credebl-keycloak:8080/realms/vca-<role>-realm/.well-known/openid-configuration` |

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

### One realm per role

`vca setup` writes `deploy/keycloak-<dpg>/vca-<role>-realm.json`
(ADR-035 decision 1).
Each role of a stack has its own realm and its own user base:
`vca-admin-realm`, `vca-issuer-realm`, `vca-holder-realm`, and
`vca-verifier-realm`.
A realm holds one client with the id `vca-<role>` and a generated
client secret.
The client has the exact redirect URI of the pair, the authorization
code flow, and PKCE S256.
Self registration is on in every realm.
A new user of the issuer realm gets the role `issuer-operator`.
A new user of the verifier realm gets `verifier-operator`.
A new user of the holder realm gets `holder`.
A new user of the admin realm gets no role.
The bootstrap token binds the first admin (ADR-035 decision 6).
Turn self registration off in the admin realm after the first run.

Keycloak imports every realm of the directory on its first start.
The stack file mounts `deploy/keycloak-<dpg>` read only.
The directory has mode 0755 and a realm file has mode 0644, so the
Keycloak user inside the container reads them.
Keycloak parses every JSON file of the directory, so nothing but a
realm ends in `.json` there.
A later `vca dpg bootstrap <dpg> --role <role>` run creates or updates
the realm of that role through the Keycloak admin API.

### The Keycloak administrator

`vca setup` writes `deploy/keycloak-<dpg>/.env` with mode 0600
(ADR-035 decision 7).
It holds `KEYCLOAK_ADMIN=admin` and a generated
`KEYCLOAK_ADMIN_PASSWORD` of 32 random bytes.
Every role of the stack shares the file, and a later run keeps the
password.
No default password ships.
Sign in to the administration console at `VCA_OIDC_PUBLIC_URL` with
these values.
`vca dpg bootstrap` reads the same file; `VCA_BOOTSTRAP_ADMIN_PASSWORD`
overrides it.

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
| `holder-inji` | `http://inji-mimoto:8099` |
| `holder-credebl` | `http://credebl-api-gateway:5000` |
| `verifier-waltid` | `http://waltid-verifier-api:7003` |
| `verifier-inji` | `http://inji-verify-service:8080` |
| `verifier-credebl` | `http://credebl-api-gateway:5000` |

The admin role calls no DPG, so it has no default.
The walt.id verifier pair also gets `VCA_WALTID_VERIFIER2_URL`, the
address `http://waltid-verifier-api2:7004` of verifier API 2.
Verifier API 2 answers DCQL requests.
Its host port is 17004, and `WALTID_VERIFIER2_HOST_PORT` changes it.
`WALTID_VERIFIER2_BASE_URL` sets the address a wallet opens.
Set `VCA_DPG_URL` yourself when the DPG runs on another host.
Your value always wins over the default.

## The resource floor

One role with one DPG stays under 4 GB of memory (ADR-008 decision 7).
The Inji issuer is one exception (ADR-049).
Every CREDEBL role that calls the platform is the other (ADR-045).
The whole legacy stack needed 8 GB to 12 GB and about 25 ports.

| Role and DPG | VCA services | VCA memory | DPG memory | Total memory | CPUs |
|---|---|---|---|---|---|
| `issuer-waltid` | 9 | 864 MiB | 2048 MiB | 2912 MiB | 3.25 |
| `issuer-inji` | 9 | 864 MiB | 4000 MiB | 4864 MiB | 3.25 |
| `issuer-credebl` | 9 | 864 MiB | 5184 MiB | 6048 MiB | 3.25 |
| `holder-waltid` | 3 | 288 MiB | 2048 MiB | 2336 MiB | 1.75 |
| `holder-inji` | 3 | 288 MiB | 3584 MiB | 3872 MiB | 1.75 |
| `holder-credebl` | 3 | 288 MiB | 5184 MiB | 5472 MiB | 1.75 |
| `verifier-waltid` | 7 | 672 MiB | 2048 MiB | 2720 MiB | 2.75 |
| `verifier-inji` | 7 | 672 MiB | 2560 MiB | 3232 MiB | 2.75 |
| `verifier-credebl` | 7 | 672 MiB | 5184 MiB | 5856 MiB | 2.75 |
| `admin-waltid` | 2 | 192 MiB | 512 MiB | 704 MiB | 1.5 |
| `admin-inji` | 2 | 192 MiB | 512 MiB | 704 MiB | 1.5 |
| `admin-credebl` | 2 | 192 MiB | 512 MiB | 704 MiB | 1.5 |

One stack is the four roles of one DPG together:

| Selection | `waltid` | `inji` | `credebl` |
|---|---|---|---|
| `--all --dpg <dpg>` | 4064 MiB | 7040 MiB | 7200 MiB |

`--all` alone starts every role of every DPG and needs 18304 MiB.
The four roles of one DPG share one DPG stack and one Keycloak, so a
stack counts once.

The VCA figure is 96 MiB per service.
The admin role runs the admin service and the trust registry.
The holder role runs the wallet portal, the wallet auth service, and one
DPG adapter.
Each service is one static Go binary in a distroless image.
The DPG figure is the floor of the stack in `deploy/vca/dpg/`.
The Inji holder role adds 1024 MiB to the Inji stack.
It runs Mimoto with its Postgres and its Redis, and Inji Web.
The Inji issuer role adds 1440 MiB.
It runs Inji Verify with its Postgres, and the nginx of the presentation definition.
Certify checks a presentation during issuance with them.
It also runs the second Certify, which takes the tokens of the holder authorization server.
Certify 0.14.0 takes the tokens of one authorization server only, so the stack runs it twice (ADR-049).
So the `issuer-inji` pair needs more than the 4 GB target of ADR-008 decision 7.
`vca doctor` marks it in the floor report.
The CREDEBL figure is the sum of the services of `dpg/credebl.yaml`.
Keycloak takes 512 MiB, PostgreSQL 256 MiB, NATS 64 MiB, Redis 64 MiB.
The schema file server takes 128 MiB and the API gateway 384 MiB.
Each of the 17 other platform services takes 192 MiB.
The shared Credo agent takes 512 MiB.
So every CREDEBL pair except the admin needs more than the 4 GB target (ADR-045 consequence 2).
These figures are estimates until the nightly run measures the stack.
`vca doctor` marks those pairs in the floor report.
eSignet runs only with an authenticator (ADR-053).
It adds 1024 MiB to an Inji issuer or holder: eSignet, its Postgres, its Redis, and its login page.
The floor report of `vca doctor` shows both floors of those pairs.
An added figure counts for each role that brings it.
The admin role talks to no DPG.
Its profile starts only the Keycloak of the stack.
The landing adds 96 MiB once, whatever the selection, because every profile starts the one landing container.

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

The chart of the Inji adapter lists the claims store in `stackMounts`
(ADR-051).
Inji Certify runs outside the charts, so its Postgres must read the
same volume.
Name a claim that both mount:

```sh
helm upgrade vca deploy/vca/helm/vca \
  --set 'dpg-adapter-inji.stackMounts[0].name=inji-claims' \
  --set 'dpg-adapter-inji.stackMounts[0].mountPath=/vca/claims' \
  --set 'dpg-adapter-inji.stackMounts[0].env=VCA_INJI_CLAIMS_DIR' \
  --set 'dpg-adapter-inji.stackMounts[0].existingClaim=<claim>'
```

The chart then mounts the claim and sets `VCA_INJI_CLAIMS_DIR`.
Without a claim, the issuer stages no subject.

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
- [ADR-047](adr/ADR-047-public-rpc-surface.md): the paths the reverse proxy publishes.
- `verifiably-go/docs/dpg-matrix.md`: the DPG versions.
- [Compose profiles](https://docs.docker.com/compose/how-tos/profiles/)
- [Helm charts](https://helm.sh/docs/topics/charts/)
