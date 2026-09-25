# Get started with the Verifiable Credentials Adapters

This page takes you from a clone of the repository to a running role.
Read it first. It covers a laptop and a server with a public name.

## Prerequisites

| Need | Version | When | How to check |
|---|---|---|---|
| Go | 1.25 or newer | Only to build `vca` from source | `go version` |
| buf | 1.47.2 | Only to change the proto files. `make bootstrap` installs it and checks its SHA-256 | `buf --version` |
| Docker Engine | 24 or newer, and your user in the `docker` group | Always | `docker version` |
| Docker Compose | v2, the `docker compose` plugin | Always | `docker compose version` |
| Memory | 3.5 GB free for one role and one DPG | Always | `free -m` |
| Disk | 10 GB free for the images and the volumes | Always | `df -h .` |
| Host ports | One block of ports per role and DPG pair | Always | `vca ports --role <role> --dpg <dpg>` |

A pair starts at host port 18000. Each pair owns its own block.
The Keycloak of each DPG stack has its own host port as well.
`vca ports --role <role> --dpg <dpg>` prints every port of one pair.
`docs/deploy.md` holds the memory floor of each pair.

One command checks all of this for you:

```sh
vca doctor --role <role> --dpg <dpg>
```

`<dpg>` is one of `waltid`, `inji`, `credebl`; the three are equal.
`<role>` is one of `issuer`, `holder`, `verifier`, `admin`.
Leave either flag out and the command asks for it with a numbered menu
of every value. A run that is not a terminal, or that passes
`--non-interactive`, fails and names the missing flag.

`doctor` prints one line per prerequisite with a pass or a fail.
A fail line names the fix. The command exits with status 1 on any fail.
Add `--from-source` when you build the tool with Go.
`vca doctor --suggest` prints the selection that fits this host.

## Get the binary

There are three ways. Pick one.

1. Download the binary of a GitHub Release, when a release exists.
   Unpack it and copy `vca` to `/usr/local/bin/`.
2. Install it with Go, when a tag exists:

   ```sh
   go install github.com/centre-for-dpi/vc-adapters/cmd/vca@<tag>
   ```

3. Build it from the source in this repository:

   ```sh
   cd vca
   go mod tidy
   go install ./cmd/vca
   ```

   `go install` writes the binary to `$HOME/go/bin`, which needs no
   root access. Add that directory to your `PATH`. If you want a
   system-wide copy and you have root access, run
   `sudo install $HOME/go/bin/vca /usr/local/bin/` instead.

Until the first tag, only the source build works.
No release and no tag exist yet, so use way 3.
`go mod tidy` writes `go.sum`, which the repository does not ship yet.
`make install` does the same build into your `GOBIN` directory.

## Where to run the commands

You can run `vca` in any directory.
The tool finds the repository root and reads `deploy/vca/compose.yaml`
under it. It looks in this order:

1. The `--repo <path>` flag.
2. The `VCA_REPO` variable.
3. The first parent directory of your working directory that holds
   `ADR.md`.

An error names `ADR.md` when the path you gave is not the root.

## The local machine path

Use this path on a laptop. There is no TLS and no Caddy.
Run one role with one DPG. Four commands start it:

```sh
vca doctor --from-source
vca setup
vca deploy --build
vca dpg bootstrap
```

Each command asks for the role and the DPG, because no flag names them.
Name them ahead of time with `--role <role> --dpg <dpg>` instead.

`vca setup` asks one setting question on a laptop: the public URL.
Press Enter to keep the default. Every other value has a default too.
The public URL is `http://localhost` with the host port of the home
service of the role. "Where each page lives" names the home service.
The DPG URL is the container of the stack.
The identity provider is the Keycloak of the stack.
The command prints a summary of every value before it writes.

Open the home page of the role in a browser.
`vca deploy` prints the pages at the end.
The issuer home of the first issuer pair is
`http://localhost:18002/issuer/`.
The wallet, the verification results, and the admin portal each have
their own host port.
`vca ports --role <role> --dpg <dpg>` prints every port of one pair.
A laptop has no reverse proxy, so each service answers on its own host
port.
The login redirect of the pair then does not reach the auth service.
Use the server path for a login test.

One pair needs 704 MiB to 3424 MiB of free memory:

| Role | `waltid` | `inji` | `credebl` |
|---|---|---|---|
| `issuer` | 2912 MiB | 3424 MiB | 3424 MiB |
| `holder` | 2336 MiB | 2848 MiB | 2848 MiB |
| `verifier` | 2720 MiB | 3232 MiB | 3232 MiB |
| `admin` | 704 MiB | 704 MiB | 704 MiB |

`docs/deploy.md` holds the full table.
`vca doctor --suggest` prints the selection that fits this host.

`--all` is the server-class option.
`--all --dpg <dpg>` starts the four roles of one stack:

| Selection | `waltid` | `inji` | `credebl` |
|---|---|---|---|
| `--all --dpg <dpg>` | 3968 MiB | 4480 MiB | 4480 MiB |

`--all` alone starts every role of every DPG and needs 12928 MiB.
The four roles of one DPG share one DPG stack and one Keycloak, so a
stack counts once.

The setup command writes a `Caddyfile`, but a local run does not need it.
The Keycloak of the stack serves the login page on its own host port:

| DPG | Login page |
|---|---|
| `waltid` | `http://localhost:17010` |
| `inji` | `http://localhost:17080` |
| `credebl` | `http://localhost:17180` |

## The server path

Use this path on a machine with a public name. The machine can run
other projects. VCA binds only its own host ports, 17000 to 19999, on
the loopback address. It hands the reverse proxy of the machine one
file per pair.

1. Point one wildcard DNS record, `*.<domain>`, at the server.
   For example `*.labs.example`.
   Every pair then gets `https://<role>-<dpg>.<domain>`, for example
   `https://issuer-waltid.labs.example`, and the Keycloak of each stack
   gets `https://<dpg>-keycloak.<domain>`.
2. Run the setup with the base domain:

   ```sh
   vca setup --all --dpg <dpg> --domain <domain>
   ```

   A terminal run with more than one pair asks the base domain when the
   flag is absent.
3. Run `vca doctor --all --dpg <dpg>`.
   It checks that every host name resolves and reports who holds port
   80 and port 443.
4. Run the deploy and the bootstrap of the next section.
5. Give the reverse proxy the generated sites.
   `vca proxy` prints the Caddyfile of every pair as one snippet.
   Each site sends its requests to `127.0.0.1:<host port>`.
   A Caddy that already runs on the machine takes the snippet with one
   import line and a reload:

   ```sh
   vca proxy --all | sudo tee /etc/caddy/vca.caddy >/dev/null
   echo 'import /etc/caddy/vca.caddy' | sudo tee -a /etc/caddy/Caddyfile
   sudo systemctl reload caddy
   ```

   The copy under `/etc/caddy` matters: the `caddy` user cannot read a
   file under your home directory.
   Run `vca proxy` again after every `vca setup`.
   A machine with no web server starts Caddy with the same import line.
   Caddy gets one certificate per host name from Let's Encrypt on its
   first start. Port 80 and port 443 must be open in the firewall.
   Another reverse proxy, such as nginx, takes the same host names and
   host ports from the snippet.
6. Open the pages that `vca deploy` prints at the end.
   The root of a pair sends the browser to the home page of the role.
   The issuer opens `/issuer/` of the issuance service.
   The holder opens `/wallet/`.
   The verifier opens `/portal/` of the verification results.
   The admin opens `/admin/`.
   The issuer also prints the schema builder at `/builder/`.
   The verifier also prints the citizen check at `/verify/`, the issuer
   discovery pages at `/discovery/`, and the scanner at `/scan/`.
   The login of a page goes to `/auth/login` on the same host name.
   The browser then sees the Keycloak of the stack at
   `https://<dpg>-keycloak.<domain>`.
   "Where each page lives" lists every path.

`vca setup` writes the secrets with mode 0600 into
`deploy/<role>-<dpg>/`.
Back up that directory. It holds the `.env` file and the signing key.
Without it you cannot start the same deployment again.

## Where each page lives

Every service of a pair answers on the one host name of the pair.
The route table in `internal/cli/services.go` says which service takes
which path, and the `Caddyfile` of the pair comes from it.
A service with HTML pages sits at the root, because its pages link
with absolute paths.
An API only service whose public URLs come from its `*_BASE_URL`
setting keeps a prefix.
Its routes name the protocol paths under the prefix.
The reverse proxy removes the prefix before the request reaches the
service.
The proxy publishes a Connect service only when every RPC of it checks
the caller (ADR-047).
It answers `404` to every other `/vca.*` path.
The section "What the proxy publishes" of `deploy.md` lists each
service and the reason.
`/static/*` is the same asset set in every UI service, so the home
service of the role serves it.

The `issuer` role. Its home page is `/issuer/` on `issuance`.

| Path | Service | Note |
|---|---|---|
| `/` | `issuance` | Sends the browser to `/issuer/`. |
| `/issuance/pdf/*` | `issuance` |  |
| `/issuer/*` | `issuance` | A page: Issuer portal. |
| `/identity/*` | `issuance` | A page: Issuer identity. |
| `/issue/*` | `issuance` | A page: Issue. |
| `/notifications/*` | `issuance` | A page: Issuer notifications. |
| `/help/*` | `issuance` | A page: Issuer help. |
| `/static/*` | `issuance` |  |
| `/.well-known/did.json` | `issuance` |  |
| `/issued/chain-head` | `issued-credentials` |  |
| `/issued/jwks.json` | `issued-credentials` |  |
| `/vca.issuerauth.v1.IssuerAuthService/*` | `issuer-auth` |  |
| `/vca.admin.v1.AdminService/*` | `issuer-auth` |  |
| `/.well-known/jwks.json` | `issuer-auth` |  |
| `/token` | `issuer-auth` |  |
| `/auth/*` | `issuer-auth` | A page: Sign in. |
| `/builder/*` | `schema-builder-ui` | A page: Schema builder. |
| `/pdf/preview/*` | `schema-builder-ui` |  |
| `/.well-known/openid-credential-issuer` | `schema-registry` |  |
| `/.well-known/vct/*` | `schema-registry` |  |
| `/vct/*` | `schema-registry` |  |
| `/schemas/*` | `schema-registry` |  |
| `/api/schemas` | `schema-registry` |  |
| `/portal/*` | `schema-registry` | A page: Schemas. |
| `/status-bitstring/status/*` | `status-bitstring` | The service sees the path without `/status-bitstring`. |
| `/status-bitstring/.well-known/jwks.json` | `status-bitstring` | The service sees the path without `/status-bitstring`. |
| `/status-token/status/*` | `status-token` | The service sees the path without `/status-token`. |
| `/status-token/.well-known/jwks.json` | `status-token` | The service sees the path without `/status-token`. |
| `/offers/*` | `dpg-adapter-<dpg>` | Only the `inji` adapter. |
| `/vca.*` | none | The proxy answers 404. |
| Every other path | `issuance` | |

The `holder` role. Its home page is `/wallet/` on `wallet-portal`.

| Path | Service | Note |
|---|---|---|
| `/` | `wallet-portal` | Sends the browser to `/wallet/`. |
| `/vca.walletauth.v1.WalletAuthService/*` | `wallet-auth` |  |
| `/vca.admin.v1.AdminService/*` | `wallet-auth` |  |
| `/.well-known/jwks.json` | `wallet-auth` |  |
| `/auth/*` | `wallet-auth` | A page: Sign in. |
| `/wallet/*` | `wallet-portal` | A page: Wallet. |
| `/static/*` | `wallet-portal` |  |
| `/offers/*` | `dpg-adapter-<dpg>` | Only the `inji` adapter. |
| `/vca.*` | none | The proxy answers 404. |
| `/auth/vca.*` | none | The proxy answers 404. |
| Every other path | `wallet-portal` | |

The `verifier` role. Its home page is `/portal/` on `verifier-results`.

| Path | Service | Note |
|---|---|---|
| `/` | `verifier-results` | Sends the browser to `/portal/`. |
| `/vca.verifierauth.v1.VerifierAuthService/*` | `verifier-auth` |  |
| `/vca.admin.v1.AdminService/*` | `verifier-auth` |  |
| `/.well-known/jwks.json` | `verifier-auth` |  |
| `/token` | `verifier-auth` |  |
| `/auth/*` | `verifier-auth` | A page: Sign in. |
| `/catalog` | `verifier-discovery` |  |
| `/catalog/*` | `verifier-discovery` |  |
| `/discovery/*` | `verifier-discovery` | A page: Issuer discovery. |
| `/oid4vp/*` | `verifier-ingest` |  |
| `/scan/*` | `verifier-ingest` | A page: Scanner. |
| `/portal/*` | `verifier-results` | A page: Verification results. |
| `/verify/*` | `verifier-results` | A page: Citizen check. |
| `/static/*` | `verifier-results` |  |
| `/offers/*` | `dpg-adapter-<dpg>` | Only the `inji` adapter. |
| `/vca.*` | none | The proxy answers 404. |
| Every other path | `verifier-results` | |

The `admin` role. Its home page is `/admin/` on `admin`.

| Path | Service | Note |
|---|---|---|
| `/` | `admin` | Sends the browser to `/admin/`. |
| `/vca.admin.v1.AdminService/*` | `admin` |  |
| `/.well-known/jwks.json` | `admin` |  |
| `/auth/*` | `admin` |  |
| `/device_authorization` | `admin` |  |
| `/token` | `admin` |  |
| `/cli/*` | `admin` |  |
| `/admin/*` | `admin` | A page: Admin portal. |
| `/static/*` | `admin` |  |
| `/trust-registry/trust-list/*` | `trust-registry` | The service sees the path without `/trust-registry`. |
| `/trust-registry/.well-known/*` | `trust-registry` | The service sees the path without `/trust-registry`. |
| `/trust-registry/dedi/*` | `trust-registry` | The service sees the path without `/trust-registry`. |
| `/trust-registry/trust/*` | `trust-registry` | The service sees the path without `/trust-registry`. |
| `/vca.*` | none | The proxy answers 404. |
| Every other path | `admin` | |

`vca deploy` prints the pages of each pair from the same table.

## The first run

The four commands of "The local machine path" start the role and the DPG
you chose in the menus. Check it with:

```sh
vca status --role <role> --dpg <dpg>
```

`--build` builds every image from the source of this repository.
Use it until the first release publishes the images.
`vca images build --role <role> --dpg <dpg>` does the same builds and
tags each image `local`.

Open the home page of the role at the host port that `vca ports`
prints.
Stop the deployment when you finish:

```sh
vca down --role <role> --dpg <dpg>
```

The volumes stay, so the data survives.

## Common errors

| What you see | Why | The fix |
|---|---|---|
| `Command 'vca' not found` | No binary is on your path. | Build it and copy it to `/usr/local/bin/`. See "Get the binary". |
| `missing go.sum entry` | The repository ships no `go.sum`. | Run `go mod tidy` in `vca/` before the build. |
| `pull access denied` or `manifest unknown` | No release published the images yet. | Add `--build` to `vca deploy`, or run `vca images build`. |
| `port is already allocated` | Another program holds a host port. | Stop that program. Or set `VCA_HOST_PORT_<SERVICE>` in the `.env` file of the pair. |
| `no such host` in the browser | The DNS name does not point at the server. | Add the DNS record. Wait for the old answer to expire. |
| `DNS_PROBE_FINISHED_NXDOMAIN` | The host name has no DNS record. `vca doctor` reports it. | Add one wildcard record, `*.<domain>`, or one record per pair. |
| `permission denied` under `/data` in a container log | A data volume from an older image belongs to root. | `vca down --all`, then remove or chown the `vca_` volumes. See "Data volumes" in `deploy.md`. |
| `ERR_SSL_PROTOCOL_ERROR` | A web server holds port 443 but has no certificate for the host name. | Give it the snippet of `vca proxy` and reload it. See step 5 of "The server path". |
| `Cannot connect to the Docker daemon` | The daemon does not run. | Start Docker. Add your user to the `docker` group. |
| `container name is in use outside the vca compose project` | A container from an older compose project, or one you started by hand, holds a name the pair needs. | Run the `docker rm -f` line that the message prints. Then run `vca deploy` again. |
| `The container name "/inji-certify" is already in use` | Same cause, reported by an older `vca` binary. | `docker rm -f inji-certify`, then run `vca deploy` again. |

## How to check it works

```sh
vca doctor --suggest            # the selection that fits this host
vca deploy --role <role> --dpg <dpg> --build --dry-run
vca status --role <role> --dpg <dpg>
```

The dry run prints the compose file, the build override file, and the
commands. It starts nothing.

After a real deploy, open the pages that the command prints:

| Role | Page | What you see |
|---|---|---|
| `issuer` | `/issuer/` | The issuer overview. `/portal/` opens the schemas and `/builder/` opens the schema builder. |
| `holder` | `/wallet/` | The wallet. It sends a citizen with no session to `/auth/login`. |
| `verifier` | `/portal/` | The verification results. `/verify/` is the citizen check. |
| `admin` | `/admin/` | The admin portal. |

The root of a pair answers with a redirect to the home page.
`/auth/login` on the issuer pair sends the browser to the Keycloak of
the stack and comes back to `/auth/callback`.
A `404` at the root means the reverse proxy has an old `Caddyfile`.
Run `vca proxy` again and reload the proxy.

## Reference

- [The vca command line tool](cli.md): every command and every flag.
- [Deployment](deploy.md): the profiles, the ports, and the memory floor.
- [Architecture decisions](adr.md): ADR-007 and ADR-008 define this flow.
- [Docker Engine install](https://docs.docker.com/engine/install/)
- [Docker Compose install](https://docs.docker.com/compose/install/)
- [Go downloads](https://go.dev/dl/)
