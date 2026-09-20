# Get started with the Verifiable Credentials Adapters

This page takes you from a clone of the repository to a running role.
Read it first. It covers a laptop and a server with a public name.

## Prerequisites

| Need | Version | When | How to check |
|---|---|---|---|
| Go | 1.25 or newer | Only to build `vca` from source | `go version` |
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

`vca setup` asks no setting question on a laptop.
Every value has a default.
The public URL is `http://localhost` with the host port of the portal.
The DPG URL is the container of the stack.
The identity provider is the Keycloak of the stack.
The command prints a summary of every value before it writes.

Open the portal of the role in a browser.
The issuer portal of the first pair is `http://localhost:18002`.
The wallet portal, the verifier portal, and the admin portal each have
their own host port.
`vca ports --role <role> --dpg <dpg>` prints every port of one pair.

One pair needs 704 MiB to 3424 MiB of free memory:

| Role | `waltid` | `inji` | `credebl` |
|---|---|---|---|
| `issuer` | 2912 MiB | 3424 MiB | 3424 MiB |
| `holder` | 2336 MiB | 2848 MiB | 2848 MiB |
| `verifier` | 2624 MiB | 3136 MiB | 3136 MiB |
| `admin` | 704 MiB | 704 MiB | 704 MiB |

`docs/deploy.md` holds the full table.
`vca doctor --suggest` prints the selection that fits this host.

`--all` is the server-class option.
`--all --dpg <dpg>` starts the four roles of one stack:

| Selection | `waltid` | `inji` | `credebl` |
|---|---|---|---|
| `--all --dpg <dpg>` | 8576 MiB | 10112 MiB | 10112 MiB |

`--all` alone starts every role of every DPG and needs about 28 GB.

The setup command writes a `Caddyfile`, but a local run does not need it.
The Keycloak of the stack serves the login page on its own host port:

| DPG | Login page |
|---|---|
| `waltid` | `http://localhost:17010` |
| `inji` | `http://localhost:17080` |
| `credebl` | `http://localhost:17180` |

## The server path

Use this path on a machine with a public name.

1. Point a DNS A record or AAAA record at the server.
2. Open port 80 and port 443 in the firewall.
   Caddy needs both to get a Let's Encrypt certificate.
3. Set the public URL to that name:

   ```sh
   export VCA_PUBLIC_URL=https://issuer.example
   ```

4. Run `vca doctor --role <role> --dpg <dpg>`.
   It checks that the name resolves and that the two ports are free.
5. Run the setup, the deploy, and the bootstrap of the next section.
6. Start Caddy with the generated `deploy/<role>-<dpg>/Caddyfile`.
   Caddy gets the certificate from Let's Encrypt on its first start.

`vca setup` writes the secrets with mode 0600 into
`deploy/<role>-<dpg>/`.
Back up that directory. It holds the `.env` file and the signing key.
Without it you cannot start the same deployment again.

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

Open the portal at the host port that `vca ports` prints.
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
| `Cannot connect to the Docker daemon` | The daemon does not run. | Start Docker. Add your user to the `docker` group. |

## How to check it works

```sh
vca doctor --suggest            # the selection that fits this host
vca deploy --role <role> --dpg <dpg> --build --dry-run
vca status --role <role> --dpg <dpg>
```

The dry run prints the compose file, the build override file, and the
commands. It starts nothing.

## Reference

- [The vca command line tool](cli.md): every command and every flag.
- [Deployment](deploy.md): the profiles, the ports, and the memory floor.
- [Architecture decisions](adr.md): ADR-007 and ADR-008 define this flow.
- [Docker Engine install](https://docs.docker.com/engine/install/)
- [Docker Compose install](https://docs.docker.com/compose/install/)
- [Go downloads](https://go.dev/dl/)
