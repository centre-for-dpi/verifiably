# Get started with the Verifiable Credentials Adapters

This page takes you from a clone of the repository to a running role.
Read it first. It covers a laptop and a server with a public name.

## Prerequisites

| Need | Version | When | How to check |
|---|---|---|---|
| Go | 1.25 or newer | Only to build `vca` from source | `go version` |
| Docker Engine | 24 or newer | Always | `docker version` |
| Docker Compose | v2, the `docker compose` plugin | Always | `docker compose version` |
| Memory | 4 GB free per role | Always | `free -m` |
| Disk | 10 GB free for the images and the volumes | Always | `df -h .` |
| Host ports | One block of ports per role and DPG pair | Always | `vca ports --role issuer --dpg waltid` |

A pair starts at host port 18000. Each pair owns its own block.
`vca ports --role <role> --dpg <dpg>` prints every port of one pair.
`docs/deploy.md` holds the memory floor of each pair.

One command checks all of this for you:

```sh
vca doctor --role issuer --dpg waltid
```

`doctor` prints one line per prerequisite with a pass or a fail.
A fail line names the fix. The command exits with status 1 on any fail.
Add `--from-source` when you build the tool with Go.

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
   go build -o vca ./cmd/vca
   sudo install vca /usr/local/bin/
   ```

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

1. Set the public URL to the portal of the role:

   ```sh
   export VCA_PUBLIC_URL=http://localhost:18002
   ```

   18002 is the host port of the issuer portal.
   `vca ports --role issuer --dpg waltid` prints the number for you.

2. Run `vca setup`, `vca deploy --build`, and `vca dpg bootstrap`.
3. Open `http://localhost:18002` in a browser.
   The wallet portal, the verifier portal, and the admin portal each have
   their own host port. `vca ports` prints them.

The setup command writes a `Caddyfile`, but a local run does not need it.
The identity provider of a local run uses a self-signed certificate.
Your browser asks you to accept it once.

## The server path

Use this path on a machine with a public name.

1. Point a DNS A record or AAAA record at the server.
2. Open port 80 and port 443 in the firewall.
   Caddy needs both to get a Let's Encrypt certificate.
3. Set the public URL to that name:

   ```sh
   export VCA_PUBLIC_URL=https://issuer.example
   ```

4. Run `vca doctor --role issuer --dpg waltid`.
   It checks that the name resolves and that the two ports are free.
5. Run the setup, the deploy, and the bootstrap of the next section.
6. Start Caddy with the generated `deploy/issuer-waltid/Caddyfile`.
   Caddy gets the certificate from Let's Encrypt on its first start.

`vca setup` writes the secrets with mode 0600 into
`deploy/<role>-<dpg>/`.
Back up that directory. It holds the `.env` file and the signing key.
Without it you cannot start the same deployment again.

## The first run

This run starts the issuer role with walt.id on a laptop.

```sh
vca doctor --role issuer --dpg waltid --from-source
vca setup --role issuer --dpg waltid
vca deploy --role issuer --dpg waltid --build
vca dpg bootstrap waltid --role issuer
vca status --role issuer --dpg waltid
```

`--build` builds every image from the source of this repository.
Use it until the first release publishes the images.
`vca images build --role issuer --dpg waltid` does the same builds and
tags each image `local`.

Open the portal at the host port that `vca ports` prints.
Stop the deployment when you finish:

```sh
vca down --role issuer --dpg waltid
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
vca doctor --all --dpg waltid   # one stack fits a laptop; drop --dpg for all three
vca deploy --role issuer --dpg waltid --build --dry-run
vca status --role issuer --dpg waltid
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
