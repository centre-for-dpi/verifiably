# Verifiable Credentials Adapters

Verifiable Credentials Adapters (VCA) is a set of small services. Each
service adds one function that walt.id, Inji, or CREDEBL does not give
you by default. The DPG issues and signs the credentials. The adapters
never hold issuer signing keys.

VCA serves four groups of people:

- Operators, who deploy one role with one DPG.
- Issuer and verifier staff, who use the portals.
- Citizens, who use the wallet and the public check page.
- Readers, who need short documents in plain English.

The Go module is `github.com/centre-for-dpi/vc-adapters`. This folder
replaces the `verifiably` monolith role by role (ADR-030). The monolith
stays in `verifiably-go/` until each role has the same functions.

## Start

Read [Get started](docs/getting-started.md) first. It lists the
prerequisites and the three ways to get the binary. It also holds the
local path, the server path, and the common errors.

Three steps take you from a clone to a running role:

```sh
cd vca && go mod tidy && go install ./cmd/vca   # puts vca in $HOME/go/bin, no root needed
vca doctor --from-source        # asks for the role and the DPG
vca setup && vca deploy --build # asks again, then starts one role with one DPG
```

Each command asks for the role and the DPG when the `--role` and `--dpg`
flags are absent. The menu lists every role and every DPG. `<dpg>` is one
of `waltid`, `inji`, `credebl`; the three are equal. Add the flags to
answer ahead of time, as in `vca deploy --role <role> --dpg <dpg>`.

`vca doctor` checks Docker, the memory, and the ports, and names the fix
for each fail. It prints the memory floor of each selected pair.
`vca setup` asks only for a required value that no source and no default
filled. A laptop run answers no setting question. It writes one `.env`
file per role and DPG pair. `vca deploy` starts the services with Docker
Compose profiles. Use `--build` until the first release publishes the
images. One role with one DPG needs about 3 GB of memory.
`--all --dpg <dpg>` starts the four roles of one stack and needs 4 GB
to 4.5 GB, by DPG. `--all` alone starts every role of every DPG and needs
about 13 GB, so it is a server option. `vca doctor --suggest` prints the
selection that fits your host.

Now, for developers:

1. Run `make bootstrap`. This installs the proto tools.
2. Run `make gen`. This generates Go code from the files in `proto/`.
3. Run `make test`. This runs the unit tests.
4. Run `make cover`. This checks the coverage floor.
5. Run `make ste-lint`. This checks the documents and the decision records.

## Services

Each service has one proto API, one container image, and one document.
The names come from ADR-002.

Deployment:

- `landing`: the front door of a deployment. It explains VCA, lists the stacks that run, and sends each visitor to a role. It runs once per deployment.

Admin:

- `admin`: the super admin API and portal, with man pages and a help page. See [docs/admin.md](docs/admin.md).

Trust:

- `trust-registry`: a signed list of the issuers that a verifier accepts.

Issuer:

- `issuer-auth`: OIDC sign-in for issuer staff and API access for issuer systems.
- `schema-registry`: stores credential schemas and serves them to issuers and verifiers.
- `schema-builder-ui`: a portal page that builds a schema with a live preview.
- `data-source`: connects an issuer to its data, with access control and mapping.
- `issuance`: issues credentials in many formats through the DPG.
- `issued-credentials`: a portal that lists the credentials an issuer has issued.
- `status-bitstring`: publishes a Bitstring Status List for revocation.
- `status-token`: publishes a Token Status List for revocation.

Holder:

- `wallet-auth`: OIDC sign-in for citizens and binding of a holder to a wallet.
- `wallet-portal`: web wallet pages to discover, claim, view, present, and delete credentials. See [docs/wallet-portal.md](docs/wallet-portal.md).

Verifier:

- `verifier-discovery`: a portal where a verifier finds schemas and issuers.
- `verifier-ingest`: accepts a presentation in any supported format and normalises it.
- `verifier-policy`: applies a checklist of rules to a presentation.
- `verifier-results`: stores and shows the results of each check.
- `verifier-combined`: asks for several credentials in one OID4VP transaction.

DPG adapters:

- `dpg-adapter-waltid`: connects VCA to walt.id.
- `dpg-adapter-inji`: connects VCA to Inji Certify, Inji Web, and Inji Verify.
- `dpg-adapter-credebl`: connects VCA to CREDEBL.

Each service lives in `services/<name>/`. Shared pure code lives in
`core/<pkg>`. Vendor names appear only in the DPG adapters.

## Documents

- [Get started](docs/getting-started.md): the prerequisites, the binary, and the first run.
- [Architecture decisions](docs/adr.md): the 31 root decision records that define VCA, and the index of the new records.
- [Decision records](docs/adr): one file per record from ADR-032 on. A new record supersedes or extends a root decision.
- [ADR status](docs/adr-status.md): the state of every decision in the tree.
- [Glossary](docs/glossary.md): the project dictionary.
- [Writing style](docs/style.md): the rules for all reader-facing text.
- [Service document template](docs/template-service.md): the four sections each service documents.
- [Error catalogue](docs/errors.md): every user-facing error, with the next step.
- [Command line tool](docs/cli.md): the vca setup, deploy, dpg, and admin commands.
- [Deployment](docs/deploy.md): the compose profiles, the DPG stacks, and the Helm charts.
- [Super admin service](docs/admin.md): the admin API, the portal, and the login flows.
- [Wallet portal](docs/wallet-portal.md): the citizen wallet pages and the browser storage.
- [Landing](docs/landing.md): the front door of a deployment, the stacks it shows, and the role picker.
- `docs/<service>/`: one folder per service, planned as each service ships.

## Layout

| Path | Content |
|---|---|
| `proto/` | The proto3 contracts, one package per service. |
| `gen/` | Generated Go code. Do not edit it. |
| `core/` | Pure functions shared by services. |
| `services/` | One folder per service. |
| `docs/` | Decision records, glossary, style, errors. |
| `hack/` | Build and lint scripts. |

## Rules for contributors

1. Write the test first. Each package has tests with at least 90 percent coverage.
2. Define each API in proto3. Run `buf lint` before you commit.
3. Write comments and documents in Simplified Technical English. See [style.md](docs/style.md).
4. Start each source file with `// SPDX-License-Identifier: Apache-2.0`.
5. Keep vendor names inside `services/dpg-adapter-*`.

## Licence

Code is under Apache-2.0. See [LICENSE](../LICENSE). Documents are under
CC-BY-4.0 (ADR-029).
