# Verifiable Credentials Adapters (vca)

Small services that add one citizen-facing capability each to a
verifiable-credential backend (walt.id, Inji, CREDEBL).

Start here:

1. `make bootstrap` prepares the build tools.
2. `make gen` generates Go code from the proto files in `proto/`.
3. `make test` runs the tests.

Each service has a folder under `services/` and a document under `docs/`.
Architecture decisions are in `docs/adr.md`.
