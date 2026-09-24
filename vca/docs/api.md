# API reference

Every service API is a proto3 contract under `proto/vca/<name>/v1/` with
package `vca.<name>.v1` (ADR-003 decision 1). Connect serves each contract
over gRPC, gRPC-Web, and JSON on one port (ADR-003 decision 2). Generated Go
code lives in `gen/`. The repository commits it.

## Conventions

- A credential or a presentation is an opaque `bytes` payload plus a
  `vca.common.v1.Format` value (ADR-003 decision 6). No service decodes or
  re-encodes it.
- Every message and every field has a one sentence comment in Simplified
  Technical English. The `hack/ste-lint.sh` script checks the comments.
- List RPCs take `vca.common.v1.Pagination` and return
  `vca.common.v1.PageResult`.
- A failed RPC attaches `vca.common.v1.Error` as a Connect error detail
  (see `errors.md`).
- Secrets travel as `vca.common.v1.SecretRef`, never as values.
- Each admin RPC carries the `(vca.common.v1.description)` option. The
  CLI help, man pages, portal help, and OpenAPI summary read it
  (ADR-009 decision 4).
- Each field of `vca.config.v1.Config` carries the
  `(vca.config.v1.setting)` option with its environment variable name,
  default, secret flag, roles, and DPGs (ADR-007 decision 6).
- Health endpoints stay HTTP at `/healthz` and `/readyz` (ADR-005
  decision 6). No service has a Health RPC.
- Standard HTTP endpoints stay plain handlers (ADR-003 decision 7): issuer
  metadata, JWKS, `vct` documents, OID4VP `direct_post`, status list GET.

## Services

| Package | Service | RPCs | Streaming | Purpose |
| --- | --- | --- | --- | --- |
| `vca.common.v1` | none | 0 | 0 | Shared types: Format, Role, Credential, Presentation, Pagination, Error, Subject, SecretRef. |
| `vca.config.v1` | none | 0 | 0 | The setup Config message and the setting option (ADR-007). |
| `vca.backend.v1` | CapabilityService, IssuerBackendService, HolderBackendService, VerifierBackendService, CatalogBackendService | 16 | 0 | The DPG adapter contract, one service per role function (ADR-002 decision 2). |
| `vca.admin.v1` | AdminService | 22 | 0 | Tenants, trust entries, auth providers, API keys, health, audit log, provider and admin onboarding (ADR-009, ADR-010). |
| `vca.trust.v1` | TrustService | 7 | 0 | Trust entries, publication per method, and TrustLookup with provenance (ADR-011). |
| `vca.issuerauth.v1` | IssuerAuthService | 7 | 0 | Staff OIDC login, session tokens, role mapping (ADR-012). |
| `vca.verifierauth.v1` | VerifierAuthService | 7 | 0 | Verifier staff OIDC login, session tokens, role mapping (ADR-036). |
| `vca.schema.v1` | SchemaService | 11 | 0 | Schema versions, publish and retire, issuer metadata, vct documents (ADR-013). |
| `vca.schemabuilder.v1` | SchemaBuilderService | 3 | 0 | Pure preview of a schema with sample data (ADR-014). |
| `vca.datasource.v1` | DataSourceService | 10 | 1 | CSV, HTTP, and SQL sources, previews, field maps, bulk runs (ADR-015). |
| `vca.issuance.v1` | IssuanceService | 5 | 1 | Single and batch issuance over every channel (ADR-016). |
| `vca.issued.v1` | IssuedService | 10 | 1 | The hash chained issued record log with append, revoke, export, and retention (ADR-017). |
| `vca.status.v1` | StatusService | 6 | 0 | Bitstring and Token status lists: allocate, set, read, signed list bytes (ADR-018, ADR-019). |
| `vca.walletauth.v1` | WalletAuthService | 7 | 0 | Citizen OIDC login, session tokens, holder key binding (ADR-020). |
| `vca.walletportal.v1` | WalletPortalService | 11 | 0 | Discover, claim, scan, accept, present, and consent for citizens (ADR-021). |
| `vca.discovery.v1` | DiscoveryService | 9 | 0 | Issuer crawl, catalogue, and versioned presentation templates (ADR-022). |
| `vca.ingest.v1` | IngestService | 4 | 0 | Every carrier to one RawPresentation, OID4VP requests and responses (ADR-023). |
| `vca.policy.v1` | PolicyService | 7 | 0 | Named checks, policy set versions, Evaluate (ADR-024). |
| `vca.results.v1` | ResultsService | 5 | 1 | VerificationResult store, query, export, purge (ADR-025). |
| `vca.combined.v1` | CombinedService | 6 | 0 | Combined templates with cross credential rules (ADR-026). |

Total: 19 packages, 21 services, 146 RPCs, 4 server streaming RPCs.

## Checks

Run these from `vca/` before you commit a proto change:

```sh
buf lint
./hack/ste-lint.sh $(find proto -name "*.proto")
buf generate
go build ./...
```

`buf breaking` runs in CI through `hack/buf-breaking.sh`. The script
compares against the last release tag. Before the first release it
compares against the merge base with `main` (ADR-003 decision 4).

## OpenAPI

The OpenAPI 3.1 document comes from `protoc-gen-connect-openapi`
(ADR-003 decision 3). The restricted build network cannot fetch the plugin,
so `buf.gen.yaml` does not list it. Run `hack/openapi.sh` on a machine with
network access. See `openapi/README.md` for the steps.
