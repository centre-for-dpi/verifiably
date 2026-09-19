# Verifier presentation policy

This page describes the `verifier-policy` service (ADR-024). The service
README at [`services/verifier-policy/README.md`](../services/verifier-policy/README.md)
says how to run it. This page says how it works.

## Shape of a check

A check is a named function in `core/policy`:

```go
type Func func(ctx context.Context, p Presentation, pc Context) []CheckResult
```

The function is pure. Every side effect arrives as a port on `Context`:

| Port | Use |
|---|---|
| `Keys` | Resolve the keys of an issuer, for the signature check. |
| `Status` | Fetch a status list document. |
| `Schemas` | Fetch a JSON Schema document. |
| `Trust` | Ask the trust registry about one issuer. |

A test injects a fake port and gets a function with no network. The
service injects the real ports in `internal/ports`.

A check returns one result per credential, or one result with the index
`-1` for the whole presentation. A result has a name, an outcome, a
detail sentence, and evidence. The evidence never holds personal data.

## The outcomes

| Outcome | Meaning |
|---|---|
| `PASS` | The check found no problem. |
| `FAIL` | The check found a problem. |
| `SKIP` | The check does not apply to this presentation. |
| `ERROR` | The check could not run. |

The verdict is the conjunction. One blocking `FAIL` gives `INVALID`. No
blocking `FAIL` and at least one `ERROR` gives `INDETERMINATE`.
Everything else gives `VALID`.

## The checks

| Name | Mandatory | What it does |
|---|---|---|
| `signature` | yes | Verifies the issuer JWS of each credential with the keys of the issuer. |
| `key_binding` | yes | Resolves the SD-JWT disclosure digests and verifies the key binding JWT. |
| `nbf` | yes | Compares the start of validity with the evaluation time. |
| `exp` | yes | Compares the end of validity with the evaluation time. |
| `audience` | yes | Compares the audience of the presentation with the verifier client id. |
| `nonce` | yes | Compares the nonce of the presentation with the nonce of the request. |
| `status` | no | Reads the status list entry of each credential. |
| `trust_chain` | no | Looks each issuer up on the trust lists and checks the chain links. |
| `schema` | no | Validates each credential against the schema it declares. |
| `derived_proof` | no | Reserved for BBS selective disclosure (ADR-031 decision 2). It returns `SKIP` with the detail "reserved for BBS: not implemented". |

A mandatory check always runs, and a `FAIL` of it always blocks
(ADR-024 decision 2). A policy set adds the optional checks and says
whether each one blocks.

## Key resolution

The signature check asks the `Keys` port for a key set. The service
resolves the issuer in this order:

1. A DID resolves through `core/did`. The package covers `did:web`,
   `did:key`, and `did:jwk`. The service injects the `did:web` fetcher, so the
   cache and the size cap apply to it.
2. An `http` or `https` issuer resolves through
   `<issuer>/.well-known/jwks.json`.

Any other issuer gives an `ERROR`, because the service cannot get a key.

## Status checks

The `status` check reads the pointer of a credential: a `credentialStatus`
object, a `status.status_list` claim, or the flat `statusUri` claims. It
then fetches the list through the cached fetcher and reads the entry.

A Bitstring Status List credential decodes with
`core/statuslist/bitstring`. A Status List Token decodes with
`core/statuslist/token`. A token that is a compact JWS is signature
checked with the keys of its issuer.

The `fail_mode` parameter decides what an unreachable list means:

| Value | Outcome |
|---|---|
| `closed` (default) | `FAIL`, so the verdict is `INVALID`. |
| `open` | `ERROR`, so the verdict is `INDETERMINATE`. |

The deployment sets the default with
`VCA_VERIFIER_POLICY_STATUS_FAIL_MODE`. A policy set overrides it.

## Trust chain

The `trust_chain` check calls `TrustLookup` on the trust registry service
for each credential, with the issuer and the primary credential type. An
issuer that no enabled list names gives a `FAIL`.

The check then looks at the chain. A credential links to its parent with
one of these fields: `parentCredential` at the top level, the same field
inside `credentialSubject`, `delegation.parent_capability`, or a
`termsOfUse` entry with `parentCapability`. Each link must name a
credential of the same presentation by id. A link that names a missing
credential gives a `FAIL`. The parameter `require_chain` makes a
presentation with no link fail too.

## Schema

The `schema` check reads the `credentialSchema` entry of a credential,
fetches the document, and validates the credential with
`core/jsonschema`. The evidence names the number of problems and the
first one.

## Policy sets

A policy set is a named list of checks with parameters and a blocking
flag. `CreatePolicySet` writes version 1. `UpdatePolicySet` writes the
next version and leaves the old one readable. Every `Evaluate` response
carries the set id and the set version, so an audit shows the rules that
ran (ADR-024 decision 6).

The store writes one document per version under the key
`policyset/<id>/<version>`.

When a deployment configures no default set, the service uses a built in
set with `status`, `trust_chain`, and `schema`, each blocking.

## Follow-ups

| Item | Reason |
|---|---|
| Data Integrity proofs (`ldp_vc`) | The signature check returns `SKIP` with the detail `not implemented: RDF canonicalisation`. RDF Dataset Canonicalization needs a new dependency, so it waits for a decision on that dependency. |
| ISO 18013-5 mdoc | The signature check returns `SKIP` with the detail `not implemented: mdoc COSE_Sign1 verification`. The mdoc work arrives with the mDL service. |
| Data Integrity on a status list | The service reads a status list that is a plain JSON document without a signature check. The evidence says `signature: not checked`. |
