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
| `signature` | yes | Verifies the issuer JWS of each credential with the keys of the issuer. For a Claim 169 code it verifies the COSE_Sign1 signature, as the next section says. |
| `key_binding` | yes | Checks the holder binding of each credential (ADR-083). The parameter `require_holder_binding` defaults to `true`. |
| `nbf` | yes | Compares the start of validity with the evaluation time. |
| `exp` | yes | Compares the end of validity with the evaluation time. |
| `audience` | yes | Compares the audience of the presentation with the verifier client id. |
| `nonce` | yes | Compares the nonce of the presentation with the nonce of the request. |
| `status` | no | Reads the status list entry of each credential. |
| `trust_chain` | no | Looks each issuer up on the trust lists and checks the chain links. |
| `schema` | no | Validates each credential against the schema it declares. |
| `claim_predicate` | no | Checks a claim against a rule that DCQL cannot hold (ADR-042 decision 3). The parameters are `path`, `op`, `value`, and `type`. The operators are `before` and `after` a date, and `at_least_years` and `at_most_years` before the time of evaluation. A credential outside `type` does not apply. The check fails when no credential carries the claim. The evidence names the rule and never the claim value. |
| `derived_proof` | no | Reserved for BBS selective disclosure (ADR-031 decision 2). It returns `SKIP` with the detail "reserved for BBS: not implemented". |

A mandatory check always runs, and a `FAIL` of it always blocks
(ADR-024 decision 2). A policy set adds the optional checks and says
whether each one blocks.

## Claim 169 codes

An identity QR code holds a CBOR Web Token with claim 169 in a
COSE_Sign1 message (RFC 8392, RFC 9052). The format is `claim169`.
`core/vc` reads it. The issuer is the `iss` claim, often a `did:web`.
Each attribute of claim 169 becomes a
claim with its name in the 169 QR code specification, such as
`Full Name`. A coded gender or marital status reads as a word. An
image or a biometric stays out of the claims. The `nbf` and `exp`
claims give the validity window.

The `signature` check resolves the keys of the issuer with the `kid` of
the protected header. That is the same resolver as for the issuer of a
JWT. It verifies ES256 and EdDSA signatures. The `status` check finds no
status list. The `trust_chain` check looks the issuer up on the trust
lists.

## Holder binding

An OID4VP answer in a format that can carry holder binding must carry
it (ADR-083). These formats are `dc+sd-jwt`, `vc+sd-jwt`, `jwt_vc_json`
and `mso_mdoc`. An unbound answer fails `key_binding` with the detail
"the presentation carries no holder binding". The verdict then reads
Not valid. A pasted, scanned or uploaded credential is no
presentation, so the rule does not apply to it.

The holder binding of each format:

| Format | Binding | What the check does |
|---|---|---|
| `dc+sd-jwt`, `vc+sd-jwt` | A key binding JWT of the `cnf.jwk` key | Verifies the signature, the type, the `sd_hash` and the time. |
| `jwt_vc_json` | A VP JWT that carries the credential | Verifies the VP JWT with the `cnf.jwk` key, or the key of a `did:jwk` or `did:key` subject. The VP JWT names the holder. The audience and nonce checks read the VP JWT. |
| `mso_mdoc` | The device signature of a `DeviceResponse` | VCA does not check it yet. It skips an mDoc with a device signature, and the stack verifier checks it. An `IssuerSigned` structure alone fails. |

The verifier of a stack sees the binding, while VCA gets only the
credentials. An answer that a stack verifier accepted carries
`stack_checked_holder`. The check then skips with the detail "the stack
verifier checked the holder binding".

A policy set turns the rule off with the parameter
`require_holder_binding` set to `false` on `key_binding`. An unbound
answer then skips, as before ADR-083.

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
The fetcher keeps a document for `VCA_VERIFIER_POLICY_CACHE_TTL`. A
Status List Token names its own `ttl` in seconds. The fetcher keeps such
a token for the shorter of the two times.

A Bitstring Status List credential decodes with
`core/statuslist/bitstring`. A Status List Token decodes with
`core/statuslist/token`. A token that is a compact JWS is signature
checked with the keys of the credential issuer first (ADR-071).

A status service of VCA signs the lists of an issuer whose key sits in
a DPG, such as walt.id. It publishes its key set under the list
address. For a list at `<base>/status/<id>` the key set is at
`<base>/.well-known/jwks.json`. When the keys of the issuer do not
pass the list, the check reads that key set. The evidence then says
`signature: valid, key set of the list`.

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
issuer that no enabled list names gives a `FAIL`. The check tells an
unknown issuer from a registry that does not answer. A credential that
names no issuer gives a `FAIL` with the detail "the credential names no
issuer". A registry that answers `NOT_FOUND` or `INVALID_ARGUMENT` gives
a `FAIL` with the detail "the trust registry does not know the issuer".
Only a registry that does not answer gives an `ERROR` with the detail
"the trust registry is not reachable".

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

## Trust cache

`internal/cache` keeps checked copies of the trust material (ADR-041).
With them, a verifier can check a presentation with no network for a
set time. The cache keeps three kinds of copy.

| Kind | Source | Check before the cache keeps the copy |
|---|---|---|
| Trust list | `ExportSnapshot` of the trust registry: the local entries and the copy of each external registry, with its registry id and name. | The JWS signature against the key set of the trust registry, the `typ` header, and the `exp` claim. |
| Registry keys | The key set of the trust registry. The `did:web` documents and key sets of the listed issuers. The X.509 anchor chains of the external registries. | A DID document must name the DID it came from and hold a usable key. A key set must hold a key. Each certificate must be valid now and signed by the next one. |
| Status lists | The status lists that the listed issuers publish, and each list that a check read online. | The keys of its issuer must check the signature of a status list token. A `did:key` or a `did:jwk` issuer carries its key, so the cache reads no network for it. A plain JSON list says `not checked`, as the online check does. |

A copy that no key signs, such as a plain key set, can stay in the
cache. The registry names its address, which pins it. The caching page marks that
source "Unsigned, pinned by address", never "Good".

A read that fails, or a copy that fails its check, keeps the last good
copy. The source then shows the reason in `last_error`. The copies sit
in the state directory under `cache/`, so they survive a restart.

A schedule reads each kind on its own interval: the trust list every
6 hours, the registry keys every 24 hours, and the status lists every
hour. The schedule looks for a due kind every
`VCA_VERIFIER_POLICY_CACHE_TICK`. `SyncCache` reads a kind at once.
A sync hands each status list it read and checked to the cached
fetcher. So after Sync now, the next check reads the fresh list, and a
revocation shows at once.

Each check asks the network first. When a source does not answer and
the policy allows checks with no network, the check reads the copy.

| Age of the copy | Outcome |
|---|---|
| Inside the window | The check uses the copy. The response carries `material_age`, the age of the oldest copy it read. `material_stale` is true when a copy is older than its refresh interval and the policy marks such results. |
| Older than the window | The signature and trust checks `FAIL` with the evidence `stale: true`. The status check fails too when the policy refuses stale status lists. Otherwise the fail mode decides. |

The window is at most 7 days. `GetCacheState` returns the policy and
each source. `SetCachePolicy` stores a new policy in the state
directory. The caching page of `verifier-results` shows both.

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
