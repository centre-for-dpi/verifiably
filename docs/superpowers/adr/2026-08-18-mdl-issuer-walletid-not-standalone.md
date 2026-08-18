# ADR: mDL issuance goes through walt.id's existing catalog, not a standalone issuer

**Status:** Decided. **Date:** 2026-08-18. **Decider:** repo owner, after a deep
investigation prompted by a whole-branch-review finding.

## Context

Earlier in this session, `docs/superpowers/specs/2026-08-17-mdl-iso18013-5-poc-design.md`
and two implementation plans (`2026-08-17-mdl-issuer-go.md`,
`2026-08-18-mdl-issuance-endpoint.md`) were written and fully executed under
the assumption that `verifiably-go` had **no existing mDL issuance path** and
needed one built from scratch: a process-lifetime self-signed IACA/DSC
(`internal/mdl/serversigner.go`), a custom nonce store and proof-of-possession
JWT verifier, and a new `POST /api/v1/credentials/mdl/issue` endpoint
(`internal/handlers/mdl_issue.go`) authenticating directly against OIDC
citizen tokens rather than going through the standard OID4VCI offer flow. A
parallel `src/agent/mdl/` module was built in `cdpi-wallet` to consume it.

That assumption was never verified against the `waltid` adapter before
writing the spec. It was wrong.

## What was actually found

While investigating a whole-branch-review finding (the wallet's `aud`/issuer-
host derivation), a deeper look at `internal/adapters/waltid/` turned up:

- **walt.id's real, live catalog already advertises mDL.**
  `deploy/k8s/config/issuer/credential-issuer-metadata.baseline.conf:35-40`
  registers `"org.iso.18013.5.1.mDL" = { format = mso_mdoc, doctype = "org.iso.18013.5.1.mDL", ... }`
  — the exact file this session already patched once, for the `cwt`→`jwt`
  proof-type fix (commit `1ac0c7d`/`078e69e`), without anyone connecting that
  this file *is* the mDL catalog entry the rest of this ADR is about.
- **The adapter already routes `mso_mdoc` end to end.**
  `internal/adapters/waltid/issuer.go:925-926` maps `mso_mdoc` schemas to
  walt.id's `/openid4vc/mdoc/issue` route; `buildMdocData` (`:1020-1038`)
  builds the namespace-keyed body that route expects, generically, from any
  schema's `BaseType()` — no mDL-specific code needed.
- **Discovery is dynamic, not mocked.** `ListSchemas`
  (`internal/adapters/waltid/issuer.go:102-180`) fetches walt.id's real
  `.well-known/openid-credential-issuer` at request time and groups
  configurations into cards. Since the catalog file above is real, live
  config, an mDL card would appear in the existing discovery/eligibility UI
  today — no new code required to surface it.
- **`self_issue.go` is already format-agnostic.** The existing citizen
  self-issuance handler (`internal/handlers/self_issue.go`) verifies the OIDC
  token, checks eligibility via claims-coverage, prefills subject data from
  verified claims, and calls `h.Adapter.IssueToWallet(...)` — none of that is
  W3C/SD-JWT-specific. It would issue an mDL through this exact path today,
  returning a normal OID4VCI offer URI, if an mDL schema were registered and
  eligibility-mapped.
- `internal/mock/data.go:112` even has a mock schema entry (`sch2`, "Driver's
  Licence", `Std: "mso_mdoc"`) that was never connected to the real catalog
  finding above — a second, independent signal that mDL-via-walt.id was
  always the intended shape, just never wired up or noticed.

In short: **two working mDL issuers now exist in this codebase** — the one
built this session (`mdl_issue.go` + its own PKI) and the one that was
already there, dormant, inside the existing OID4VCI pipeline. They were built
in ignorance of each other.

## Decision

**walt.id, via the existing OID4VCI self-issue pipeline, is the mDL issuer of
record.** `mdl_issue.go`'s standalone issuance endpoint, its process-lifetime
self-signed IACA/DSC, its custom nonce store, and its custom
proof-of-possession JWT verification are **not** the path forward.

Reasons:
- It reuses infrastructure the rest of the platform already depends on and
  maintains: catalog discovery, eligibility/claims-coverage checks, subject
  prefill, status-list revocation binding, issuance metrics, and the
  wallet's *existing* `oid4vci/requestCredentials.ts` receive flow — instead
  of a second, narrower copy of all of that.
- It avoids maintaining a second PKI. `serversigner.go`'s self-signed,
  process-lifetime IACA/DSC was flagged during this session's own
  whole-branch review as a real hazard (a credential is only verifiable
  within the single server run that issued it, since the IACA rotates on
  every restart) — walt.id's own IACA/DSC lifecycle is not this project's
  problem to solve.
- It closes the `aud`/issuer-host gap documented in `cdpi-wallet`'s
  `app/receive.tsx` (commit `0053481`) by construction: there is no second
  issuer host to reconcile against verifiably-go's own base, because
  walt.id's offer already carries its own correct `credential_issuer`.

## Consequences

**Kept, unmerged, as reference — not deleted:**
- Branch `feat/mdl-issuer` in `verifiably` (`mdl_issue.go`, `serversigner.go`,
  `mdl_nonce_store.go`, `mdl_proof.go`, plus the earlier `internal/mdl` mdoc-
  construction package this branch also contains).
- Branch `feat/mdl-holder` in `cdpi-wallet` (`src/agent/mdl/generateDeviceKey.ts`,
  `buildPossessionProof.ts`, `requestMdl.ts`, `isMdocOffer.ts`, `storeMdoc.ts`,
  `presentMdoc.ts`, `app/present-mdl.tsx`).

Neither branch was ever merged to `main` in either repo, so nothing here
requires a revert — declining to merge is the entire mechanism. They stay
available in case a future requirement genuinely needs verifiably-go to hold
its own IACA (e.g. sovereignty/control requirements a walt.id-hosted PKI
can't satisfy) — that would be a new decision, made with that requirement in
hand, not a resurrection of this one by default.

**Reusable from those branches**, even though the parallel issuer is
retired:
- `internal/mdl`'s mdoc CBOR/COSE construction, PKI generation, and signer
  primitives (`internal/mdl/pki`, `internal/mdl/sign.go`, etc.) — these are
  general ISO/IEC 18013-5 building blocks, useful independent of which
  service holds the signing key, and were built and reviewed correctly.
- `cdpi-wallet`'s `storeMdoc.ts` (Task 6) — it already uses Credo-TS's native
  `agent.mdoc`/`MdocRecord` APIs to parse and persist a received mdoc with
  the device-key binding (§AD-2) intact, and is agnostic to which issuer
  produced the credential. This is very likely still needed: the wallet's
  *existing* `oid4vci/storeCredential.ts` dispatch-by-format-type path needs
  to route `mso_mdoc` responses somewhere, and `storeMdoc.ts` is exactly that
  destination — it just needs to be reachable from the *existing* OID4VCI
  receive flow instead of from `requestMdl.ts`'s custom two-step exchange.

**Not reusable / superseded:**
- `mdl_issue.go`, its nonce store, its proof-of-possession JWT verifier, and
  `serversigner.go` — these exist only because the standalone-issuer design
  needed its own token exchange and signing identity. The OID4VCI path
  already does both, via the DPG/wallet's standard credential-request +ˇ
  proof exchange.
- `requestMdl.ts`, `generateDeviceKey.ts`, `buildPossessionProof.ts`,
  `isMdocOffer.ts` on the wallet side — these exist to talk to
  `mdl_issue.go`'s custom contract specifically. The wallet's device-key
  generation and proof-of-possession for a *normal* OID4VCI credential
  request already happens in `credentialBinding.ts`/`requestCredentials.ts`;
  once mDL comes through that path, these become unnecessary duplicates of
  the same logic `buildPossessionProof.ts`'s own doc comment admits it was
  mirroring.
- `presentMdoc.ts` / `app/present-mdl.tsx` (Task 8, BLE scaffolding + consent
  screen) are unaffected by this decision either way — presentation-side
  work is orthogonal to which service issued the credential, and was already
  explicitly deferred to Fase 0 hardware validation regardless.

## What actually needs to happen next (not done by this ADR)

This ADR records the decision; it does not implement it. Follow-up work,
scoped separately:

1. ~~Confirm the real `org.iso.18013.5.1.mDL` catalog entry's field list maps
   cleanly through `identityPrefill`/eligibility.~~ **Done — reframed, not a
   code fix.** Traced end to end: `fieldsForCredentialType` already has a
   correct, curated field list for `Iso18013DriversLicenseCredential`
   (`family_name`, `given_name`, `birth_date`, `document_number`,
   `driving_privileges`, `expiry_date` —
   `internal/adapters/waltid/issuer.go:1157-1161`), and the template-fetch
   path (`ResolveSchemaFields`) can't clobber it since it only overwrites
   `FieldsSpec` `if len(fields) > 0` (`issuer.go:428-430`) and an ISO doctype
   string won't resolve against `credentials.walt.id`'s JSON-LD VC template
   server. But `evaluateEligibility` (`internal/handlers/eligibility.go:37-53`)
   requires every declared field to resolve to an OIDC claim, and
   `driving_privileges`/`expiry_date` have no entry in `identityAliases`
   (`identity_prefill.go:71-96`) because they aren't identity claims — a DMV
   grants vehicle categories and a validity window, an IdP doesn't assert
   them. This is **not a bug**: it's the same "issuer-gated data" case the
   code already names for a diploma's `degree`
   (`eligibility.go:35-36`, `self_issue.go:47-48`) — self-issue is correctly
   *not* the right path for mDL. **Decision: mDL issues via the existing
   operator flow** (`POST /api/v1/credentials/issue`, `internal/handlers/api.go:228`
   — API-key auth, free-form `subject_data`, no eligibility gate, same
   `IssueToWallet` call `self_issue.go` uses). Confirmed this already
   supports it with zero code changes: `HolderDID` is deliberately empty in
   this path for every operator-issued credential today (`backend/adapter.go:172-177`)
   — the holder's key binds later, at OID4VCI pre-auth redemption, not at
   issuance. mDL follows the identical pattern as the diploma/vaccination-
   record schemas already issued this way.
2. Confirm `cdpi-wallet`'s *existing* `oid4vci/storeCredential.ts`
   dispatch-by-format path routes an `mso_mdoc` credential response to
   `storeMdoc.ts` (Task 6, kept) rather than treating it as SD-JWT/W3C — this
   is a small, targeted change to existing dispatch logic, not a new module.
3. Run an actual issuance smoke test against a live walt.id container once
   one is available, to confirm the `/openid4vc/mdoc/issue` path genuinely
   round-trips a valid mdoc — this ADR's confidence is architectural (real
   code paths traced end to end) but not yet empirically confirmed against a
   running walt.id instance, which wasn't available in this environment.
4. Re-run Fase 0 hardware planning (§C.7.0 of the spec) against this
   simplified path once (1)-(3) land — the hardware test matrix itself
   doesn't change, only what's being tested changes (walt.id-issued mdoc
   instead of a verifiably-go-signed one).
