# What it would actually take to issue real mDLs from `verifiably` — walt.id version, adapters, wallet trust, and the two competing unmerged branches

Status: **analysis only, no implementation started.** Written to answer four
questions together, because they interact: (1) what does upgrading walt.id's
legacy `issuer-api` cost, (2) is `issuer-api2` viable as a real backend, (3)
what's the correct architecture for wallet-side certificate trust instead of
the hardcoded test cert from the previous ADR, (4) what does it take for
`verifiably` itself — not a Python script — to issue a conformant mDL. Every
claim below cites a specific file, line, or diffed source tag; nothing here
is inferred from general walt.id knowledge or repeated from memory of the
prior session.

**Read `2026-08-20-mdl-cbor-type-limits.md` and
`2026-08-20-mdl-issuer-api2-portrait-fix.md` first** — this doc assumes their
findings (legacy `issuer-api` cannot type-map CBOR at any version; a working
fix exists in the separate `issuer-api2` service; a hand-built test PKI and
wallet-side `X509Module` config got one credential working end to end).

## The central fact this analysis turned up: there are two unmerged branches, not one

Going in, the working assumption was that mDL work lives on
`feat/mdl-iso-fields` (the branch with `coerceMdocValue` and this session's
ADRs) and that the only path forward is patching the walt.id adapter
further. That's wrong. A second branch, **`feat/mdl-issuer`** (12 commits,
`c8a64c4`..`b1c79b9`, +4846/−647 across 48 files, diverged from `main`,
never PR'd), contains a **complete native Go mdoc issuer** that doesn't call
walt.id at all:

- `internal/mdl/cbortypes.go`, `encode.go`, `sign.go` — hand-written
  ISO/IEC 18013-5 CBOR encoding: canonical/deterministic `EncMode()`
  (`cbortypes.go:104-112`), tag 24 wrapping, tag-0 `tdate` vs. tag-1004
  `full-date` handled correctly and *distinctly* (`cbortypes.go:40-49`, with
  an explicit comment warning about the difference this session's walt.id
  debugging ran headfirst into), `IssuerSignedItem.random` ≥16 bytes,
  SHA-256 digests, MSO version "1.0".
- `internal/mdl/pki/pki.go` — generates an IACA root + DSC signer, ISO
  Annex B-conformant: 457-day DSC cap enforced in code (`pki.go:31`, `:84-90`),
  EKU `1.0.18013.5.1.2` set (`:24`).
- `internal/mdl/testdata/vectors/` + `vectors_test.go` + a **Node.js
  conformance verifier** (`testdata/verify/verify.mjs`, 376 lines) —
  independent-implementation cross-checking, something neither the walt.id
  path nor this session's manual testing had.
- `internal/signer/` — a `Signer` interface with a software implementation;
  built to be swappable for HSM/KMS later, per its own structure.
- `mdl_issue.go` — a **separate REST endpoint**, `POST
  /api/v1/credentials/mdl/issue` (`main.go:759`), with real OID4VCI
  proof-of-possession (`c_nonce` store, JWT proof verification, device-key
  extraction) — none of which the walt.id-backed path has ever needed to
  implement itself, because walt.id does it.

This branch already produces spec-correct CBOR typing — the exact problem
the walt.id-side ADRs spent a full session solving via `issuer-api2` and a
hand-built PKI. **But it is not integrated with `verifiably`'s operator
platform at all**: no schema catalog entry, no `subject_data` input, no
audit log entry (`APIMdlIssue` never calls `apiRecordIssuance` — confirmed
absent), hardcoded POC subject data (birth date computed as `now.AddDate
(-30,0,0)`, country/authority/privileges all literals — `mdl_issue.go:185-207`),
and an IACA that's regenerated from scratch on every process restart
(`serversigner.go:24-38` — meaning every previously issued credential
becomes unverifiable the moment the server restarts).

**This changes the shape of the real decision.** It is not "upgrade walt.id
or don't" — it's "which of two fundamentally different architectures do we
build the operator-facing mDL flow on: a patched walt.id adapter, or the
native Go issuer, or some combination." Sections below give the facts for
each; the final section lays out that decision explicitly.

---

## Part 1 — Upgrading walt.id's legacy `issuer-api` (v0.18.2 → v0.23.1)

Verified by cloning `walt-id/waltid-identity` and diffing source at both git
tags directly — not release notes alone.

### Does it fix the portrait/date problem? No.

`mDocNameSpacesDataMappingConfig` — the mechanism `issuer-api2` uses — is
**absent from `waltid-issuer-api` at every tag through v0.23.1**, confirmed
by `git grep` across the module at that tag returning nothing. **This is a
service migration, not a version bump**, regardless of what else is true
below. If the goal is portrait/date correctness on the walt.id path, v0.23.1
of legacy `issuer-api` does not get you there; only `issuer-api2` does (Part
2), or the native issuer does (already there, Part 3).

### What upgrading DOES cost, if done anyway for other reasons

**Every HTTP path/method verifiably-go calls survives unchanged.**
`IssuerApi.kt`, `OidcApi.kt`, `OnBoardingApi.kt`, `OnboardingRequest.kt`, and
`WebBaseRoutes.kt` diff empty between v0.18.2 and v0.23.1. `VerifierApi.kt`
and the auth controllers only lost `@OptIn` annotations or moved a route
wrapper without changing the final mounted URL. The `IssuanceRequest` DTO
gained five optional nullable fields (`credentialStatus`,
`sdJwtCredentialClaims`, `mdocStatus`, `authorizedTransactionDataTypes`,
`mdocValidityDays`) and removed none — additive only.

**One real behavior break: the default credential-format fan-out narrowed.**
v0.18.2's `CredentialTypeConfig.parse()` advertises 10 formats per bare-array
schema entry; v0.23.1 restricts the default to `jwt_vc_json`, `sd_jwt_vc`,
`jwt_vc` — with an explicit walt.id comment that `jwt_vc_json-ld` and
`ldp_vc` were "not implemented (fall to JWT path silently)" all along. Your
deploy overrides `credential-issuer-metadata.conf` wholesale with explicit
HOCON objects (not the bare-array shorthand), so **this doesn't break your
config** — but `catalog.go:128-131`'s `waltidWireFormatsForStd` still writes
`ldp_vc`/`jwt_vc_json-ld` entries for `w3c_vcdm_2` schemas, which walt.id
itself now classifies as non-issuable. Not broken; stale.

**The one genuinely untested risk: VCDM 1.1/2.0 field mixing.**
`buildCredentialData` (`issuer.go:1076-1091`) emits a VCDM 1.1 `@context`
(`https://www.w3.org/2018/credentials/v1`) together with VCDM 2.0 field
names (`validFrom`/`validUntil`, not `issuanceDate`/`expirationDate`).
v0.20.0 added `@context`-keyed auto-detection with 1.1↔2.0 field renaming
(release notes, `#1687`) — how that detector treats this specific mixed
input was not traced to source and is explicitly unverified. **This is the
one thing that must be tested against a real v0.23.1 instance before any
production bump** — it affects every non-mdoc, non-SD-JWT credential type
this system issues today, which is the majority of its traffic.

**Config files: byte-identical.** Every `.conf` this repo mounts
(`deploy/k8s/config/{issuer,verifier,wallet}/*.conf`) diffs empty between
tags, except a new commented-out optional field example. No HOCON schema
migration needed. Dockerfiles are byte-identical (`amazoncorretto:22` at
both tags). Postgres: no column/table changes for the tables this deployment
actually uses (`jdbc:postgresql://` path is unaffected by a SQLite-only
`SchemaUtils` branch change). `/livez` health endpoint survives (path
normalization only).

**Mechanical version-pin updates required in 15 locations** (all plain
find-and-replace, verified by grep): `deploy/cloud/ec2-bootstrap.sh:193-195`;
`deploy/compose/hub/.env.example:82`; `deploy/compose/hub/docker-compose.yml:141`;
`deploy/compose/stack/docker-compose.yml:145,159,170`; six files under
`deploy/k8s/helm/charts/walt-{issuer,verifier,wallet}/{Chart.yaml,values.yaml}`;
`deploy/k8s/helm/umbrella/waltid/Chart.yaml:6`; plus doc-only version
mentions in two scripts.

**Test fixtures needing attention:** `internal/adapters/waltid/integration_test.go`
hardcodes the `0.18.2` image tag and asserts the old 3-format fan-out
(`jwt_vc_json` + `jwt_vc_json-ld` + `ldp_vc`) — this is the decisive
regression test to run against a real bumped instance, since your custom
schemas use explicit-object HOCON (should survive) but this is what would
prove it. `catalog_test.go` and `verifier_test.go` assert the same
3-format list in pure-unit form; only need updating if you deliberately
narrow `waltidWireFormatsForStd` to match walt.id's new default.

**Overall verdict for Part 1:** closer to a mechanical bump than the 5-minor-
release gap suggests, EXCEPT for the VCDM 1.1/2.0 field-mixing question,
which is a real unknown with broad blast radius and must be tested — not
inferred — before trusting it in production. And doing this work fixes
nothing about mdoc/portrait; it only reduces future-upgrade risk and gives
access to whatever else v0.19.0–v0.23.1 improved (status-list signature
hardening, PD parsing fixes).

---

## Part 2 — `issuer-api2` as a real production backend, not a test tool

This reverses the working assumption going in, so state the correction
plainly first: **`issuer-api2` DOES accept real per-request subject data.**
The previous ADR's testing only exercised the baked-in profile sample data,
which made it look like a fixed-data-only demo service. It isn't.

### Per-request data flows all the way to the signature

`CredentialOfferRuntimeOverrides.credentialData: JsonObject?`
(`waltid-issuer-api2/.../models/CredentialOfferModels.kt`) is deep-merged
over the profile's baked-in `credentialData` in
`CredentialOfferService.mergeCredentialDataOverride` — objects merge
recursively, arrays/scalars replace wholesale — and the merged result flows
through `IssuanceSession.credentialData` into
`OpenId4VciProtocolService` and finally into `MdocCredentialSigner
.generateMdocCredential`, which is what actually signs. A per-request
`runtimeOverrides.mDocNameSpacesDataMappingConfig` is also supported,
meaning the CBOR type mapping itself can be supplied per call, not only via
server-side profile config.

**The real footgun in this design:** because the merge is recursive-object /
replace-scalar, any field your override does NOT mention **keeps the
profile's sample value**. The shipped `isoMdl` profile's sample data is a
fictional Austrian test person. A caller that overrides `family_name` and
`birth_date` but forgets `nationality` will issue a real credential with
`nationality: "AUT"` silently attached. This must be handled explicitly —
either the profile's `credentialData` needs to be stripped to a
near-empty template, or the calling code must always send every field the
profile declares.

### Concrete request shape for dynamic issuance

```json
POST /issuer2/credential-offers
{
  "profileId": "isoMdl",
  "authMethod": "PRE_AUTHORIZED",
  "expiresInSeconds": 300,
  "sessionId": "verifiably-req-8f2c1a",
  "runtimeOverrides": {
    "credentialData": {
      "org.iso.18013.5.1": {
        "family_name": "...", "given_name": "...", "birth_date": "...",
        "issue_date": "...", "expiry_date": "...", "issuing_country": "DO",
        "issuing_authority": "INTRANT", "document_number": "...",
        "portrait": "<base64 JPEG>",
        "driving_privileges": [{"vehicle_category_code": "B", ...}]
      }
    },
    "mDocNameSpacesDataMappingConfig": {
      "org.iso.18013.5.1": {
        "birth_date": {"type": "full-date"}, "issue_date": {"type": "full-date"},
        "expiry_date": {"type": "full-date"}, "portrait": {"type": "bytes"}
      }
    }
  }
}
```

Response is `201` with a JSON body (`{offerId, credentialOffer, ...}`), not
the bare-string URI legacy `issuer-api` returns — `IssueToWallet`
(`issuer.go:762`) would need its response parsing changed accordingly, but
that specific delta is small.

### The catalog/schema model does not map cleanly onto verifiably-go's today

Legacy `issuer-api` lets an operator define a brand-new custom schema by
appending one HOCON block and restarting — including schemas walt.id has
never seen, via a "borrow a stock configId" trick this repo already relies
on (`issuer.go:627-635` comment: "walt.id doesn't cross-check it against the
credentialData payload"). `issuer-api2` requires **two** coordinated HOCON
writes (a `credential-issuer-metadata.conf` entry AND a matching
`issuer2-profiles.conf` profile referencing it 1:1 — `CredentialProfileService
.validateProfile` throws if the reference is missing, and
`resolveProfileByCredentialConfigurationId` throws if more than one profile
maps to the same configuration id), and **the borrow trick has no
equivalent** — a `profileId` must resolve to a real, pre-provisioned
profile. There is no path to "operator defines a totally new credential type
through the UI and it just works" against `issuer-api2` the way there is
today against legacy `issuer-api`. This is a genuine product-capability
regression if dynamic custom schemas matter, not a rough edge.

Also: profile validation is all-or-nothing — `listProfiles()` validates
every profile on every call, so one malformed profile breaks the entire
catalog, not just the broken entry. Worse failure isolation than today.

### Auth model: PRE_AUTHORIZED ports cleanly; other flows may not

`issuer-api2`'s `AuthenticationMethod` enum has exactly two values,
`PRE_AUTHORIZED` and `AUTHORIZED` — narrower than legacy `issuer-api`'s
enum, which also has ID_TOKEN/VP_TOKEN/NONE variants that
`authenticationMethod(req.Flow)` (`issuer.go:674`) maps onto today. Any
verifiably-go flow that maps to one of those has no `issuer-api2` target and
would need redesigning, not just re-pointing. The PRE_AUTHORIZED case itself
— what mdoc issuance uses — ports in a straightforward way: `issuer-api2`
generates the pre-auth code itself, same as legacy.

### Persistence: memory by default, with a silent-fallback trap

There is no Postgres-backed mode. `PersistenceConfiguration.type` is
`"memory"` or `"redis"`/`"redis-cluster"` only — anything else throws.
Worse: the redis config is only read `if
FeatureManager.isFeatureEnabled(persistenceFeature)`, and the shipped
`_features.conf` has that feature **commented out** — meaning a correctly
written `persistence.conf` pointing at Redis will silently be ignored and
the service will run in-memory anyway, with no error. In-memory mode loses
every in-flight offer/pre-auth-code/access-token on restart (already-issued
credentials, being signed artifacts already in the wallet, are unaffected).
Any multi-replica deployment requires Redis — a single-pod deployment can
survive on memory, but the failure mode (silent fallback if you forget the
feature flag) is a real operational trap worth documenting loudly wherever
this gets deployed.

### Hard blockers found in the shipped configuration — must fix before any real traffic

1. **`POST /issuer2/credential-offers` and `GET /issuer2/sessions` are
   completely unauthenticated** in the shipped service — no auth plugin
   wraps the controller at all. Anyone who can reach the port can mint a
   signed credential with arbitrary subject data via `runtimeOverrides
   .credentialData`. The container this session stood up at
   `walt-issuer2.mtc.credenciales.ysalabs.work` was, for the duration of
   testing, an open credential-minting endpoint reachable from the public
   internet. **Must go behind a gateway/mTLS/private network before any
   real deployment — the service itself provides no auth knob for this.**
2. **`GET /issuer2/sessions` leaks issuer private key material.** The
   `IssuanceSession` objects it returns include `issuerKey: JsonObject` in
   full, plus complete applicant `credentialData`. Combined with (1), this
   is worse than just unauthorized issuance — it's private-key and PII
   disclosure to anyone who finds the endpoint.
3. **The shipped `issuer2-profiles.conf` and `issuer-service.conf` contain
   real private key material in plaintext, committed to walt.id's own
   public GitHub repo** (`defaultIssuerKey`'s `d` component, `ciTokenKey`,
   `credentialEncryptionKey`). Any deployment that runs this config
   unmodified is signing credentials with a keypair whose private half is
   public. **Every one of these must be replaced with real, non-public
   material before anything issued is meant to be trusted by anyone.**
4. No rate limiting, no CORS configuration anywhere in the module.

### Verdict for Part 2

The technical capability gap that motivated this whole investigation — can
`issuer-api2` sign real, dynamic mDLs with correct CBOR typing — is closed:
yes, verified via the deep-merge trace to the actual signer call. What's
open is entirely operational/architectural: no auth on the management API
(hard blocker), published test keys in the default config (hard blocker),
no durable persistence without a feature flag most people would miss, and a
schema-catalog model that's fundamentally less dynamic than what
verifiably-go's operators can do today with legacy `issuer-api`. None of
this is unfixable, but it's real work, not a re-point.

---

## Part 3 — The native Go mdoc issuer (`feat/mdl-issuer`) as the alternative to walt.id entirely

Re-stating from the top of this doc because it's the other live option:
this branch already produces conformant CBOR (canonical encoding, tag 24,
tag-0 tdate vs tag-1004 full-date handled correctly and distinctly, SHA-256
digests, proper `IssuerSignedItem.random`), has its own IACA/DSC generator
respecting the 457-day Annex B cap and the mDL DS EKU, has real OID4VCI
proof-of-possession with a `c_nonce` store, and has independent-
implementation conformance vectors verified by a separate Node.js verifier.
None of this depends on walt.id at all — it sidesteps every problem in Part
1 and Part 2 by not going through walt.id's mdoc path in the first place.

**What it does NOT have, verified absent:**

- **No schema-catalog integration.** It's a hardcoded, separate endpoint
  (`POST /api/v1/credentials/mdl/issue`) outside the operator's schema
  system entirely — an operator cannot configure or discover it the way
  they can any other credential type.
- **Mostly hardcoded subject data, with a partial exception.**
  `mdlLicenceFromClaims` (`mdl_issue.go:185-201`) does accept real
  `family_name`/`given_name` claims when present (`firstNonEmpty(claims[...],
  fallback)`), but `BirthDate` is an unconditional placeholder
  (`now.AddDate(-30,0,0)`, comment: "POC placeholder: not derived from a
  real IdP claim"), and `IssuingCountry`, `IssuingAuthority`,
  `UNDistinguishingSign`, and `DrivingPrivileges` are all literal constants
  with no claims path at all. Its own struct (`internal/mdl/issue.go:22-34`)
  doesn't have a `portrait` field.
- **No audit log entry** — `APIMdlIssue` never calls `apiRecordIssuance`,
  so mDLs issued this way are invisible to whatever compliance/audit
  tooling exists for every other credential type.
- **IACA does not survive a restart.** `NewServerSigner`
  (`serversigner.go:24-38`) generates a fresh root and DSC on every process
  start. Every previously issued credential becomes cryptographically
  unverifiable — its trust anchor no longer exists — the moment the server
  restarts. This alone makes it unusable for anything beyond a demo today.
- **No HSM/KMS custody** — `internal/signer/software.go` is the only
  implementation of the `Signer` interface; the interface exists (good
  extensibility signal) but nothing implements hardware-backed custody yet.
- **No multi-tenant/multi-issuing-authority support** — one process-wide
  `h.MdlSigner`, hardcoded `CN="verifiably POC IACA"`, hardcoded country
  `"DO"`. An instance issuing for more than one issuing authority isn't
  expressible.
- **No revocation** (see Part 4 — this is shared with the walt.id path,
  not specific to this branch).

### Verdict for Part 3

This branch is the *only* option investigated that gets ISO 18013-5 CBOR
typing fully right without depending on a second, unauthenticated,
key-leaking walt.id service. But "gets the encoding right" and "is a
production issuance path" are different bars, and this branch clears only
the first one. Bringing it up to the second means: hooking it into the
operator schema catalog and `subject_data` flow (real engineering, not
small — the input model is a typed Go struct today, not a generic
`map[string]string`, which is actually a strength for correctness but means
it needs its own UI/API surface rather than reusing the existing generic
form renderer as-is), persisting the IACA/DSC across restarts, wiring audit
logging, and eventually real key custody. None of this is walt.id-version-
dependent, which decouples it entirely from Part 1's and Part 2's concerns.

---

## Part 4 — The wallet's certificate trust story: what's actually right, not just what got one credential working

The previous session's fix — a single hardcoded IACA PEM constant in
`cdpi-wallet/src/agent/setup.ts` — was explicitly self-documented in its own
code comment as a stopgap. This section is what a real architecture looks
like, verified against what Credo-TS (the wallet's underlying SDK) actually
supports, not assumed.

### The library already supports runtime trust updates — this was never a Credo limitation

Traced the full call path: `X509Module` registers one `X509ModuleConfig`
instance into Credo's dependency container by reference
(`registerInstance`, no cloning). `Mdoc.verify()` re-resolves that same
config object **on every call**, not once at agent-init time. Combined,
this means: **mutating the live config object at any point after
`agent.initialize()` is immediately picked up by the next verification —
no re-initialization needed.** `X509ModuleConfig` exposes
`setTrustedCertificates()` (replace the whole list) and
`addTrustedCertificate()` (append) as plain, callable-anytime methods — both
already reachable from application code via
`agent.dependencyManager.resolve(X509ModuleConfig)`. There is no
`removeTrustedCertificate`; removal means re-setting the full list minus one
entry.

**Conclusion: the reason every certificate fix this session required a full
CI build-and-sideload cycle was a missing app feature, not a missing SDK
capability.** The capability was there the whole time.

### VICAL: not supported today, hand-rollable, but solves a different problem than the one CDPI has right now

Zero VICAL references anywhere in `@credo-ts/core` or `@animo-id/mdoc` —
confirmed by exhaustive grep. The cryptographic primitives needed to parse
one (CBOR decode, COSE_Sign1 verification, X.509 parsing) are all already
present as dependencies, so hand-rolling a parser is maybe 100-200 lines
with no new dependencies — but VICAL parsing is spec-sensitive in ways that
fail silently if gotten wrong, and there's no test corpus to validate
against. More fundamentally: **VICAL solves federation at scale** — trusting
one list-signer instead of N individual issuers. CDPI doesn't have multiple
external issuing authorities to federate with yet; adopting VICAL now would
add a bespoke crypto parser to maintain in exchange for a problem that
doesn't exist yet. AAMVA does operate a real VICAL service, but it's
gated behind terms-of-service acceptance and scoped to real North American
issuing authorities — it would never contain a CDPI test (or even a CDPI
real) IACA, so it doesn't help either the current iteration-speed problem
or a future CDPI-only deployment.

### The strongest evidence: the reader app already solved this, and didn't reach for VICAL either

`multipaz-identity-reader` (the unmodified upstream OpenWallet Foundation
reader used throughout this session) has a two-tier trust model:
`builtInTrustManager` (populated automatically) and `userTrustManager`
(manual import via the file-picker UI this session used). The built-in tier
is populated by `updateBuiltInIssuers()` fetching a **versioned JSON list**
of trust entries from the reader's own backend
(`GET /trusted-issuers?version=N`), wiping and repopulating the local set —
a pure runtime refresh, no app rebuild. The backend that serves it
implements exactly one entry type, `iaca_certificate` (base64url DER); its
own code throws on anything else, meaning **the reference implementation
built VICAL client support into the data model but chose NOT to operate a
VICAL server itself** — it ships a signed/versioned cert list instead. This
is real corroboration from a working, independently-designed system, not a
generic recommendation.

### Recommended shape (this section is judgment, not verified fact — flagged as such)

Stage 1: verifiably-go serves a versioned, **signed** trust-anchor list
(mirroring the reader backend's `{version, entries: [{certificate, ...}]}`
shape, so the same endpoint design could someday feed both apps). The
wallet fetches it after `agent.initialize()`, caches it locally, calls
`setTrustedCertificates()`, and falls back to cache-then-bundled-seed on
network failure. Signing the payload (not just serving it over TLS) is
non-negotiable — an unsigned list means a compromised endpoint or a MITM
can inject a trusted issuer the wallet will cryptographically accept.
This alone eliminates the rebuild-per-cert-change cost this session paid
three times.

Stage 2: an in-app, gated (dev/operator build only — never citizen-facing)
import screen mirroring the reader's `TrustedIssuersScreen.kt`, for fast
manual iteration without needing the Stage 1 endpoint to be finished first.

Stage 3, once there's more than one mdoc issuer to trust: move from a flat
trusted-certificates list to Credo's
`X509ModuleConfig.getTrustedCertificatesForVerification` async resolver
callback, which receives the actual presented certificate chain and can
scope trust decisions per issuer/docType rather than trusting one global
list for everything.

VICAL: revisit only if/when CDPI needs to interoperate with an issuing
authority it doesn't itself operate, or a partner mandates it.

---

## Part 5 — Everything the mdoc flow still needs regardless of which issuance path is chosen

These gaps exist identically whether mDLs end up issued via a patched
walt.id adapter, `issuer-api2`, or the native Go signer — they're about
`verifiably`'s surrounding platform, not about CBOR encoding.

### Where would a real applicant's data — especially the photo — actually come from?

**No data source in this codebase has a photo today.** The mock
`citizens-postgres` registry's schema (`citizens-db/init.sql:7-39`) has no
photo/image column. The OIDC-claims prefill path
(`identity_prefill.go:17-32`) maps string claims via an alias table with no
`picture` entry (even though OIDC standard claims include one, as a URL —
not usable as bytes without a fetch step). Every existing DPG data-source
capability (`registry`/`db`/`csv`/`api` in `config/backends.json`) is wired
for string-shaped claims.

The transport layer compounds this: the REST issuance DTO
(`apiIssueRequest.SubjectData`, `api.go:204`) and the operator web form
(`issuer_issue.html`, `SubmitIssue` reading `r.FormValue` — never
`r.FormFile`) are both string-only, with no `type="file"` input anywhere in
the issuance UI and no base64-decode step in the handler. The schema
builder itself (`issuer_schema_builder.html:170-175`,
`FieldSpec.Datatype`) only knows `string|number|integer|boolean|string:date
|string:uri` — there's no `bytes`/`image` datatype an operator could even
declare for a new schema.

None of this is a deep architectural blocker — base64-in-a-string-field is
a well-worn pattern and would fit the existing `map[string]string` shape
without a redesign — but every layer (data source, DTO, form UI, schema
datatype enum) needs the same small extension independently, and today
none of them have it.

### How would a wallet ever come to trust a *real* verifiably-issued IACA?

**Nothing in verifiably-go publishes X.509/IACA material today.** The
existing trust-publication surface (`GET /trust-registry`,
`GET /.well-known/jwks.json`) is entirely DID-shaped —
`trust.TrustedIssuer` (`internal/trust/registry.go:44-73`) has a `DID
string` field and no certificate/PEM/x5chain field at all. An mdoc's trust
anchor is an X.509 root, not a DID; the existing model doesn't extend to it
without a new field or a parallel endpoint. This is the natural landing
spot for Part 4's Stage 1 signed trust-list endpoint — but it doesn't exist
yet, in any form, for any credential type that needs X.509 trust rather
than DID trust.

Separately: the self-generated test IACA from the previous session sets
`Country` but never `Province`/`stateOrProvinceName` — so if `issuing_jurisdiction`
is ever added to a real credential (it isn't in `feat/mdl-issuer`'s
`LicenceData` today, but IS in walt.id's sample profile data this session
tested against), the same class of certificate-field bug from the previous
ADR would resurface on a from-scratch cert unless this is deliberately
checked.

### Revocation is not implemented, by design, for mdoc specifically

`statusListKindFor` (`issued.go:56-65`) explicitly routes `mso_mdoc` to a
`default:` case producing no status-list kind; `allocateStatusListBinding`
consequently allocates nothing for any mdoc; `APIRevoke` returns HTTP 422
("credential has no status list binding and cannot be revoked") for every
mdoc issued today. This is consistent across both unmerged branches — the
native issuer's `MobileSecurityObject` struct has no status field either.
This is a fact, not a judgment call on whether it's acceptable to ship
without — but it is a real gap against ISO 18013-5's expectation that a
production mDL be revocable.

### Full list of other spec-conformance items not yet addressed, verified item by item

Confirmed present (in `feat/mdl-issuer` only, absent from any walt.id path):
canonical CBOR, tag 24 wrapping, correct tdate/full-date tag distinction,
proper random-value entropy, SHA-256 digest algorithm, MSO version string,
MSO-validity-not-exceeding-cert-validity check, age-over computed against
MSO validity date rather than wall-clock `now`.

Confirmed absent from **both** branches: MSO validity period as an
operator-configurable value (both hardcode it — walt.id path via
`mdocValidityDays` defaulting silently, native path via a compile-time
constant `mdlCredentialValidity`); the `expectedUpdate` refresh-policy
field (declared, never populated); most optional ISO elements beyond the
mandatory set (`sex`, `height`, `weight`, `eye_colour`, `hair_colour`,
`birth_place`, `resident_*`, `nationality`, `signature_usual_mark`) —
present in walt.id's sample test data but not modelable as real applicant
data anywhere yet; the `issuing_jurisdiction` element; AAMVA or other
domestic/secondary namespaces; VICAL production; IACA persistence across a
restart (native path only — walt.id path persists this fine, since walt.id
owns key storage); server-side mdoc *verification* (verifiably-go can issue
but not verify what it issued, on either path); and BLE chunking/MTU
assumptions in the wallet's presentation code, which were grepped for and
found absent — meaning nothing hardcodes an unsafe size limit, but nothing
has been tested against a payload larger than this session's 42KB test
photo either. That's a genuinely open question, not a known-bad or
known-good one.

### Multi-tenancy vs. one-IACA-per-issuing-authority

Real tension, present on both paths. verifiably-go's registry model already
supports multiple independent DPG backends (`config/backends.json`
currently declares four). Neither mdoc path supports the equivalent for
X.509 material: the walt.id adapter's `Config` struct has exactly one
`IssuerKey`/`IssuerDID` pair with no cert-chain field at all; the native
path has exactly one process-wide `Signer` with hardcoded issuing-country/
-authority values. If CDPI ever needs to issue mDLs on behalf of more than
one issuing authority from a single verifiably-go deployment, neither
branch as currently written can express that — it would need either
multiple full backend instances (one walt.id/native-signer instance per
authority) or a real per-tenant signer-selection layer that doesn't exist
in either branch today.

---

## Summary table — the decision this ADR sets up, not resolves

| | Legacy `issuer-api` (patched further) | `issuer-api2` | Native Go signer (`feat/mdl-issuer`) |
|---|---|---|---|
| Portrait/date CBOR typing | Never — confirmed absent at every version | Yes, verified to the signer | Yes, already correct |
| Dynamic per-request subject data | Yes (already the model) | Yes, verified via deep-merge trace | No — hardcoded POC data, needs new input plumbing |
| Operator schema-catalog integration | Yes (already the model) | Partial — needs 2-file coordinated writes, no "borrow" escape hatch | No — separate hardcoded endpoint, not in the catalog at all |
| Auth on the issuance-triggering endpoint | Yes (existing API-key/session model) | **No — unauthenticated in shipped config, hard blocker** | Yes (existing API surface, but bypasses `apiRecordIssuance`) |
| Durable persistence | Yes (existing Postgres) | Redis-only, with a silent-fallback-to-memory trap | N/A — signer itself has no durability; IACA dies on restart |
| Depends on walt.id at all | Yes | Yes | No |
| Revocation | No (mdoc excluded by design) | No (same) | No (same) |
| Multi-issuing-authority | No (one key/DID pair) | No (same structural gap) | No (one process-wide signer) |
| Production-ready today | No (missing typing) | No (auth + published test keys are hard blockers) | No (no restart durability, no real data input, no catalog integration) |

None of the three options is a small step from where things stand. The
honest framing for whoever picks this up next: this is a real build, not a
configuration change, regardless of which of the three paths — or which
combination — gets chosen.

## Sources

- `internal/adapters/waltid/{issuer,catalog,verifier,wallet,docker,config,normalize}.go`
  and their `_test.go` siblings (verifiably-go, `main`)
- `internal/mdl/{cbortypes,encode,sign,issue,pki/pki,serversigner}.go`,
  `internal/handlers/mdl_issue.go`, `internal/signer/*.go`
  (verifiably-go, branch `feat/mdl-issuer`)
- `internal/handlers/{api,issuance,issued,identity_prefill}.go`,
  `internal/trust/registry.go`, `templates/pages/issuer_{issue,schema_builder}.html`
  (verifiably-go, `main`)
- `deploy/compose/stack/citizens-db/init.sql`, `config/backends*.json`
- `walt-id/waltid-identity` at tags `v0.18.2` and `v0.23.1` (cloned and
  diffed directly): `waltid-services/waltid-issuer-api/`,
  `waltid-services/waltid-issuer-api2/`, `waltid-services/waltid-verifier-api/`,
  `waltid-services/waltid-wallet-api/`, and their `config/` directories
- walt.id GitHub release bodies v0.19.0 through v0.23.1
- `cdpi-wallet/src/agent/setup.ts`, `src/agent/trust.ts`, `branding.config.ts`
- `node_modules/@credo-ts/core/build/modules/{x509,mdoc}/*.mjs` (cdpi-wallet)
- `multipaz-identity-reader`: `composeApp/.../TrustedIssuersScreen.kt`,
  `App.kt` (`updateBuiltInIssuers`), `backend/.../ApplicationExt.kt`
- ISO/IEC 18013-5 (mandatory/optional element sets, Annex B/C certificate
  and VICAL requirements)
