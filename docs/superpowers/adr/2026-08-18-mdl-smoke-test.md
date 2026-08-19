# mDL issuance smoke test — run when a walt.id container is available

Companion to `2026-08-18-mdl-issuer-walletid-not-standalone.md` follow-up 3.

**UPDATE — actually run, end to end, on `cdpi-vps` (`deploy.sh up waltid`
alongside the existing `hub` deployment, both isolated by port/project-name
overrides).** `POST /api/v1/credentials/issue` with
`schema_id=org.iso.18013.5.1.mDL` returned a real `credential_id` +
`offer_uri`, and the resolved offer genuinely advertised
`credential_configuration_ids: ["org.iso.18013.5.1.mDL"]`. Three real bugs
were found and fixed in the process — none were anticipated by this doc's
original (code-reading-only) predictions below, so read the corrections
inline rather than trusting the speculative text where it conflicts:

1. `deploy.sh` unconditionally overwrote `CADDY_HTTP_PORT`/silently died on
   `docker inspect` of a container the scenario never starts — both fixed
   (`8d6d621`, `963f003`), unrelated to walt.id/mdl code itself.
2. `displayNameFor` mangled the mdoc entry's doctype-keyed config id into an
   unreadable name (`"org.iso.18013.5.1.m DL"`) — fixed (`911f2fe`).
3. **The actual blocker, and the one this doc got wrong (see Step 2's
   correction below): `schemaAllowlistDefault` never included mDL at all** —
   an earlier stale comment claimed "five credentials" but the array only
   ever had four. Fixed (`1b2a8d0`). Fix #2 was real and worth keeping, but
   didn't fix the 404 by itself — #3 did.

The steps below are left as originally drafted (pre-execution) for the
sections that still hold; corrections are called out where reality diverged.

## What this proves

That `POST /api/v1/credentials/issue` genuinely round-trips a valid mdoc
through walt.id's real `/openid4vc/mdoc/issue` route — the one piece of the
architecture that couldn't be confirmed by reading code alone.

## Prerequisites

1. The stack up: `deploy/compose/stack/docker-compose.yml` brings up
   `issuer-api` (walt.id, port `${WALTID_ISSUER_PORT:-7002}`) among others.
2. `VERIFIABLY_API_KEYS` set on the `verifiably-go` process with at least one
   key — that's your `Authorization: Bearer <key>` below.
3. Confirm the mDL entry is actually live in walt.id's served metadata (not
   just present in the repo's `.conf` — the mounted file could be stale):

```bash
curl -s http://localhost:7002/draft13/.well-known/openid-credential-issuer \
  | jq '.credential_configurations_supported["org.iso.18013.5.1.mDL"]'
```

Expected: a non-null object with `"format": "mso_mdoc"`,
`"proof_types_supported": {"jwt": {...}}` (confirms this session's `cwt`→`jwt`
fix, commit `1ac0c7d`/`078e69e` on `feat/mdl-issuer`, is present in the
running config — if this still shows `cwt`, the container is running a stale
mount).

## Step 1: confirm discovery surfaces it, and reconfirm the eligibility gap

**Correction from an earlier draft of this doc:** `GET /api/v1/schemas`
(`h.APIListSchemas`) filters to `s.Custom` schemas only
(`internal/handlers/api_schemas.go:135-138`) — it will NOT show the built-in
walt.id mDL entry. Neither does `GET /api/schemas`
(`h.ServePublicSchemas`, same `!s.Custom` filter,
`internal/handlers/public_schemas.go:29-33`). Nothing in this repo exposes
the raw `ListAllSchemas()` output as external JSON — it's rendered into HTML
views only. The closest real, callable check is the eligibility endpoint,
which already surfaces the full unscoped catalog and is exactly what this
ADR's follow-up 1 investigation traced:

```bash
curl -s -X POST http://localhost:8080/api/v1/credentials/eligible \
  -H "Authorization: Bearer $VERIFIABLY_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"claims": {"family_name": "Pérez", "given_name": "Ana", "birthdate": "1990-03-15", "cedula": "001-1234567-8"}}' \
  | jq '.credentials[] | select(.id | test("18013"))'
```

(Confirmed real route: `POST /api/v1/credentials/eligible` →
`h.APICheckEligibility`, `cmd/server/main.go:734`. The operator path — API
key + a `claims` body — is the branch that runs when a key is present;
`internal/handlers/eligibility.go:126` onward.)

Expected, per the ADR's traced conclusion: `available: false`, with
`missing_claims` containing `driving_privileges` and `expiry_date` — this
confirms the eligibility gate genuinely rejects self-issue for mDL (as
predicted from reading `identity_prefill.go`'s alias table), NOT that
discovery is broken. This is the expected, correct result, not a bug to
chase — it's why Step 2 goes through the operator flow instead.

If you want to see the field list itself (not just eligibility), the
simplest confirmation is indirect: run Step 2 with an intentionally wrong
`schema_id` and read the 404 body, or check the running walt.id container's
`/.well-known/openid-credential-issuer` response directly (prerequisite
check above) — the ISO field names aren't in that document either (mdoc
metadata doesn't declare per-claim types the way VC `credential_definition`
does), so the curated list in `fieldsForCredentialType` genuinely can't be
verified from outside the Go process without adding a debug endpoint. Not
adding one here — out of scope for a smoke test.

## Step 2: issue via the operator flow

`schema_id` must be walt.id's exact configuration ID (`findSchemaByID`
matches `Schema.ID` or a variant's `ID` verbatim, `internal/handlers/schema.go:21-28`
— no fuzzy/display-name lookup). Get it from the prerequisite check's
`.well-known` response: it's the JSON key inside
`credential_configurations_supported` whose value has `"format":
"mso_mdoc"` and `"doctype": "org.iso.18013.5.1.mDL"` — i.e. re-run:

```bash
curl -s http://localhost:7002/draft13/.well-known/openid-credential-issuer \
  | jq -r '.credential_configurations_supported | to_entries[] | select(.value.format == "mso_mdoc") | .key'
```

and use that exact string (likely `org.iso.18013.5.1.mDL` itself, or
`org.iso.18013.5.1.mDL_mso_mdoc` if walt.id appends a format suffix — the
command above tells you which, don't guess):

```bash
curl -s -X POST http://localhost:8080/api/v1/credentials/issue \
  -H "Authorization: Bearer $VERIFIABLY_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "schema_id": "<exact key from the command above>",
    "subject_data": {
      "family_name": "Pérez",
      "given_name": "Ana",
      "birth_date": "1990-03-15",
      "document_number": "001-1234567-8",
      "driving_privileges": "B",
      "expiry_date": "2030-03-15"
    }
  }' | jq .
```

Expected: `200 OK`, `{"credential_id": "...", "offer_uri": "openid-credential-offer://...", "flow": "pre_auth", ...}`
— no `valid_from`/`valid_until` needed (per `resolveIssuanceWindow`,
`internal/handlers/issued.go:35-49`: mDL likely has `ExpiresWithWindow() ==
false`, since `statusListKindFor` explicitly treats `mso_mdoc` as "MSO/IACA
[revocation], out of scope" rather than a bitstring/token schema — if this
step 400s asking for `valid_until`, the schema DOES declare a window; add
`"valid_until": "<RFC3339 date>"` and retry).

**If this 400s or 502s instead**, the error message is the actual finding —
capture it verbatim. The two most likely failure shapes, per the code read:
- `IssueToWallet` → walt.id `/openid4vc/mdoc/issue` returns non-2xx: read
  walt.id's response body in the wrapped Go error; check whether
  `buildMdocData`'s namespace-keyed body
  (`internal/adapters/waltid/issuer.go:1025-1038`, `{"org.iso.18013.5.1": {...6 fields...}}`)
  is what walt.id v0.18.2's mdoc issuer actually expects, or whether the real
  wire shape differs from what the doc comment assumed.
- A schema-not-found 404 — **this is exactly what happened live, and this
  doc's original text about it was wrong.** It claimed "the default
  allowlist... does include `Iso18013 Drivers License Credential`" — false;
  `schemaAllowlistDefault` (`issuer.go:210-216`) only ever had four entries
  (Bank Id, Educational ID, Tax Receipt, University Degree), confirmed via
  `git blame` back to the original author. `applySchemaAllowlist` genuinely
  does filter `APIIssue`'s search space (that part of the original text was
  correct — it's called inside `ListSchemas`, which `ListAllSchemas` calls
  with no bypass), so an unlisted schema is truly unreachable by
  `schema_id`, not just hidden from a UI grid. Proven by isolation: with the
  default allowlist active, `BankId_jwt_vc_json` issued fine while
  `Iso18013DriversLicenseCredential_jwt_vc_json` (a completely different
  variant from the mdoc entry, ruling out the displayNameFor bug as the
  cause) also 404'd. **Fixed in `1b2a8d0`** by adding
  `"Iso18013 Drivers License Credential"` as a fifth default entry. If your
  deployment sets `VERIFIABLY_WALTID_SCHEMA_ALLOWLIST` explicitly (overriding
  the default array entirely), you still need to add it there yourself, or
  set the var to `*`.

## Step 3: confirm the wallet can receive it

**UPDATE — actually run, end to end, on a real Android device (local release
APK, `adb install`), against `https://verifiably.mtc.credenciales.ysalabs.work`
on `cdpi-vps`.** This section's original prediction (Credo's native
`requestCredentials`/`credentialBindingResolver` path, `stored MdocRecord`)
was wrong about *which code path the offer takes* — read the correction
below rather than the predictions that follow it.

`isLegacyEndpoint()` in `cdpi-wallet`'s `requestCredentials.ts` matches any
issuer URL containing `/draft13` — which this offer's `credential_issuer`
does (`https://walt-issuer.mtc.credenciales.ysalabs.work/draft13`, confirming
the issuer-host/aud gap this doc already called out: walt.id issues,
verifiably-go orchestrates, two different hosts by design). That routes
`mso_mdoc` through the wallet's own hand-rolled manual-POST path, entirely
bypassing Credo's `holder.requestCredentials()`/`credentialBindingResolver`
— so none of this section's original log-line predictions ever fire for
this deployment. Three real bugs were found and fixed in that legacy path
(`cdpi-wallet` `main` commit `516b72d`), each surfacing as a different error
on successive attempts with fresh offers:

1. `proofOptionsFromConfig()` didn't recognize `cose_key` (mdoc's binding
   method) as JWK-equivalent, so the proof JWT was `did:key`-bound instead
   of carrying an embedded `jwk` header — walt.id's mdoc issuer only reads
   the latter. → `"No holder key could be extracted from proof"` (400).
2. The legacy POST body omitted `doctype`; walt.id's
   `findMatchingIssuanceRequest` (`CIProvider.kt`) matches the issuance
   session to the request by `docType` alone for `mso_mdoc`, no fallback.
   → `"No matching issuance request found for this session: <id>"` (400),
   despite the session and proof both being valid.
3. The credential response (raw base64url IssuerSigned CBOR) was routed
   through the same manual-JWT path as `jwt_vc_json`/`vc+sd-jwt` and stored
   as `SdJwtVcRecord` — decoding CBOR as a JWT threw `"Invalid JWT as
   input"`. Fixed with a dedicated `ManualMdocResult` path
   (`Mdoc.fromBase64Url` → `MdocRecord.fromMdoc`).

Confirmed in the wallet's logcat, in order across the three fixes:
`[oid4vci] stored manual-mdoc id: <uuid>, docType: org.iso.18013.5.1.mDL` —
**not** `stored MdocRecord id: ...` as originally predicted; that log line
belongs to the Credo-native dispatch branch in `storeCredential.ts`, which
this deployment's offers never reach.

A fourth, protocol-unrelated gap surfaced once storage was fixed:
`credentials/index.tsx` never called `agent.mdoc.getAll()`, so the stored
mdoc was invisible in the wallet's credential list despite being correctly
persisted. Fixed in the same commit (`fromMdocRecord()` in `credential.ts`,
wired into the list's load/delete alongside the sdJwtVc/w3cCredentials/
w3cV2Credentials branches already there).

Visually confirmed on-device: the credential list shows an "Iso18013
Drivers License Credential" card ("VÁLIDA"), and its detail sheet renders
all six subject claims correctly, including accented characters ("Family
Name: Pérez") — see the investigation note below on an accented-character
mangling that appeared during testing and was fully root-caused as a test-
harness artifact, not a bug in any of this project's code.

**Investigation note — a "Pérez" → "P�rez" mangling appeared during initial
testing, traced conclusively to the test harness, not the codebase.** Root
cause, confirmed byte-for-byte via `tcpdump` between `verifiably-go` and
`issuer-api` plus a CBOR decode of the raw mdoc bytes: manual `curl -d
'...Pérez...'` invocations from a Windows Git Bash shell sent "é" as a
single non-UTF-8 byte (`0xE9`, consistent with the active ANSI codepage)
instead of its correct 2-byte UTF-8 encoding (`C3 A9`) — confirmed by the
request's `Content-Length` matching the cp1252-encoded length, not the
UTF-8 one. That single invalid byte then passed through `verifiably-go`
→ walt.id → CBOR encoding → `@animo-id/mdoc`'s decoder unchanged at each
hop (every hop correctly treats an invalid UTF-8 byte as U+FFFD replacement
character) — so the visible mangling was a faithful reproduction of a
corrupted *input*, not a decoding bug anywhere in the pipeline. Reissuing
via a `curl --data-binary @file.json` payload written with explicit
`encoding='utf-8'` produced correct `C3 A9` bytes at every hop (verified
in the `issuer-api` capture) and rendered as "Pérez" correctly in the
wallet. No code changed as a result of this investigation — nothing to fix.

## What this smoke test does NOT cover

- BLE presentation (`presentMdoc.ts`, Task 8 on `feat/mdl-holder`) — separately
  gated on Fase 0 hardware per the original spec, unaffected by this ADR.
- Whether the mdoc walt.id issues is *itself* spec-correct CBOR/COSE (valid
  IssuerAuth, correct MSO structure) — that's walt.id's own conformance, not
  something this repo's code determines. If a conformant external mdoc
  verifier can validate the credential, that's the real confirmation; this
  smoke test only proves the transport/storage plumbing works.
