# mDL issuance smoke test — run when a walt.id container is available

Companion to `2026-08-18-mdl-issuer-walletid-not-standalone.md` follow-up 3.
This wasn't run in the agent session (no live walt.id container available
there) — everything below is prepared from reading the real code, ready to
execute the moment you have the stack up.

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
- A schema-not-found 404, two possible causes — check both:
  1. **The allowlist genuinely can cause this, despite its own doc comment
     implying otherwise.** `applySchemaAllowlist` (`issuer.go:225-236`) is
     called *inside* `ListSchemas`, and `APIIssue` calls `ListAllSchemas` →
     `ListSchemas` with no bypass — so a schema filtered out by
     `VERIFIABLY_WALTID_SCHEMA_ALLOWLIST` is genuinely absent from what
     `findSchemaByID` searches, not just hidden from a UI grid (the
     function's own comment, "the issuer can still target a hidden schema by
     id via direct API," describes walt.id's underlying config being
     untouched — a different layer — not a bypass of this filter). The
     default allowlist (`schemaAllowlistDefault`, `issuer.go:203-209`) does
     include `"Iso18013 Drivers License Credential"`, so this shouldn't bite
     on a default config — but if `VERIFIABLY_WALTID_SCHEMA_ALLOWLIST` is set
     in your deployment and doesn't include it, that's the fix: add it, or
     set the var to `*`.
  2. `findSchemaByID` matches on `Schema.ID`/variant `ID` verbatim, not
     display name — confirm the exact key you read from `.well-known` in
     Step 2's prerequisite command matches what `ListSchemas`'s grouping
     logic actually assigns as `Schema.ID` for this entry (re-read
     `internal/adapters/waltid/issuer.go`'s `ListSchemas` if these diverge).

## Step 3: confirm the wallet can receive it

Take `offer_uri` from Step 2 and run it through `cdpi-wallet`'s normal
receive flow (`app/receive.tsx`'s existing `resolveOID4VCI` — no mDL-specific
code path needed anymore, per this session's `storeCredential.ts` fix,
`main` commit `bfe87e3`). Confirm in the wallet's logs:

- `[oid4vci] requestCredentials returned: 1 immediate, 0 deferred` (Credo
  accepted the `mso_mdoc` config and didn't bounce it as unsupported)
- `[oid4vci] stored MdocRecord id: ...` (the new dispatch branch fired, not
  the `unknown record type, not stored` warning)

Then confirm the stored record is queryable and carries a `kmsKeyId`:

```ts
// in a dev console / temporary debug screen
const records = await agent.mdoc.getAll();
console.log(records.map(r => ({ id: r.id, keyId: r.credentialInstances[0]?.kmsKeyId })));
```

Expected: one record, `keyId` non-empty (confirms Credo's own binding
resolver — not `storeMdoc.ts`, which isn't in this path — set it correctly).

## What this smoke test does NOT cover

- BLE presentation (`presentMdoc.ts`, Task 8 on `feat/mdl-holder`) — separately
  gated on Fase 0 hardware per the original spec, unaffected by this ADR.
- Whether the mdoc walt.id issues is *itself* spec-correct CBOR/COSE (valid
  IssuerAuth, correct MSO structure) — that's walt.id's own conformance, not
  something this repo's code determines. If a conformant external mdoc
  verifier can validate the credential, that's the real confirmation; this
  smoke test only proves the transport/storage plumbing works.
