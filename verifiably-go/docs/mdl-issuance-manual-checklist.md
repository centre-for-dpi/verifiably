# mDL / Photo ID issuance — manual verification checklist

**Purpose:** several steps in the mdoc issuance path can only be checked by
actually issuing a credential and decoding it. This file records what was
verified, what was *not*, and exactly what has to be redone on the next
walt.id upgrade.

| | |
|---|---|
| Date performed | 2026-08-21 |
| walt.id version | `waltid/issuer-api:0.23.1`, `waltid/issuer-api2:0.23.1` |
| Branch | `feat/mdl` |
| Verifier used | `internal/mdl/testdata/verify` — `@owf/mdoc` 0.7.0 + `@owf/cose`, on `node:crypto` |
| Performed by | automated agent session (no browser, no phone — see Steps 2/6/7) |

Read the **Findings** section before trusting any green mark below. Two real
defects were found, and neither is fixed in the tree.

---

## Findings (read first)

### F1 — BLOCKER: `issuerKey.jwk` is substituted as a *string*, not an object

`deploy/k8s/config/issuer2/issuer2-profiles.conf:12` reads:

```hocon
defaultIssuerKey = {
  type = "jwk"
  jwk = ${VERIFIABLY_ISSUER2_KEY}
}
```

HOCON substitutes an environment variable as a **string**. walt.id needs a
nested JSON *object* here. `GET /issuer2/profiles` shows the result:

```json
"issuerKey": { "type": "jwk", "jwk": "{\"kty\":\"EC\",\"crv\":\"P-256\",...}" }
```

Note `jwk` is a quoted, escaped string. Consequence: **every mdoc issuance
fails** at the credential endpoint with

```
HTTP 500 {"error":"server_error","error_description":"Invalid JSON object"}
```

thrown from `com.nimbusds.jose.util.JSONObjectUtils.parseJSONObject`. This is
*not* visible at boot — the service starts cleanly, `/issuer2/profiles`
returns 200, and the wellknown is correct. It only appears when a wallet
actually asks for a credential.

Task 2's report anticipated the mirror-image problem for the *other* two keys
(`ciTokenKey` / `credentialEncryptionKey` must be the full
`{"type":"jwk","jwk":{...}}` wrapper, unquoted) and got those right. This
third one, the bare-JWK nested-object case, was not caught because Task 2's
verification stopped at boot + `/issuer2/profiles`, and neither surfaces it.

To get any credential at all for this checklist, the JWK was inlined as a
literal HOCON object in a **scratch copy** of the config. That proved the
diagnosis: `jwk` then decodes as an object and issuance succeeds. **The repo
is unmodified** — fixing this is not in Task 8's scope, but nothing can be
issued until it is.

### F2 — Photo ID emits `portrait` as a text string, not a byte string

The mDL profile maps the portrait to CBOR bytes:

```hocon
"portrait" = { "type" = "string", "conversionType" = "base64StringToByteString" }
```

The **Photo ID profile has no `portrait` entry in its
`mDocNameSpacesDataMappingConfig`** — only `birth_date`, `issue_date`,
`expiry_date`, `portrait_capture_date`. So the portrait is emitted as a
base64 *text string*. Confirmed by decoding a real issued Photo ID:

```
FAIL  portrait is a CBOR byte string — js type string
```

This is **walt.id's own shipped defect**, verified by reading the profile
inside the unmodified `waltid/issuer-api2:0.23.1` image — not a regression
introduced by Task 2's trimming.

Adding the same four-line mapping the mDL profile already has fixes it
completely (tested in a scratch copy — `portrait is a CBOR byte string —
70 bytes`, all 8 checks pass). Not applied to the repo: out of scope here.

### F3 — `verify.mjs` does not take a file argument

The brief's Step 4 says `node verify.mjs <path-to-issued-mdoc>`. It does not
accept one — `verify.mjs` is hardcoded to `../vectors/mdl_full.cbor`,
`iaca.pem`, `dsc.pem`, and asserts exactly 13 elements and the
`POC-DO-NOT-TRUST` subject markers, all specific to the Go-generated vectors.
It verifies `internal/mdl`'s own output, which is its documented job.

For this checklist the same `@owf/mdoc` + `node:crypto` `MdocContext` was
driven against the walt.id-issued credentials instead. Same library, same
primitives, same checks — different input. If checking issued credentials is
meant to be routine, `verify.mjs` should be given an optional path argument.

---

## Steps

### Step 1 — Bring the stack up — DONE (reduced scope)

The brief says `docker compose up -d` for the whole stack. That is **53
services**, and three compose `${VAR:?}` guards hard-block `up` with no
`.env` present: `VERIFIABLY_ISSUER2_KEY`,
`VERIFIABLY_ISSUER2_CI_TOKEN_KEY`, `VERIFIABLY_ISSUER2_CRED_ENCRYPTION_KEY`.

Three disposable EC P-256 JWKs were generated into a scratch env file
(never committed) and only the services issuance needs were started:
`issuer-api`, `issuer-api2`, `caddy`.

Both issuers reached `Web server ready!` — issuer-api2 in 3773 ms.
`verifiably-go` was **not** started; it is not on the mdoc issuance path
exercised here (see Step 2).

### Step 2 — Issue an mDL through the real operator flow — NOT PERFORMED

**The browser UI path was not exercised.** No operator, no browser session.
This step exists specifically to prove the path the operator actually takes,
and driving the HTTP API is not that. It must be redone by a human.

What was done instead: credentials were issued by driving `issuer-api2`'s
OID4VCI endpoints directly, to produce real signed artifacts worth verifying
in Steps 4–6. That covers the *issuance* path but says nothing about the
schema-picker UI, field rendering, or the operator's form.

Offer URI form observed (from the API):

```
openid-credential-offer://?credential_offer_uri=http%3A%2F%2Flocalhost%3A7002%2Fopenid4vci%2Fcredential-offer%3Fid%3D<uuid>
```

### Step 3 — Issuer display name in the wellknown — PASS

The brief's URL is wrong. The real path carries the `/draft13` prefix:

```bash
curl -s "http://localhost:7002/draft13/.well-known/openid-credential-issuer"
```

```json
"display": [
  { "name": "INTRANT", "locale": "en",
    "description": "Instituto Nacional de Transito y Transporte Terrestre" }
]
```

The configured name, not the URL. The brief's bare
`/.well-known/openid-credential-issuer` returns **404** — confirmed.

issuer-api2 advertises its own metadata at yet another path,
`/.well-known/openid-credential-issuer/openid4vci` (RFC 8414 suffix form),
also carrying `"name": "INTRANT"`.

### Step 4 — Retrieve the credential and verify CBOR types independently — PASS

This is the payoff step: `@owf/mdoc` (OpenWallet Foundation, also used by
Credo) checking walt.id's output, on `node:crypto` primitives, with nothing
in the trust path from our Go code.

Full OID4VCI pre-authorized-code exchange completed: offer → resolve →
token → nonce → holder-bound ES256 proof JWT → credential. Issued mDL:
**7218 bytes**.

Note the credential endpoint takes an **encrypted JWE request**
(`Content-Type: application/jwt`, ECDH-ES + A128GCM to the issuer's published
`credential_request_encryption` key). Plain JSON works too, but any request
carrying `credential_response_encryption` is rejected unless the request
itself is encrypted.

```
PASS  IssuerSigned decodes under @owf/mdoc schemas
PASS  docType is org.iso.18013.5.1.mDL
PASS  chain terminates in the trust anchor — 2 certificates
PASS  disclosed elements had digests recomputed — 46 digest comparisons
PASS  birth_date is CBOR tag 1004 (full-date), not a text string
PASS  portrait is a CBOR byte string — 70 bytes
      full issuer verification — 56 assessments, 1 failed (see below)
```

Byte-level confirmation of the tag, independent of any library:

```
CBOR tag 1004 (full-date) occurrences: 8, each followed by 0x6a
```

`0xD9 0x03 0xEC` is tag 1004; `0x6A` is a 10-character text string —
`YYYY-MM-DD`. Exactly the ISO 18013-5 `full-date` encoding.

**Signature and chain validate.** The 1 failed assessment of 56 is
`issuing_jurisdiction` (`""`) not matching `stateOrProvinceName` (absent) in
the signing certificate — an artifact of the diagnostic certificate used here
(see the x5chain caveat below) combined with the profile's emptied sample
field, not a defect in the CBOR encoding.

**x5chain caveat — the signature check above is only meaningful because the
certificate was replaced.** As shipped, `issuer2-profiles.conf` pairs the
operator's `VERIFIABLY_ISSUER2_KEY` with walt.id's **published example
certificate**, whose embedded public key is a different keypair. Task 2
flagged this as a hard gate. Every mdoc issued in that configuration is
COSE-signed with one key while advertising another in its x5chain, and fails
signature verification at any conformant reader. To make Step 4 a real test,
a throwaway IACA + DSC covering the actual signing key was generated for this
session only. **That is a diagnostic aid, not a fix** — real certificate
provisioning is owned by
`docs/superpowers/specs/2026-07-23-issuer-key-rotation-design.md`.

### Step 5 — Omission safety property, on a real issuance — PASS

An mDL was issued supplying only `family_name` and `given_name` (plus the
date fields the profile's `stringToFullDate` mapping forces — see below).
The decoded credential was searched for walt.id's Austrian sample data:

| string | occurrences |
|---|---|
| `Musterfrau` | 0 |
| `Muster` | 0 |
| `Bundesministerium` | 0 |
| `Vienna` | 0 |
| `walt.id` | 0 |
| `AT` | 0 |

Every field not supplied came through as the emptied placeholder — `""`,
`0`, `false`, `null` — never sample data:

```
family_name = "Perez"      given_name = "Ana Maria"
document_number = ""       issuing_authority = ""     issuing_country = ""
birth_place = ""           nationality = ""           resident_address = ""
sex = 0                    height = 0                 age_over_18 = false
```

**Task 2's emptying of the profile sample data holds end to end.** This
pins the whole path, not just the request side that the Task 3 unit test
covers.

One wrinkle worth knowing: a truly minimal request fails with
`DateTimeParseException: Text '' could not be parsed at index 0`, because
the emptied `""` date fields still run through `stringToFullDate`. Real
dates must be supplied for issuance to succeed at all. Also,
`driving_privileges` must carry **exactly 2** entries or issuance fails with
`Json array sizes (input & config) are not equal` — the mapping config
declares a fixed 2-element array.

### Step 6 — Repeat for Photo ID — PASS with a real defect (F2)

Issued through the same API path, docType `org.iso.23220.photoid.1`
(lowercase `photoid` — capital `photoID` does not resolve), namespace
`org.iso.23220.1`. Issued Photo ID: **20929 bytes**, 125 elements.

```
PASS  IssuerSigned decodes under @owf/mdoc schemas
PASS  docType is org.iso.23220.photoid.1
PASS  full issuer verification — 164 assessments, 0 failed
PASS  chain terminates in the trust anchor — 2 certificates
PASS  disclosed elements had digests recomputed — 154 digest comparisons
PASS  birth_date is CBOR tag 1004 (full-date)
FAIL  portrait is a CBOR byte string — js type string      <-- F2
```

**164 assessments, 0 failed** — a completely clean cryptographic
verification, better than the mDL's (the `issuing_jurisdiction` element that
tripped the mDL does not exist in this namespace).

The per-docType design is confirmed genuine: Photo ID's mandatory set really
is different — 9 fields, `issuing_authority_unicode` rather than
`issuing_authority`, and `age_over_18` mandatory rather than optional. The
namespace is `org.iso.23220.1`, which is *not* what stripping the docType's
last segment would give (`org.iso.23220.photoid`) — the explicit
`docTypeProfiles` table in `internal/adapters/waltid/issuer2.go` is doing
real work.

Only `portrait` is wrong, and it is walt.id's shipped mapping gap (F2).

**Also unreachable through the Go adapter as written:** `buildIssuer2Offer`
types `credentialData` as `map[string]string`, but `driving_privileges`
requires an array of objects and `age_over_18` a boolean. Any mDL issued
through the Go path today cannot supply `driving_privileges` — one of the 11
ISO mandatory elements.

### Step 7 — Verify with the real reader — NOT PERFORMED

**No Android device was attached** (`adb devices` empty), so
`multipaz-identity-reader` could not be run. Nothing was presented to a real
reader; the portrait was never rendered on a device.

This is the only step that exercises a genuinely independent, conformant ISO
18013-5 verifier end to end, including the IACA-import trust flow. It
**must** be performed by a human before any release claim. Steps 4–6 verify
the same cryptography in software, which is strong evidence but is not the
same as a real reader accepting the credential.

### Step 8 — This document — DONE

### Step 9 — Commit — DONE

---

## Summary

| Step | Result |
|---|---|
| 1 Stack up | DONE — 3 of 53 services, keys generated |
| 2 Issue via operator UI | **NOT PERFORMED** — no browser; API used instead |
| 3 Wellknown display name | PASS — `/draft13` prefix required |
| 4 mDL CBOR types verified independently | PASS — tag 1004, portrait bytes, signature + chain valid |
| 5 Omission safety | PASS — zero Austrian sample data leaked |
| 6 Photo ID | PASS except `portrait` (F2, upstream defect) |
| 7 Real reader | **NOT PERFORMED** — no Android device |
| 8 This document | DONE |

**Two defects found, neither fixed in the tree:** F1 blocks all issuance;
F2 makes every Photo ID portrait non-conformant. Both have a confirmed
one-line remedy, each validated in a scratch config.

---

## What must be repeated on the next walt.id upgrade

All of it — every step here is manual. In particular:

1. **Steps 2 and 6 through the browser UI**, by a human operator. Never
   satisfied by driving the API.
2. **Step 7 against `multipaz-identity-reader` on a real Android device**,
   including the IACA import. Never satisfied in software.
3. **Steps 4 and 5 re-run against freshly issued credentials.** walt.id
   changing a `conversionType` default, or re-adding sample data to a
   shipped profile, would be invisible to every unit test in this repo.
4. **Re-check F1 and F2.** If either was fixed in the tree, confirm the
   upgrade did not reintroduce it; if upstream fixed F2, drop the local
   patch rather than carrying it forever.
5. **Re-check the wellknown paths.** `/draft13/...` and
   `/.well-known/openid-credential-issuer/openid4vci` are walt.id's
   choices and have already moved once.
6. **Re-check the credential request shape** — the encrypted-JWE
   requirement, the 2-element `driving_privileges` array, and the
   `stringToFullDate` behaviour on empty strings are all undocumented
   walt.id behaviours found by trial here.
