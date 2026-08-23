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

Read the **Findings** section before trusting any green mark below. Three real
defects were found. **F1 is fixed**; F2 and F3 remain open and are on the debt
list.

---

## Findings (read first)

### F1 — FIXED: `issuerKey.jwk` was substituted as a *string*, not an object

**Was** `deploy/k8s/config/issuer2/issuer2-profiles.conf`:

```hocon
defaultIssuerKey = {
  type = "jwk"
  jwk = ${VERIFIABLY_ISSUER2_KEY}      # <-- substitutes as a STRING
}
```

HOCON substitutes an environment variable as a **string** and never re-parses
it as JSON. walt.id needs a nested *object* here — the shipped original was a
nested HOCON object. `GET /issuer2/profiles` showed the damage:

```json
"issuerKey": { "type": "jwk", "jwk": "{\"kty\":\"EC\",\"crv\":\"P-256\",...}" }
```

Note `jwk` is a quoted, escaped string. Consequence: **every mdoc issuance
failed** at the credential endpoint with

```
HTTP 500 {"error":"server_error","error_description":"Invalid JSON object"}
```

thrown from `com.nimbusds.jose.util.JSONObjectUtils.parseJSONObject`.

The dangerous part: this was **invisible to a boot check**. The service
started cleanly, `/issuer2/profiles` returned 200 with the key present, and
the wellknown was correct. It only appeared when a wallet actually asked for
a credential. Task 2's verification stopped at exactly those two signals.
*Booting a service is not exercising it.*

**The fix.** The JWK is now supplied field by field, so each substitution is
a plain string in a position that wants a string, and `jwk` itself is a real
HOCON object:

```hocon
defaultIssuerKey = {
  type = "jwk"
  jwk = {
    kty = "EC"
    crv = "P-256"
    x = ${VERIFIABLY_ISSUER2_KEY_X}
    y = ${VERIFIABLY_ISSUER2_KEY_Y}
    d = ${VERIFIABLY_ISSUER2_KEY_D}
  }
}
```

`VERIFIABLY_ISSUER2_KEY` is replaced by `VERIFIABLY_ISSUER2_KEY_X` / `_Y` /
`_D` in `docker-compose.yml` and `.env.example`. Bare `${VAR}` (not `${?VAR}`)
is kept, so a missing key still stops the boot — verified: removing
`VERIFIABLY_ISSUER2_KEY_D` makes `docker compose config` exit 1 with
`required variable VERIFIABLY_ISSUER2_KEY_D is missing a value`.

**Verified by issuing, not by booting.** With the fixed config,
`/issuer2/profiles` reports `issuerKey.jwk` as an object with
`['crv','d','kty','x','y']`, and a full OID4VCI pre-authorized-code exchange
against the unmodified repo config produced a real **7191-byte mDL** — the
same request that previously returned `500 "Invalid JSON object"`. Decoded:

```
PASS  IssuerSigned decodes under @owf/mdoc schemas
PASS  docType is org.iso.18013.5.1.mDL
PASS  birth_date is CBOR tag 1004 (full-date), not a text string
PASS  portrait is a CBOR byte string — 70 bytes
CBOR tag 1004 (full-date) occurrences: 8, each followed by 0x6a
```

**Do not revert this to the single-variable blob form.** The reasoning is
recorded in the config comment above `defaultIssuerKey`.

Note the contrast, now corrected in `issuer-service.conf`'s comment:
`ciTokenKey` and `credentialEncryptionKey` genuinely DO take a JSON *string*
(walt.id ships them as triple-quoted strings), so the single-variable
substitution is correct for those two and must not be "harmonised" with the
issuer key. The old comment claimed HOCON "parses the substituted JSON text
as an object" — that is false, and it is precisely the belief that produced
this bug one file over. The code was right for the wrong reason.

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
services**, and compose `${VAR:?}` guards hard-block `up` with no `.env`
present: `VERIFIABLY_ISSUER2_KEY_X` / `_Y` / `_D` (three separate guards
after the F1 fix), `VERIFIABLY_ISSUER2_CI_TOKEN_KEY`, and
`VERIFIABLY_ISSUER2_CRED_ENCRYPTION_KEY`.

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
operator's key (`VERIFIABLY_ISSUER2_KEY_X`/`_Y`/`_D`) with walt.id's
**published example certificate**, whose embedded public key is a different
keypair. Task 2
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
| F1 fix re-verified | PASS — 7191-byte mDL issued from the fixed repo config |

**F1 — the issuance-blocking `issuerKey.jwk` string/object defect — is FIXED**
in this branch and re-verified by issuing a real credential, not by booting.

**F2 remains open:** walt.id's Photo ID profile omits the `portrait`
byte-string mapping, so every Photo ID portrait is emitted as text. The
four-line remedy is confirmed working but is routed to the debt list, not
applied here. F3 (`verify.mjs` takes no path argument) and F4 (the Go
adapter's `map[string]string` cannot express `driving_privileges`) are also
open and on that list.

---

## One-time migration — existing deployments, baseline/runtime config split

**Applies to:** any deployment created before issuer-api2's two configs were
split into tracked `*.baseline.conf` seeds plus gitignored runtime files.
**A fresh clone needs none of this** — `deploy.sh` seeds both files itself.

### Why it is needed

`deploy/k8s/config/issuer2/issuer2-profiles.conf` and
`credential-issuer-metadata.conf` used to be tracked in git while holding
generated and operator-authored content: the deployment's real DSC/IACA
x5chain (rendered in by `provision_issuer2_certificates`) and the operator's
custom mdoc schema display name (written by `setIssuer2Display`). Every
`git pull` / `checkout` / `stash pop` reverted both. The tracked files are now
`*.baseline.conf` seeds and the runtime files are gitignored.

### What happens if you just pull

**The pull refuses and aborts** — it does not destroy anything:

```
error: Your local changes to the following files would be overwritten by merge:
	verifiably-go/deploy/k8s/config/issuer2/credential-issuer-metadata.conf
	verifiably-go/deploy/k8s/config/issuer2/issuer2-profiles.conf
Aborting
```

Git blocks it because the rename deletes files you have locally modified. Your
certificates and schema name are still on disk at this point. Do **not** run
`git checkout --` or `git stash` on these two files to "clear" the block —
that is precisely what discards the DSC inside every mdoc already issued.

### The migration (run from the repo root, on the deployment host)

```bash
cd deploy/k8s/config/issuer2

# 1. Copy the two runtime files somewhere outside the repo.
cp issuer2-profiles.conf           ~/issuer2-profiles.conf.save
cp credential-issuer-metadata.conf ~/credential-issuer-metadata.conf.save

# 2. Return the tracked copies to their committed state so the pull is clean.
cd -
git checkout -- deploy/k8s/config/issuer2/

# 3. Pull. The rename now applies without conflict.
git pull

# 4. Put the real files back under the (now gitignored) runtime names.
cp ~/issuer2-profiles.conf.save \
   deploy/k8s/config/issuer2/issuer2-profiles.conf
cp ~/credential-issuer-metadata.conf.save \
   deploy/k8s/config/issuer2/credential-issuer-metadata.conf
```

### Verify before redeploying

```bash
# Both runtime files must now be ignored (each prints a .gitignore line):
git check-ignore -v \
  deploy/k8s/config/issuer2/issuer2-profiles.conf \
  deploy/k8s/config/issuer2/credential-issuer-metadata.conf

# Your real certificate must still be in place — this must NOT match:
grep -c MIIBeTCCAR8CFHrWgrGl5KdefSvRQhR \
  deploy/k8s/config/issuer2/issuer2-profiles.conf   # expect 0

git status --short   # expect clean
```

`MIIBeTCCAR8...` is walt.id's published example certificate. If that grep
returns non-zero, the real x5chain was lost — restore it from
`~/issuer2-profiles.conf.save` before deploying, because credentials issued
with the example certificate are refused by every wallet and nothing in the
logs says so.

The next `deploy.sh` is then a no-op for both files: `seed_issuer2_configs`
uses `cp -n`, so it only creates a runtime file that does not already exist.
Keep the `~/*.save` copies until you have issued and verified one credential.

---

## Dynamic wallet trust anchors (2026-08-23) — closes the recompile-per-deploy gap

**Applies to:** any deployment created before `GET /trust/mdoc-anchors`
existed. A fresh clone/deploy plus a wallet build from current `main` needs
none of this — it works out of the box.

Before this, a wallet only trusted a certificate **compiled into the app**
(`src/agent/setup.ts::MDOC_TRUSTED_CERTIFICATES` in `cdpi-wallet`). Since
`provision_issuer2_certificates` generates a brand-new IACA whenever
`dsc.pem` doesn't already exist, every from-scratch redeploy silently broke
every wallet build until it was recompiled with the new certificate —
`"No trusted certificate was found"` at accept time, with nothing in the
server logs pointing at the cause (the offer and credential endpoints both
return 200; only the wallet's local signature check fails).

**Fixed** by `verifiably-go` publishing its current IACA over HTTP
(`GET /trust/mdoc-anchors`, `internal/handlers/mdoc_anchors.go`) and the
wallet fetching it dynamically per `credential_issuer`
(`src/agent/mdocTrustAnchors.ts`), unioned with the compiled-in fallback so
already-issued credentials keep verifying. Full design rationale and the
documented VICAL production path:
`docs/superpowers/adr/2026-08-23-mdl-trust-anchor-distribution.md`.

### The routing gap this surfaced, and how to recognize it again

The endpoint lives on the `verifiably-go` container. The wallet fetches it
from the **`walt-issuer2` origin** — the `credential_issuer` it resolved
the offer from, a *different* container/subdomain. The first deploy of this
feature exposed the endpoint on `verifiably-go`'s own domain only;
`walt-issuer2`'s Caddy block still allowlisted just `/openid4vci/*` and
`/.well-known/*` (deliberately narrow — `issuer-api2` has no auth on its
management API), so the wallet's fetch 404'd there while curl against
`verifiably-go` directly returned 200 the whole time.

**Symptom:** wallet reports "No trusted certificate was found" even though
the dynamic-anchor mechanism is confirmed built, tested, and deployed.

**Diagnosis** (reproduce before assuming it's this):

```bash
# 1. What origin does the wallet actually fetch from?
curl -s "https://<walt-issuer2 subdomain>/.well-known/openid-credential-issuer/openid4vci" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['credential_issuer'])"
# => https://<walt-issuer2 subdomain>/openid4vci

# 2. Does the anchor endpoint answer AT THAT EXACT ORIGIN?
curl -s -o /dev/null -w "%{http_code}\n" "https://<walt-issuer2 subdomain>/trust/mdoc-anchors"
# 200 = fine, look elsewhere. 404 = this routing gap.

# 3. Sanity: same path on verifiably-go's own domain, for comparison.
curl -s -o /dev/null -w "%{http_code}\n" "https://<verifiably subdomain>/trust/mdoc-anchors"
```

**Fixed in `scripts/gen-caddy.sh`** (commit `2afe956`): the `walt-issuer2`
Caddy block now has a third allowlisted rule,
`handle /trust/mdoc-anchors { reverse_proxy verifiably-go:8080 }`, ahead of
the catch-all 404 — the only new path opened, allowlist otherwise
unchanged. If you see this symptom on a deployment whose `gen-caddy.sh`
predates that commit, `git pull` and re-run `./deploy.sh up waltid`
(regenerates and Caddy needs a reload — `docker exec <public caddy
container> caddy reload --config /etc/caddy/Caddyfile` if the container
name differs from what `deploy.sh` already reloads).

### Verified working end to end (2026-08-23)

Confirmed live against `mtc.credenciales.ysalabs.work`, not just unit
tests: a from-scratch-equivalent redeploy regenerated the IACA
(`CN=VERIFIABLY POC IACA`, freshly issued that day) — different from the
`CN=INTRANT POC IACA` compiled into the wallet's static fallback. After
the Caddy fix:

- `walt-issuer2` origin's `/trust/mdoc-anchors` → 200, serving the new cert.
- `verifiably-go`'s own domain → still 200 (unaffected by the fix).
- `walt-issuer2` origin's `/issuer2/sessions` (unauthenticated management
  API) → still 404 (allowlist not weakened).

**Still needs a human:** an on-device accept of a credential signed by
this rotated IACA, with the wallet build unchanged (no recompile), to
confirm the dynamic mechanism closes the loop for a real reader — the curl
checks above prove the plumbing, not the on-device Credo verification
path.

## What must be repeated on the next walt.id upgrade

All of it — every step here is manual. In particular:

1. **Steps 2 and 6 through the browser UI**, by a human operator. Never
   satisfied by driving the API.
2. **Step 7 against `multipaz-identity-reader` on a real Android device**,
   including the IACA import. Never satisfied in software.
3. **Steps 4 and 5 re-run against freshly issued credentials.** walt.id
   changing a `conversionType` default, or re-adding sample data to a
   shipped profile, would be invisible to every unit test in this repo.
4. **Re-check F1 and F2.** F1 is fixed here — confirm the upgrade did not
   reintroduce the blob form, and remember that only an *issuance* detects
   it, never a boot. F2 is still open: if upstream added the `portrait`
   mapping to the Photo ID profile, take theirs; if not, it still needs
   fixing.
5. **Re-check the wellknown paths.** `/draft13/...` and
   `/.well-known/openid-credential-issuer/openid4vci` are walt.id's
   choices and have already moved once.
6. **Re-check the credential request shape** — the encrypted-JWE
   requirement, the 2-element `driving_privileges` array, and the
   `stringToFullDate` behaviour on empty strings are all undocumented
   walt.id behaviours found by trial here.
