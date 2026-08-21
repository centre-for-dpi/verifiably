# `issuer-api2` fixes the portrait/date CBOR typing bug — and three certificate-field checks had to be fixed too

Status: **confirmed working end to end.** A real mDL with a genuine JPEG
portrait (bstr) and correctly tagged dates (CBOR tag 1004) was issued,
received into `cdpi-wallet` on iPhone, presented over BLE, and verified
successfully by `multipaz-identity-reader` on Android — with the photo
visibly rendered. Not yet deployed to `verifiably-go`'s production path; this
was validated against a standalone `issuer-api2` container, isolated from the
`issuer-api` the deployed adapter actually calls. See
`2026-08-20-mdl-cbor-type-limits.md` for why the legacy `issuer-api` can't do
this at all.

## The question that started this

After confirming (previous ADR) that walt.id's `issuer-api` has no wiring
from JSON input to `ByteStringElement`/tag-1004 output at any version through
`main`, the natural follow-up was: *walt.id clearly wrote this conversion
machinery and tested it — where does anyone actually use it?*

## Finding `issuer-api2`

Reading `waltid-services/` more broadly (not just the module the deployed
adapter calls) turned up a second, separate issuance service:
`waltid-issuer-api2`. It is not documented anywhere public-facing — no
mention in the community docs, no blog post, nothing indexed by search
engines beyond the enterprise docs page (which has its own inconsistencies,
see below). It is, however, a real, independently published, runnable
service:

- Docker Hub: `waltid/issuer-api2`, 24 tags, including `0.23.1` (matches the
  `issuer-api` version other ADRs in this doc set reference), `latest`,
  `1.0.0-PRE`.
- Present as a complete Ktor service (`Main.kt`, `Issuer2Module.kt`, its own
  `config/` directory) from at least v0.21.0 onward. **Not present at all in
  v0.18.2** — the version `verifiably-go` runs today. Upgrading the walt.id
  images on `cdpi-vps` is a prerequisite for using this in production, not
  optional.

### The mapping config that was missing

`waltid-libraries/credentials/waltid-mdoc-credentials/.../dataelement/json/`:

- `StringToCborTypeConversion.kt` — enum: `STRING_TO_FULL_DATE`,
  `STRING_TO_T_DATE`, `BASE64_STRING_TO_BYTE_STRING`,
  `BASE64URL_STRING_TO_BYTE_STRING`.
- `JsonElementToCborMappingConfig.kt` — sealed class, `@Serializable`,
  discriminator field `"type"` (confirmed against the actual
  `Json { ... }` instance `issuer-api2` uses for both its HTTP body decoding
  and its HOCON config decoding — no custom `classDiscriminator`, so the
  kotlinx default `"type"` applies both places).

`MdocCredentialSigner.kt` (in `waltid-openid4vci`, used by `issuer-api2`):

```kotlin
mDocNameSpacesDataMappingConfig
    ?.get(namespace)?.entriesConfigMap?.get(elementIdentifier)
    ?.executeMapping(elementValueJson)?.toKotlinxCborElement()
    ?: valueMappingFunction(docTypeValue, namespace, elementIdentifier, elementValueJson)
```

Per-element, opt-in, falls back to the untyped-string default (the
`issuer-api` legacy behavior) when unconfigured — this is the exact hook the
previous ADR found missing from `CIProvider.kt`.

### Where the mapping config comes from

Two ways, both real:

1. **Server-side profile config.** `issuer2-profiles.conf` ships an `isoMdl`
   profile with `mDocNameSpacesDataMappingConfig` already filled in —
   `portrait` → `base64StringToByteString`, `birth_date`/`issue_date`/
   `expiry_date`/`portrait_capture_date` → `stringToFullDate`,
   `signature_usual_mark` → `base64StringToByteString`, plus a nested
   `arrayConfig` for `driving_privileges`' own per-entry date fields. This
   profile's sample `credentialData` is what we issued against — no
   `runtimeOverrides` needed.
2. **Per-request override.** `CredentialOfferCreateRequest.runtimeOverrides`
   (type `CredentialOfferRuntimeOverrides`) carries the same
   `mDocNameSpacesDataMappingConfig` field, so a client can supply its own
   mapping without touching server config. Not used here — the shipped
   `isoMdl` profile already covered everything needed — but confirmed
   present in the DTO for when real (non-sample) data needs it.

### The API shape is different from `issuer-api`

- Endpoint: `POST /issuer2/credential-offers`, body
  `{profileId, authMethod, expiresInSeconds, ...}` — not
  `{credentialConfigurationId, mdocData, ...}`.
- Well-known metadata is served at a URL with an extra path segment:
  `{origin}/.well-known/openid-credential-issuer/openid4vci` (RFC 8615
  path-insertion form), not the legacy `{issuer}/.well-known/...`.
  `@openid4vc/openid4vci` (the library Credo's `holder.requestCredentials()`
  uses) already implements this exact resolution order — tries the
  path-inserted form, falls back to the legacy form — so **no wallet code
  change was needed** for this part.
- `/openid4vci/nonce` is a dedicated endpoint; the token response does not
  embed `c_nonce` the way `issuer-api`'s does.
- The credential response is `{"credentials": [{"credential": "..."}]}`
  (draft13 batch shape), not the bare `{"credential": "..."}` some other
  paths return.
- Credential request body: `{"credential_configuration_id": "...",
  "proofs": {"jwt": [proofJwt]}}` — `credential_configuration_id` singular
  and required, `proofs` plural (array), not `format`+`doctype`+`proof`
  singular.

None of this required a `cdpi-wallet` code change — `receive.tsx`'s manual
fetch path only activates for `http://` issuers (a dev-mode branch); an
`https://` `issuer-api2` offer goes through Credo's own
`resolveCredentialOffer`/`requestCredentials`, which already handles all of
the above correctly.

## Verifying it, on the wire, not from config

Ran the actual OID4VCI flow against a real (if disposable) EC keypair issuer
and decoded the returned mdoc:

```
portrait                   bstr (42042 bytes)  <-- BYTE STRING (correct)
signature_usual_mark       bstr (42042 bytes)  <-- BYTE STRING (correct)
birth_date                 TAG 1004 (full-date) -> date(2025-01-15)
issue_date                 TAG 1004 (full-date) -> date(2025-01-15)
expiry_date                TAG 1004 (full-date) -> date(2035-01-15)
portrait_capture_date      TAG 1004 (full-date) -> date(2024-12-20)
age_over_18                bool (True)
age_in_years                int (36)
```

(42042 bytes = a real JPEG portrait swapped in later in the session, not the
profile's original 68-byte 1×1 PNG placeholder — see "The portrait was
technically correct and still invisible" below.)

## Then: three certificate-field checks, found one at a time

Getting the CBOR typing right was necessary but not sufficient. Once mdocs
reached Credo's real verification path (see next section for why they hadn't
before), `@animo-id/mdoc`'s `Verifier` enforces three separate checks against
the signing certificate that walt.id's own sample `defaultIssuerX5chain`
fails, and that a self-generated cert has to get right on purpose:

1. **`X509Module` had no trust anchor at all.** `cdpi-wallet`'s
   `setupAgent()` never registered `X509Module`. `Mdoc.verify()` (called
   automatically by `holder.requestCredentials()` for `mso_mdoc` offers)
   throws `"No trusted certificates found. Cannot verify mdoc."`
   unconditionally when `trustedCertificates` is empty.

   **Why this never surfaced against the legacy `issuer-api`:** mdoc offers
   from a `/draft13`-style legacy endpoint are routed through a manual
   `fetch()` path in `requestCredentials.ts` (`isLegacyEndpoint()` matching
   `/draft13`, `/draft14`, or `http://`) that bypasses Credo's own
   `requestCredentials()`/`verify()` entirely. `issuer-api2`'s well-known URL
   matches none of those patterns, so its mdoc offers took the standard
   `'credo'` path for the first time — the first path that actually calls
   `Mdoc.verify()`. This is a pre-existing gap, not something `issuer-api2`
   introduced; it was simply never exercised before.

2. **walt.id's own sample certificate has no `countryName` in its Issuer
   DN.** `issuer2-profiles.conf`'s `defaultIssuerX5chain` cert's Issuer field
   is bare `CN=MDOC ROOT CA` — no `C`. `Mdoc.getIssuingCountry()` (in
   `@animo-id/mdoc`) reads `x509Certificate.issuerName` (the X.509 *Issuer*
   field — the method name `getIssuerNameField` and the check's own message
   "...in the issuer certificate's subject distinguished name" both suggest
   Subject, but the implementation reads Issuer), so every credential signed
   by that cert fails this check regardless of chain trust.
   Reported nowhere upstream that a search surfaced.

3. **`issuing_country` / `issuing_jurisdiction` must equal `C` / `ST` in the
   *Subject* DN of the signing (DS) certificate — a second, genuinely
   spec-driven cross-check**, distinct from #2's Issuer-DN check.
   `@animo-id/mdoc`'s `verifyData()` → `matchCertificate()` requires
   `mdoc.issuing_country === issuerAuth.getIssuingCountry(ctx)` (same method,
   but now comparing against the mdoc *data*, not just checking presence) and
   `mdoc.issuing_jurisdiction === issuerAuth.getIssuingStateOrProvince(ctx)`.
   The `isoMdl` sample profile's data is Austrian (`issuing_country: "AT"`,
   `issuing_jurisdiction: "AT-9"`), so a self-generated cert has to carry
   `C=AT, ST=AT-9` to match — not an arbitrary choice, and not our own
   country, precisely *because* it has to match sample data we didn't write.

   Confirmed by reading the full verifier for every `matchCertificate`/`"must
   match"` call site: these two (country, jurisdiction) are the complete
   list. No third Subject-DN field (`L`, `O`, etc.) is ever read.

### The fix: a purpose-built test PKI

Generated with `openssl`, P-256 (matching the DS key's curve; ISO 18013-5
requires the DS cert's key type to match what actually signs):

```bash
# IACA root — self-signed, CA:TRUE, C+ST present
openssl ecparam -name prime256v1 -genkey -noout -out iaca-key.pem
openssl req -x509 -key iaca-key.pem -out iaca-cert.pem -days 5475 -sha256 \
  -subj "/C=AT/ST=AT-9/O=CDPI/OU=mDL Test/CN=CDPI mDL Test IACA AT" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"

# DS — signed by the IACA, CA:FALSE, EKU 1.0.18013.5.1.2 (the mDL DS OID
# X509ExtendedKeyUsage.MdlDs already recognizes in Credo's own X509Certificate.ts)
openssl ecparam -name prime256v1 -genkey -noout -out ds-key.pem
openssl req -new -key ds-key.pem -out ds.csr \
  -subj "/C=AT/ST=AT-9/O=CDPI/OU=mDL Test/CN=CDPI mDL Test DS AT"
openssl x509 -req -in ds.csr -CA iaca-cert.pem -CAkey iaca-key.pem \
  -CAcreateserial -out ds-cert.pem -days 1095 -sha256 -extfile <(cat <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,1.0.18013.5.1.2
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
)
```

Wired in on both sides:
- `issuer2-profiles.conf`'s `defaultIssuerKey`/`defaultIssuerX5chain` swapped
  to the DS key/cert — mdocs now get signed by this chain instead of walt.id's
  sample one.
- `cdpi-wallet/src/agent/setup.ts` registers `X509Module` with the IACA root
  as `trustedCertificates` (a static, single-issuer allowlist — noted in the
  code as scoped to this one test issuer; `X509ModuleConfig
  .getTrustedCertificatesForVerification` is the intended per-issuer resolver
  once there's more than one mdoc issuer to trust).
- The reader side (`multipaz-identity-reader`, unmodified upstream OpenWallet
  Foundation source) needed **no code change at all** — it has a built-in
  "Trusted Issuers" screen (`TrustedIssuersScreen.kt`) with an "Import
  Certificate" file picker that accepts a PEM/DER IACA root directly, no
  rebuild required.

## The portrait was technically correct and still invisible

Once the cert chain passed, the reader accepted the credential — but rendered
no visible photo. Not a bug: `issuer2-profiles.conf`'s sample `portrait`
value is a genuine PNG, correctly typed as bstr, that happens to be a **1×1
pixel placeholder** (68 bytes total). The full pipeline (issuance → BLE
transfer → reader decode → `Image()` render) was correct throughout; there
was just nothing to see. Swapped in a real photo (cropped 3:4, resized to
420×560, JPEG quality 85, 42KB) into `issuer2-profiles.conf`'s `portrait` and
`signature_usual_mark` fields directly (both use the same sample bytes in
the shipped profile) — confirmed visually on the reader after.

## What's still open

- **Not deployed to the real issuance path.** `verifiably-go`'s
  `internal/adapters/waltid/issuer.go` still calls the legacy `issuer-api`
  exclusively. This session's `issuer-api2` container is a standalone
  experiment on `cdpi-vps`, isolated by port and container name from the
  deployed stack — it does not touch `verifiably-go`'s issuance path or any
  file this repo tracks in its deployed compose file.
- **v0.18.2 → ≥v0.21.0 upgrade required** before `issuer-api2` can run at
  all where `verifiably-go` currently points. Not attempted — the legacy
  `issuer-api` at v0.18.2 keeps running unmodified throughout this session.
- **Test PKI, not production PKI.** The IACA/DS keys generated here are
  disposable test material (private keys sitting in a local scratch
  directory), sized for "does the pipeline work end to end", not for any
  real-world trust decision.
- **`feat/mdl-iso-fields`'s existing commits (`coerceMdocValue` etc.) are
  unrelated to this fix** and still await a PR per the no-direct-push-to-main
  policy on this repo — this ADR doesn't change that.
- If `verifiably-go` does move to `issuer-api2`, `internal/adapters/waltid/
  issuer.go`'s request-building code needs a rewrite for the different DTO
  shape (`profileId`/`runtimeOverrides` instead of
  `credentialConfigurationId`/`mdocData`), not just a base-URL change.

## Sources

- `waltid-services/waltid-issuer-api2/` (Main.kt, Issuer2Module.kt,
  controller/Issuer2ManagementController.kt, config/issuer2-profiles.conf)
- `waltid-libraries/credentials/waltid-mdoc-credentials/.../json/
  StringToCborTypeConversion.kt`, `JsonElementToCborMappingConfig.kt`
- `waltid-libraries/protocols/waltid-openid4vci/.../MdocCredentialSigner.kt`
- `node_modules/@animo-id/mdoc/dist/index.js` (`Verifier.verifyIssuerSignature`,
  `Verifier.verifyData`, `IssuerAuth.getIssuingCountry`,
  `IssuerAuth.getIssuingStateOrProvince`, `IssuerSignedItem.matchCertificate`)
- `node_modules/@credo-ts/core/build/modules/x509/X509Certificate.mjs`
  (`getIssuerNameField` reads `x509Certificate.issuerName`)
- `node_modules/@credo-ts/openid4vc/build/openid4vc-holder/
  OpenId4VciHolderService.mjs` (L707-708, unconditional `mdocApi.verify()`)
- `node_modules/@openid4vc/openid4vci/dist/index.mjs` (L947-954,
  path-insertion well-known resolution with legacy fallback)
- ISO/IEC 18013-5 (portrait as bstr, full-date as tag 1004, DS certificate
  field requirements)
