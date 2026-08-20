# walt.id's legacy `issuer-api` encodes every mdoc string as CBOR text, so `portrait` can't be issued

Status: **confirmed limitation of walt.id's legacy `issuer-api`** (v0.18.2
through `main`), no workaround through that specific service. Found during
the first real reader test (Multipaz reader on Android against the wallet on
iPhone).

**UPDATE — resolved via a different walt.id service, not by patching this
one.** Everything below was true of `issuer-api`/`issuer-api2`'s claim in
this doc ("not wired to the issuer-api either") turned out to be wrong for
`issuer-api2` specifically — it *is* wired there, just not documented
anywhere public. Full writeup, including the certificate debugging that
followed once portrait/dates were fixed: `2026-08-20-mdl-issuer-api2-portrait-fix.md`.
Read that doc for the resolution; this one still accurately documents why
the legacy `issuer-api` (what `verifiably-go`'s `internal/adapters/waltid/issuer.go`
actually calls today) cannot do it.

## What happens

ISO/IEC 18013-5 types its data elements: `age_over_NN` are booleans,
`age_in_years` is an integer, `portrait` is a **byte string** holding a JPEG,
and `birth_date` / `issue_date` / `expiry_date` are `full-date` (CBOR tag
1004). walt.id emits the first two correctly and the rest as text strings.

Decoded from a signed mdoc issued through `/openid4vc/mdoc/issue`:

```
age_over_18     bool   True                     correct
age_in_years    int    36                       correct
portrait        str    '/9j/4AAQSkZJRgABAQ...'  should be bstr
birth_date      str    '1990-03-15'             should be full-date (tag 1004)
issue_date      str    '2020-03-15'             should be full-date (tag 1004)
expiry_date     str    '2030-03-15'             should be full-date (tag 1004)
```

A conformant reader treats a wrongly-typed element as absent. That is what
the Multipaz reader did with `portrait`: its "identification" request failed
on that element while every text element in the same request succeeded.

Empirically the reader tolerates the date typing — those same requests passed
with dates as text — so `portrait` is the only blocker in practice today.
That tolerance is the reader's choice, not something the spec promises.

## Why

`JsonElementConversions.kt` (waltid-mdoc-credentials) maps JSON to CBOR with
no branch that can produce bytes:

```kotlin
is JsonPrimitive -> when {
    this.isString -> StringElement(this.content)   // portrait lands here
    this.booleanOrNull != null -> BooleanElement(this.boolean)
    ...
```

`ByteStringElement` never appears. Booleans and integers survive only because
JSON has those types natively; binary and dates have no JSON representation,
so there is nothing for the converter to key off.

`CIProvider.kt` calls it with no configuration:

```kotlin
addItemToSign(
    nameSpace = namespace.key,
    elementIdentifier = property.key,
    elementValue = property.value.toDataElement(),   // no mapping config
)
```

And `IssuanceRequest.mdocData` is `Map<String, JsonObject>` with no sibling
field for type hints — `{"type":"bytes","value":"..."}` would just encode as
a nested CBOR map. The `mapping` field exists but only feeds the JWT/SD-JWT
path.

**The capability exists but is not wired up.** v0.18.2 ships
`StringToCborTypeConversion` (with `BASE64_STRING_TO_BYTE_STRING`),
`StringToCborElementConverter` (`ByteStringElement(Base64.decode(s))`) and
`JsonElementToCborMappingConfig`. Grepping the repo finds them referenced
only by the library's own tests — nothing under `waltid-services/` uses them.
`main` has the same `toDataElement()` call, so upgrading does not fix it.

walt.id's newer `waltid-mdoc-credentials2` does it right —
`@ByteString @SerialName("portrait") val portrait: ByteArray?`, commented
"ByteArray properties like portrait will be automatically encoded as bstr" —
and, contrary to what this doc originally concluded, IS wired up: to a
separate service, `issuer-api2` (`waltid/issuer-api2` on Docker Hub, not the
`waltid/issuer-api` this repo's adapter calls), via a per-namespace
`JsonElementToCborMappingConfig` and a `StringToCborTypeConversion` enum
(`base64StringToByteString`, `stringToFullDate`, etc.). See
`2026-08-20-mdl-issuer-api2-portrait-fix.md` for the full trace and a working
example. This doc's remaining sections are still accurate for the legacy
`issuer-api` this repo currently calls.

## Upgrading does not fix it

We run v0.18.2 and are several releases behind: v0.23.1 is the latest stable
(2026-08-11) and v1.0.0-PRE exists (2026-08-14). Neither helps here — checked
the source directly rather than the release notes:

| Version | `CIProvider.kt` | `JsonElementConversions.kt` |
|---|---|---|
| v0.18.2 | `property.value.toDataElement()` | `isString -> StringElement` |
| v0.23.1 | same (L523) | — |
| v1.0.0-PRE | same (L531) | same (L13) |

Still no mapping config passed, still no branch producing bytes. Upgrading
may be worth doing for other reasons, but not for this.

## Options

1. **Issue without `portrait`.** What we do today. Everything else is either
   correctly typed or tolerated by the reader we test against.
2. **Patch walt.id.** Small and localised: add an optional mapping field to
   `IssuanceRequest` and apply `JsonElementToCborMappingConfig` in
   `CIProvider.kt`. The conversion machinery is already written and tested;
   only the wiring is missing. Good upstream PR, needs a rebuilt issuer-api.
3. **Build and sign the mdoc outside walt.id**, with `@animo-id/mdoc` (already
   a dependency of cdpi-wallet). Passing a `Uint8Array` gives a correct bstr.
   The only route to a fully conformant mDL with a portrait without waiting on
   upstream, at the cost of owning issuance.

## If you patch or build outside

Decode the base64 with the **standard** alphabet, not base64url — a JPEG's
base64 contains `/` and `+` (`/9j/4AAQ...`), and walt.id's enum distinguishes
the two.

## Sources

- ISO/IEC 18013-5 §7.2.1 Table 5 (portrait is `bstr`)
- `waltid-libraries/credentials/waltid-mdoc-credentials/.../json/JsonElementConversions.kt`
- `waltid-services/waltid-issuer-api/.../issuance/CIProvider.kt` (~L466-474)
- `waltid-libraries/.../waltid-mdoc-credentials2/.../credsdata/mdl/Mdl.kt` (L28, L40-42)
