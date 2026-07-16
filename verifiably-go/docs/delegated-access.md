# Delegated access

How Verifiably lets one party (a **delegate**) prove they are authorised to act
**on behalf of** another (the **principal**) — a lawyer for a client, a director
for a company, a parent for a child — and how a verifier decides whether to honour
that authority. This page walks the whole mechanism: the model, the evaluator, the
two credentials, the formats, issuance, verification UX, revocation, and the known
limits.

---

## 1. The model in one paragraph

Delegated access is carried by a **pair** of credentials, presented together:

| Credential | Held by | Says |
|---|---|---|
| **Identity** (subject) | the delegate's wallet | *who the principal is* (e.g. a Pet Card / national ID), anchored on a stable `subjectRef` |
| **Delegation** | the delegate's wallet | *this delegate may perform `allowedAction` on behalf of `onBehalfOf`, until `validUntil`* |

The delegate presents **both** in one OID4VP request. The verifier runs the normal
credential checks (signature, expiry, status) **and** a delegated-access evaluator
that answers one question: *is this presenter authorised to act for this subject?*

```
        issues                       issues
issuer ───────▶ Identity cred         issuer ───────▶ Delegation cred
                    │                                      │
                    └──────────── both claimed ────────────┘
                                       │
                            delegate's wallet
                                       │ presents the pair (OID4VP)
                                       ▼
                                   verifier
                                       │ host verifies sig / binding / status
                                       ▼
                         internal/delegation.Evaluate(...)
                              linkage · invocation · capability · revocation
                                       ▼
                              AUTHORISED / DENIED
```

---

## 2. The evaluator (`internal/delegation`)

The evaluator is **DPG- and format-agnostic** and **never re-verifies signatures or
holder binding** — that is the host verifier's job, and we trust its verdict. It
owns exactly the four checks no deployed DPG performs:

> Package doc (`internal/delegation/delegation.go`):
> *"The evaluator owns exactly the four checks no deployed DPG performs: linkage,
> invocation binding, capability/caveats, and uniform revocation status. Status and
> trust lookups are injected as functions so this package stays pure and
> unit-testable."*

It runs over a normalized, per-credential view of the presentation
(`backend.NormalizedCredential`) that each verifier adapter populates, with status
and trust injected as function options:

```go
func Evaluate(ctx context.Context,
    creds []backend.NormalizedCredential,
    holder *backend.HolderBinding,
    opts Options) backend.DelegationResult
```

`Evaluate` first locates a delegation credential; if there is none it returns
`{Evaluated:false}` and the base verdict is left untouched. Otherwise it runs the
four checks, short-circuiting on the first failure with a human-readable `Reason`.

### Check 1 — Linkage: *is this delegation about the presented subject?*

```go
// onBehalfOf may name the principal by their subjectRef, DID, or any disclosed
// identifier (subjectIdentifies); the error lists what was available.
if cap.OnBehalfOf == "" || !subjectIdentifies(identity, cap.OnBehalfOf) {
    res.Reason = fmt.Sprintf("linkage failed: delegation onBehalfOf %q matches none "+
        "of the identity credential's identifiers %v — at issuance, set onBehalfOf "+
        "to the holder's subjectRef, an identifier field, or DID",
        cap.OnBehalfOf, subjectIdentifiers(identity))
    return res
}
res.Linkage = true
```

The delegation's `onBehalfOf` must match a **unique identifier** the identity
credential carries — see [§5 Linkage anchoring](#5-linkage-anchoring).

### Check 2 — Invocation: *is the presenter the bound delegate?*

The delegate is the holder-bound credential subject (`credentialSubject.id`,
rebound to the presenting holder by OID4VCI at claim time). When the host surfaces
a confirmed holder binding, the presenter must equal that delegate:

```go
delegate := deleg.SubjectID
if delegate == "" { delegate = cap.Delegate }

// holder-bound model: a confirmed binding establishes the delegate even when the
// credential names none (e.g. Inji auth-code proves possession at CLAIM time).
if delegate == "" && (holder == nil || !holder.Confirmed) {
    res.Reason = "delegation credential names no delegate"; return res
}
if holder != nil && holder.Confirmed && delegate != "" {
    if hid := holderRef(holder); hid != "" && !sameRef(hid, deleg.SubjectID) && !sameRef(hid, cap.Delegate) {
        res.Reason = fmt.Sprintf("invocation failed: presenter %q is neither the "+
            "delegation subject nor the named delegate", hid)
        return res
    }
}
res.Invocation = true
```

> **Gotcha:** if the wallet binds the identity and delegation to *different* holder
> DIDs (e.g. `did:key` vs `did:jwk` across claim sessions), invocation fails. Claim
> both credentials into the **same** wallet/DID. See [§10 Wallet limits](#10-known-limits-waltid-v0182-wallet).

### Check 3 — Capability: *is the action permitted, within validity, no chain?*

```go
if cap.HasChain { res.Reason = "re-delegation chains are not supported in v1"; return res }
if cap.Controller != "" && deleg.Issuer != "" && !sameRef(cap.Controller, deleg.Issuer) {
    res.Reason = "capability controller is not the credential issuer"; return res
}
if cap.ValidUntil != "" { /* parse + reject if opts.now().After(until) */ }
if opts.RequestedAction != "" && len(cap.AllowedAction) > 0 &&
   !containsFold(cap.AllowedAction, opts.RequestedAction) {
    res.Reason = fmt.Sprintf("action %q is not permitted by the delegation (allowed: %s)",
        opts.RequestedAction, strings.Join(cap.AllowedAction, ", "))
    return res
}
res.Capability = true
```

> **Gotcha:** the verifier's default `RequestedAction` is `present`. If your
> `allowedAction` doesn't include `present`, the presentation act itself is denied —
> include `present` alongside the domain actions.

### Check 4 — Revocation: *neither credential is revoked* (uniform across formats)

```go
for _, c := range []backend.NormalizedCredential{identity, deleg} {
    ref, has := statusRef(c)
    if !has { continue }
    revoked, err := opts.Status(ctx, ref)
    if err != nil && opts.FailClosed {
        res.Reason = fmt.Sprintf("revocation status unavailable for %s (fail-closed)", ref.URI)
        return res
    }
    if revoked { res.Reason = "a presented credential has been revoked"; return res }
}
```

When all four pass (and trust, when enforced), `Authorized = true`. The verdict
renders as a card on the verifier and the holder consent screen:

```
🔑 DELEGATED ACCESS — AUTHORISED
  Linkage      pass ✓
  Invocation   pass ✓
  Capability   pass ✓
  Not revoked  pass ✓
```

---

## 3. The capability — one normalized shape, three encodings

The decision logic reads a single `Capability` struct regardless of how the
delegation credential encoded its authority:

```go
type Capability struct {
    Controller    string   // root authority; must equal the credential issuer
    OnBehalfOf    string   // the subject the delegate acts for (linkage anchor)
    Delegate      string   // the delegate (should equal the delegation subject)
    AllowedAction []string // permitted actions; empty => unconstrained
    ValidUntil    string   // RFC3339; empty => no caveat (status list governs)
    ...
}
```

`extractCapability` (in `internal/delegation/extract.go`) fills it from whichever
shape is present, in order:

1. **JSON-LD `termsOfUse`** (W3C VCDM, walt.id) — a `DelegationCapability` entry:
   ```json
   "termsOfUse": [{
     "type": "DelegationCapability",
     "invocationTarget": "urn:person:bosco",
     "allowedAction": ["present", "consent:disclose"],
     "caveat": [{ "type": "ValidWhile", "validUntil": "2033-03-10T00:00:00Z" }]
   }]
   ```
2. **SD-JWT `delegation` claim** (object or JSON string).
3. **Flat top-level claims** — `onBehalfOf`, `allowedAction`, `validUntil`
   (Inji Certify can't nest, so the capability is carried as flat claims).

Because `vp.FromVCObject` flattens `credentialSubject` into `Claims`, a JSON-LD
`ldp_vc` capability resolves with **no extra code** — the flat path reads it via
`Claims`. This is why one evaluator absorbs every DPG's quirks.

---

## 4. Issuance — building the pair

`POST /api/v1/delegation/issue` registers the two credential **types** once
(idempotent), then issues both. The shared core is `issueDelegationPairCore`
(`internal/handlers/api_delegation_bulk.go`). For **W3C** the bodies are supplied
verbatim via a `CredentialData` override; for **SD-JWT** via flat `SubjectData`
claims. The delegation body is built by `delegation.BuildDelegationCredential`:

```go
// Always carry the canonical DelegatedAccessCredential marker (the evaluator's
// hook) AND, when distinct, the catalog/scenario type so a verifier can request
// the pair by either name (e.g. "PowerOfAttorney", "PetAccessCredential").
types := []string{"VerifiableCredential", "DelegatedAccessCredential"}
if d.Type != "" && d.Type != "DelegatedAccessCredential" { types = append(types, d.Type) }

doc := map[string]any{
    "@context":          contextArr(d.DataModel, d.ContextURL),
    "type":              types,
    "credentialSubject": cs,            // { onBehalfOf:{id}, role, id:<delegate> }
    "termsOfUse":        []any{capability},
}
```

Request shape:

```jsonc
POST /api/v1/delegation/issue
{
  "issuerDpg": "Walt Community Stack",
  "std": "w3c_vcdm_2",                 // | "w3c_vcdm_1" | "sd_jwt_vc (IETF)"
  "subject":    { "type": "PetCard", "subjectRef": "urn:pet:bosco",
                  "claims": { "givenName": "Bosco" } },
  "delegation": { "type": "PetAccessCredential", "role": "Owner",
                  "allowedAction": ["present","access"],
                  "validUntil": "2033-03-10T00:00:00Z" }
}
```

The response returns an offer URI + credentialId for each leg, plus the status-list
binding. **Bulk** (`POST /api/v1/delegation/issue/bulk`) fans the same core out
over rows via the async job queue — it registers the types **once**, then issues a
pair per row (re-registering per row would restart walt.id's issuer-api).

---

## 5. Linkage anchoring

The verifier links the two credentials on a **unique identifier**:
`delegation.onBehalfOf` must equal one of the identity credential's identifiers.
`subjectIdentifiers` (`extract.go`) defines what counts:

```go
func subjectIdentifiers(c backend.NormalizedCredential) []string {
    // ... add subjectRef (any source) + the subject DID + identifier-named fields
    add(mapStr(cs, "subjectRef")); add(c.SubjectID)
    for k, v := range c.Claims {
        if isIdentifierFieldName(k) { add(v) } // testa_id, nationalId, uin, …
    }
}

// isIdentifierFieldName: an "…id / …number / …ref" suffix or an explicit
// id/uin/nin/identifier token — so testa_id qualifies but last_name does NOT.
```

So `onBehalfOf` may map to the identity's `subjectRef`, its DID, **or** any
identifier-named field (a national ID, `testa_id`, …) — but **not** a plain name.
The issuer is guided to set this at issuance (a JIT callout next to the `onBehalfOf`
field on the issue page).

---

## 6. Revocation — type-aware, uniform check

Each delegation credential gets its own revocation slot at issuance. `statusRef`
prefers the verifiably-hosted **flat** status (`statusUri`/`statusIdx` + a
`statusType` of `bitstring`|`token`) over a DPG-stamped `credentialStatus` — because
the flat list is the one we host and can dereference, while e.g. Inji's auth-code
Certify stamps an internal `credentialStatus` URL the verifier can't reach:

```go
// FLAT status is preferred when present (revocable, publicly dereferenceable).
if uri := flatClaim(c, "statusUri"); uri != "" {
    typ := "TokenStatusList"
    if strings.Contains(strings.ToLower(flatClaim(c, "statusType")), "bitstring") {
        typ = "BitstringStatusListEntry"
    }
    return StatusRef{Type: typ, URI: uri, Index: idx, ...}, true
}
// else credentialStatus (W3C bitstring) … else status.status_list (SD-JWT token)
```

`POST /api/v1/delegation/inji/revoke` (and the issued-log Revoke button) flip the
right store: **bitstring** for W3C, **token** for SD-JWT.

---

## 7. The DPG / format matrix

Delegated access is proven end-to-end (issue → claim → **AUTHORISED** → revoke →
**DENIED**) across:

| DPG | W3C VCDM 1.1 | W3C VCDM 2.0 (ldp_vc) | SD-JWT |
|---|---|---|---|
| **walt.id** | ✅ | ✅ | ✅ |
| **Inji Certify · pre-auth** | — | ✅ | ✅ |
| **Inji Certify · auth-code** | — | evaluates ✓ (revocation Certify-managed) | ✅ |
| **CREDEBL** | — | — | ✅ (SD-JWT-only DPG) |

The headless conformant-proof holder (`injiPreAuthClaim`) + `POST
/api/v1/delegation/verify/sdjwt` is the reusable holder for any OID4VCI pre-auth
issuer.

---

## 8. Verifier UX — the two-step pair picker

On **Verifier → Verify**, ticking *"Verify as a delegated-access pair"* turns the
credential grid into a two-step picker:

1. **Step 1** — the grid auto-filters to cards that have an `onBehalfOf` field (the
   delegations). Pick one.
2. **Step 2** — the grid flips to the remaining cards (the identities). Pick the one
   the delegation is about.
3. *"✓ Pair selected"* → Generate. Both picks live on the session and build the
   OID4VP request (`req.Templates = [subject, delegation]`).

`GenerateRequest` builds each leg with the right type/format/vct via
`buildTemplateForSchema`, requesting only `onBehalfOf` for a W3C delegation (the
capability lives in `termsOfUse`, always disclosed) but **all** flat claims for an
SD-JWT one (selectively disclosed).

> **Single format only:** walt.id v0.18.2 rejects a request whose descriptors have
> different formats. Step 2 is therefore filtered to the **same wire format** as the
> picked delegation (`wireFormatOf`: `jwt_vc_json` for W3C, `vc+sd-jwt` for SD-JWT).
> The issuer is warned at issuance to keep both legs one format.

---

## 9. Holder consent — one card per requested credential

The holder's *"Review what's being shared"* parses **every** PD input-descriptor
(`describePDCredentials`) and renders a card per credential the verifier is asking
for — type, format, disclosure, the claims requested, and an *in-your-wallet*
indicator — so a pair shows as *"The verifier is requesting 2 credentials"* with a
card each, not one title with another's claims.

---

## 10. Known limits (walt.id v0.18.2 wallet)

The evaluator is correct; the wallet is the bottleneck for multi-credential
presentations:

- **SD-JWT pairs can't be presented.** Combining two SD-JWT credentials makes the
  vpToken a JSON array the wallet-api can't serialize (`JsonArray is not a
  JsonPrimitive`). Use **W3C `jwt_vc_json`** for pairs.
- **W3C pairs work but require one wallet/DID.** Both credentials must be claimed
  under the same holder DID or invocation fails.
- **Mobile wallets often present only one descriptor** of a multi-credential
  request. Use the walt.id holder wallet for pairs.

**Reliable recipe today:** W3C `jwt_vc_json`, both credentials in one wallet/DID,
presented via the walt.id holder wallet.

---

## 11. API surface (delegated access)

| Method & path | Purpose |
|---|---|
| `POST /api/v1/delegation/issue` | issue a subject+delegation pair |
| `POST /api/v1/delegation/issue/bulk` | fan a pair out over many rows (async job) |
| `POST /api/v1/delegation/verify/request` | generate an OID4VP pair request |
| `GET  /api/v1/delegation/verify/result/{state}` | the delegation verdict |
| `POST /api/v1/delegation/verify/sdjwt` | evaluate raw SD-JWT creds (headless) |
| `POST /api/v1/delegation/inji/setup` | provision an Inji auth-code pair |
| `POST /api/v1/delegation/inji/preauth/issue` | stage Inji pre-auth offers |
| `POST /api/v1/delegation/inji/preauth/claim` | headless conformant-proof claim |
| `POST /api/v1/delegation/inji/revoke` | revoke (type-aware: bitstring/token) |

Full request/response schemas are in the OpenAPI spec at **`/api/docs`**.
