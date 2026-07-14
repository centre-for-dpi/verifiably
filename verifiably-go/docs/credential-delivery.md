# Credential Delivery Mechanisms

> Architectural decision, 2026-06-09. Defines the full space of credential
> delivery mechanisms so the National ID and Discovery work is designed against
> the right model rather than as isolated features.

"Issuance" is not one thing. It is a family of delivery mechanisms with very
different security and UX properties. This document maps that space, classifies
what `verifiably-go` already does, and identifies the gaps that should shape the
near-term roadmap.

## The two axes that matter

Every delivery mechanism is defined by two questions. Everything else (channel,
format, timing) is secondary.

1. **Who initiates?** — *Issuer-initiated* (push) vs *Holder-initiated* (pull).
2. **Is it bound to an authenticated identity?** — *Anonymous* (pre-auth code,
   channel-possession trust) vs *Identity-bound* (auth code + verified claims).

```
                 ANONYMOUS               IDENTITY-BOUND
              ┌─────────────────┬──────────────────────┐
  ISSUER      │  ① QR / link    │  ⑥ Push to wallet     │
  INITIATES   │  ④ PDF          │  ⑧ DIDComm proactive  │
              │  ⑤ Bulk         │                       │
              ├─────────────────┼──────────────────────┤
  HOLDER      │       —         │  ② Auth code flow     │
  INITIATES   │  (no meaning:   │  ③ Self-service from  │
              │   nothing to    │     catalog           │
              │   bind to)      │                       │
              └─────────────────┴──────────────────────┘
```

The lower-left cell is intentionally empty: a holder-initiated request with no
authenticated identity has nothing to bind the credential to.

## Mechanisms, mapped to the code

| # | Mechanism | Initiator | Binding | Status in repo |
|---|---|---|---|---|
| 1 | OID4VCI pre-auth + QR/link | Operator | Anonymous | ✅ `Adapter.IssueToWallet` — current default |
| 2 | OID4VCI auth code flow | Holder authenticates | Identity-bound | ⏳ National ID Nivel 2 |
| 3 | Self-service from catalog | Holder browses | Identity-bound | ⏳ Credential Discovery |
| 4 | PDF / printed with verifiable QR | Operator | Anonymous | ✅ `Adapter.IssueAsPDF` |
| 5 | Bulk → link by email/notification | Operator | Anonymous | ✅ `Adapter.IssueBulk` + async job queue |
| 6 | Push to holder's wallet | Issuer pushes | Identity-bound | ❌ requires holder notification channel |
| 7 | Deferred issuance (approval needed) | Operator, holder waits | Either | ❌ not implemented |
| 8 | DIDComm proactive delivery | Issuer pushes | Identity-bound | ⚠️ CREDEBL supports it natively (Aries); not exposed |

## The structural gap

The three mechanisms in production today (1, 4, 5) all sit in the
**anonymous + operator-initiated** quadrant. That is correct for a guided demo,
but it has two ceilings:

- **No guarantee of *who* received it.** A pre-auth offer does not know who
  redeems it. If the link leaks, anyone can claim the credential.
- **The operator is the bottleneck.** It does not scale to "millions of citizens
  self-issue their own credential."

National ID (Nivel 2) and Credential Discovery are not loose features — together
they are the move from the anonymous/operator quadrant to the
**identity-bound + holder-initiated** quadrant. That is why they belong together
and in this order.

## Mechanisms not yet on the roadmap

Three mechanisms are worth recording now, even if not built immediately, because
they constrain whether the National ID / Discovery design is extensible.

### Deferred issuance (#7)

OID4VCI formally defines it: the holder requests a credential and the issuer
responds "not ready yet, come back with this `transaction_id`." This is critical
for credentials that need human approval or back-office verification (e.g. a
licence a civil servant must review). Without it, *every* issuance must be
instantaneous — unrealistic for high-value government credentials. The moment
self-service issuance is real, deferred issuance is required alongside it.

### Holder notification channel (#6) — unify with push revocation

This is the mirror of the already-tracked "push revocation to holder." The same
channel that pushes a *revocation* serves to push an *issuance / renewal*
(e.g. a licence expires and the State pushes the renewed one with no holder
action). The two should be designed as one **holder notification channel**, not
two parallel webhooks. See `[ARCH] Push revocation notification to holder` in
`TODO.md` and the Discovery `[FEAT] Push notification to wallet` item.

### DIDComm proactive delivery (#8)

CREDEBL is Aries underneath and already performs proactive delivery over
DIDComm; `verifiably-go` does not expose it. For federation with entities that
already speak Aries, this may be nearly free architecturally. Worth a spike to
confirm before committing to it.

## Recommended sequencing

Do not think of "National ID" and "Discovery" as features. Think of it as
**completing the identity-bound quadrant**, which has a natural order:

1. **Auth code flow + claim binding** (National ID Nivel 2) — the foundation;
   it lets *any* mechanism become identity-bound.
2. **Self-service catalog** (Discovery) — the first holder-initiated mechanism;
   depends on (1) for the subject data and eligibility evaluation.
3. **Deferred issuance** — needed as soon as self-service is real, because not
   every credential issues instantly.
4. **Holder notification channel** (push) — unifies push-issuance and
   push-revocation.

National ID first is the lowest-friction, highest-impact path: a citizen
authenticates with their national IdP → their data is already in the issuance
form → their credentials are bound to their identity → Discovery then has real
data to work with.
