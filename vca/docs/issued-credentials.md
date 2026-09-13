# Issued credentials

This page describes the `issued-credentials` service (ADR-017). The
service README at
[`services/issued-credentials/README.md`](../services/issued-credentials/README.md)
says how to run it. This page says how it works.

## Data model

Every issuance writes one record (ADR-017 decision 1). The record names
the credential without holding it.

| Field | Meaning |
|---|---|
| `id` | The record id. The issuance service assigns it. |
| `schema_id`, `schema_version` | The schema the credential follows. |
| `subject` | The salted, one way reference of the subject. |
| `format` | The wire format, for example `dc+sd-jwt`. |
| `status_binding` | The status list kind, list id, and index. Empty when the credential is not revocable. |
| `status` | Active, suspended, revoked, or expired. |
| `dpg` | The DPG adapter that issued the credential. |
| `issued_at` | The time of the issuance. |
| `hash` | The SHA-256 hash of the credential bytes. |
| `previous_hash`, `record_hash` | The links of the hash chain. |
| `searchable_claims` | Only the claims the issuer marks as searchable. |
| `validity` | The validity window of the credential. |
| `status_changed_at`, `status_reason` | The last status change and its reason. |
| `retain_until` | The time after which the prune job can drop the record. |

## Data minimisation

The log holds no personal data (ADR-017 decision 2). It holds two
things that point at a person.

The first is the subject reference. It is an HMAC-SHA256 of the subject
with the deployment salt as the key. Nobody can build a rainbow table
without the salt. The record never holds a DID or a name. The package
rejects a reference that looks like a DID.

The second is the searchable claims. The issuer marks which schema
properties staff can search. The service keeps only those claims. It
drops every other claim.

## The hash chain

The log is append only. It holds two kinds of event.

| Event | Meaning |
|---|---|
| `issue` | A new record joins the log. |
| `status` | The status of one record changes. |

The state of a record is the fold of its events, so a revoke never
rewrites history. The service stores the events as entries of
[`core/hashchain`](../core/hashchain). The hash of an entry is SHA-256
over three parts. They are the previous hash, a zero byte, and the
canonical JSON of the event. Canonical JSON sorts the keys at every
level and holds no white space.

`VerifyChain` walks the chain from one record to the head. It reports
the number of entries it checked and the id of the first broken entry.
The service also verifies every link when it opens the store, so a
changed file stops the start.

The legacy monolith hashed only a few fields of the previous entry
(`verifiably-go/internal/issuance/log.go`). This service hashes the
whole event, so a change to any field breaks the chain.

## The signed head

The head is the last entry of the chain (ADR-017 decision 4). The
service signs it once a day with an ES256 key. The signature is a
compact JWS with the `typ` header `vca-chain-head+jwt`.

The payload holds these claims.

| Claim | Meaning |
|---|---|
| `iss` | The name of the deployment. |
| `iat` | The time of the signature. |
| `record_id` | The id of the last record. |
| `record_hash` | The hash of the last entry. |
| `length` | The number of entries in the chain. |

An unchanged head keeps its signature until the period ends. A new entry
makes the service sign again at once.

Two endpoints serve auditors without a Connect client
(ADR-003 decision 7).

```
GET /issued/chain-head   the latest signed head as a compact JWS
GET /issued/jwks.json    the public key that signed it
```

An auditor keeps the head of each day. Two heads prove that the log only
grew. The older `length` is smaller. The walk from the older record to
the newer head matches.

## Revoke and reinstate

`Revoke` sets the status to revoked or suspended. `Reinstate` clears a
suspension. Both need a reason, and both record it
(ADR-017 decision 3).

The order of the two writes matters. The service calls the status
service first. The log writes the event only after the status list holds
the new bit. A failed status call leaves the log unchanged. The log
never claims a change that the list does not hold.

| Rule | Behaviour |
|---|---|
| A revoked credential | Stays revoked. The service rejects any further change. |
| A credential with no status list binding | Cannot change status. The service reports a failed precondition. |
| A reason that is empty | The service rejects the call. |
| A reinstate of an active credential | The service rejects the call. |

The status client is a `vca.status.v1.StatusService` Connect client. The
deployment sets its base URL. Without a URL the service reports a failed
precondition, so an operator sees the missing setting at once.

## List, search, and export

`List` returns records newest first, in pages. `Search` matches the text
against the searchable claims, ignoring case. The query holds at most
200 characters. A filter narrows both by schema, status, format,
subject reference, and time window.

`Export` streams the matching records. The encoding is RFC 4180 CSV with
a header row, or one JSON object per line. The service writes the same
CSV columns every time. The searchable claim columns follow them, sorted
by name. The service sends the bytes in chunks. It marks the last chunk
`done`.

A record whose validity window ended reads as expired in every list,
search, and export, even before a status change.

## Retention

A retention rule says how long the log keeps the records of one schema
(ADR-017 decision 5). The setting is a list of `schema=period` pairs.
The name `default` covers every schema without a rule of its own.

```
VCA_ISSUED_RETENTION=default=5y,diploma=10y,visitor=30d
```

The units are s, m, h, d, w, and y. A year is 365 days. A period of zero
keeps the record forever, and so does a schema with no rule and no
default.

The service writes `retain_until` when it appends the record. A
scheduled job runs every `VCA_ISSUED_PRUNE_INTERVAL` and drops every
record whose time passed. The job removes the record from the read
index only. The chain keeps every entry, so the head still proves that
nothing went missing.

The proto has no `Prune` RPC. The job is the only caller, and the
service exposes `Prune` as an in process method. An RPC needs a change
to `proto/vca/issued/v1/issued.proto`.

## Errors

| Case | Connect code | Catalogue |
|---|---|---|
| No record with that id | `not_found` | |
| An empty reason, a bad page token, a long query | `invalid_argument` | |
| A revoked credential, no binding, no status client | `failed_precondition` | |
| The status service is down | `unavailable` | `VCA-401` |

## Reference

- ADR-017 in [`adr.md`](adr.md).
- The API: [`proto/vca/issued/v1/issued.proto`](../proto/vca/issued/v1/issued.proto).
- The hash chain: [`core/hashchain`](../core/hashchain).
- The status service: ADR-018 and ADR-019.
