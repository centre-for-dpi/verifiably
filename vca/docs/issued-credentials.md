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
| `offer_id` | The offer id in the issuance service. |
| `dpg_offer_id` | The offer id that the DPG adapter assigned. The pages read the claim state of the offer with it. Empty for a credential without an offer. |

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

A stack can change the status of a credential in its own ledger. A
record from that ledger carries the ledger id in `dpg_credential_id`.
For such a record, a revoke goes to `Revoke` of the adapter when it
lists `FEATURE_REVOCATION` (ADR-034 decision 5). A suspension and a
reinstatement go there when it lists `FEATURE_SUSPENSION`. The request
carries the action and the ledger id. Every other change goes to the
status service. A record with a status entry of VCA has its bit in a
VCA list. The service reads the features from `GetCapabilities` of
`VCA_ISSUED_ADAPTER_URL` and keeps the answer for one minute. The rule
of the order holds: the log writes the event only after the stack took
the change.

## Sync from the stack ledger

A stack can keep a ledger of the credentials it issued. Its adapter
then lists `FEATURE_ISSUED_LEDGER` and serves `ListIssuedCredentials`.
The sync reads every page of one search: a credential type, one
indexed attribute, and its value. It adds each entry the log lacks as a
record of the stack. The record holds the ledger id and the status
entry of the stack. A second sync adds nothing twice. The schema of an
added record is the credential type of the search, version 1. The
ledger names no VCA schema. The subject reference is the salted reference of
the value. The log keeps no claim value of the ledger.

## Audit log

The service writes one audit event for each revoke, suspend, reinstate, export, and sync (ADR-039 decision 1).
The detail of a status change names the new status, and the stack when
the stack made the change. The detail of an export names the count and
the encoding.
The event names the actor, the action, the target, the outcome, and the
request id. It never holds a claim value. A failure names the Connect
code of the answer, never the text of the error. The service checks no
session itself, so the actor is the one its caller names in the
`X-Vca-Actor` header.

The events live in an append only store under `VCA_ISSUED_AUDIT_DIR`.
The CLI sets it to `/data/audit`. The service serves the store as
`vca.audit.v1.AuditService` on the internal network. Only the admin
opens it: an admin session that the key set at `VCA_ISSUED_ADMIN_JWKS_URL`
signed, or the token in `VCA_ISSUED_ADMIN_TOKEN`. The pair proxy does not
route the service. `SetRetention` keeps the events of the last days the
admin sets and removes older ones.

## List, search, and export

`List` returns records newest first, in pages. `Search` matches the text
against the searchable claims, ignoring case. The query holds at most
200 characters. A filter narrows both by schema, status, format,
subject reference, and time window.

`Export` streams the matching records. The field `query` matches the
searchable claims, as `Search` does, so an export holds the rows of a
search. The encoding is RFC 4180 CSV with
a header row, or one JSON object per line. The service writes the same
CSV columns every time. The searchable claim columns follow them, sorted
by name. A CSV cell can start with `=`, `+`, `-`, `@`, a tab, or a
carriage return. Such a cell gets a leading quote, so a spreadsheet does
not read it as a formula. The JSON lines keep every value as it is. The service
sends the bytes in chunks. It marks the last chunk `done`.

`Get` and every list report an active record whose validity window
ended as expired.

A record whose validity window ended reads as expired in every list,
search, and export, even before a status change.

## Pages

The service draws the issued credentials pages of the issuer at
`/issued/` (P3-10, ADR-044 decision 2, board `Issuer-Issued`). The pages
sit behind the staff guard of `issuer-auth` and draw the issuer shell.
They call the service in process. Every call names the staff member in
`X-Vca-Actor`, so the audit log holds the actor of each change and each
export. The chain head endpoints keep their own routes outside the
guard.

| Path | Page |
|---|---|
| `GET /issued/` | The search, the filters, and one page of the records, newest first. |
| `GET /issued/export.csv` | The rows of the search and the filters as CSV. |
| `GET /issued/export.json` | The same rows as one JSON object per line. |
| `GET /issued/{id}` | The stored fields, the record, and the history. |
| `GET /issued/{id}?action=` | The same page with the reason dialog of `suspend`, `revoke`, or `reinstate` open. |
| `POST /issued/{id}/suspend`, `/revoke`, `/reinstate` | The status change with its reason. |
| `GET /issued/sync` | The ledger search of the stack. It exists only while the adapter lists `FEATURE_ISSUED_LEDGER`. |
| `POST /issued/sync` | The sync of one search, with a table of each entry and its result. |

The search matches the searchable claims. The filters are the schema,
the status, and a range of issuance days. The export buttons carry the
search and the filters, so a file holds the rows of the page.

The detail page lists the stored fields and the log entry. Above the
fields it says "VCA stores only the fields you mark as searchable." That
sentence follows ADR-017 decision 2. The entry holds the record id, the
format, the adapter, and the status list entry. It also holds the last reason, the offer id, the
hash, and the retention. The history starts with the issuance. Then it
lists each audit event of this service for the record, with its actor
and its result.

Only an issuer operator or an issuer admin changes a status. A viewer
sees the record and a sentence that says who can act. Each action opens
a dialog with a reason field and the synchronizer token of the session.
An empty reason stays in the dialog with the error on the field. The
dialog of a revoke names the stack for a record of the stack ledger
when the adapter lists `FEATURE_REVOCATION`.

The list offers "Sync from stack" only when the adapter lists
`FEATURE_ISSUED_LEDGER`. Only an issuer operator or an issuer admin
runs a sync, because a sync adds records to the log.

The state "Offered, not claimed" shows only when the adapter lists
`FEATURE_ISSUANCE_STATUS`. The page then asks `GetIssuanceStatus` of the
adapter with the `dpg_offer_id` of each active record in view.

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
