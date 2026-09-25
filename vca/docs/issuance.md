# Issuance service

The issuance service gives a credential to a citizen. It serves
`vca.issuance.v1` over Connect. It runs ADR-016.

## Why the service exists

Every DPG issues in its own way. ADR-016 decision 1 puts one contract in
front of them. An operator, a portal, or a data source calls this
service. The service then asks the DPG adapter of the deployment for the
credential. A deployment changes its DPG by changing one URL.

## What it serves

| RPC | What it does |
| --- | --- |
| `Issue` | Issues one credential for one subject. |
| `IssueBatch` | Issues many credentials. It streams the progress. |
| `GetBatch` | Returns one page of the rows of a batch. |
| `GetOffer` | Returns the state of one offer. |
| `Deferred` | Reads the state of a deferred issuance at the adapter. |

## The issuer pages

The service is the home of the issuer (ADR-044 decision 1). It serves
the issuer pages behind the staff guard of `issuer-auth` (ADR-036
decision 3). `VCA_ISSUANCE_AUTH_JWKS_URL` names the key set and
`VCA_ISSUANCE_LOGIN_URL` names the sign in chooser. The root of the
service sends the browser to `/issuer/`.

| Path | Page |
| --- | --- |
| `GET /issuer/` | The overview of the issuer. |
| `GET /identity/` | The issuer identity. |
| `POST /identity/provision` | Asks the stack for a new identity. |
| `POST /identity/import` | Checks or imports a DID or an X.509 chain. |
| `GET /.well-known/did.json` | The DID document of a `did:web` of the host. It needs no session. |
| `GET /issue/` | The published schemas and the delivery channels of the stack. |
| `GET /notifications/` | The delivery channels of the issuer and their state. |
| `GET /help/` | Every issuer RPC with its help text. |
| `POST /issuer/signout` | Ends the session at `issuer-auth`. |

Every page draws inside the issuer shell of
`services/internal/staffshell`. The shell shows the role chip, the
stack switcher, the user menu, and the side navigation of
`internal/rolenav`. The stack switcher lists the issuer pairs that run,
from `VCA_PEERS`. The service also serves the shared assets at
`/static/`. It reads the theme file of `VCA_THEME_FILE` at start and
stops when the file is wrong (ADR-032).

The overview shows four steps: identity registered, schema published,
first credential issued, and manage. A step unlocks when the staff
member finishes every step before it. The cards count the published schemas through
`SchemaService.List` and the issued credentials through
`IssuedService.List`. The recent activity comes from the audit log of
the service.

The identity page shows the identity the stack signs with. It also
shows its entry in the trust registry of the first live admin pair.
"Start instantly" asks the stack for a key and an identifier. "Bring
your own" checks a DID or an X.509 chain. It then binds the identifier
to a key reference in the key store of the stack. The stack keeps the key; VCA stores no issuer
private key (ADR-001 decision 3, ADR-046). A box asks the trust
registry for an entry in state `pending`, which an admin approves. The
page hides the box when no live admin pair runs a trust registry, and
says so. The service serves the DID document of a `did:web` of its
host at `/.well-known/did.json`.

Each call of the pages to the issued credentials service names the
staff member in the `X-Vca-Actor` header. The audit log of that service
then names the staff member (ADR-039 decision 1).

## The steps of one issuance

1. The service reads what the adapter supports. It keeps the answer for
   a few minutes (ADR-016 decision 6).
2. It reads the schema from the schema registry, when the deployment has
   one. It checks the claims against the JSON Schema with
   `core/jsonschema`.
3. It picks the wire format. The request wins. The schema comes next.
   The first format of the adapter comes last.
4. It refuses a channel the adapter does not support. The document
   channels need no adapter channel, because the service renders them.
5. It reserves a status list entry, when the deployment has a status
   service. An SD-JWT credential gets a token status list entry. Another
   format gets a bitstring status list entry.
6. It asks the adapter for an offer, or for a signed credential.
7. It renders the page, when the channel needs one.
8. It records the issuance in the issued credentials service.
9. It hands the message to the sender of the channel.

## The channels

ADR-016 decision 5 names five channels.

| Channel | What the citizen gets |
| --- | --- |
| `oid4vci` | An offer URI. A wallet claims the credential. |
| `pdf` | An A4 page with a QR code. |
| `email` | A message with a link to the page. |
| `sms` | A short message with the link. |
| `link` | The link alone. |

## The rendered page

ADR-016 decisions 3 and 4 ask for a page with the credential in a QR
code. The service writes the page with `core/pdf` and the symbol with
`core/qr`. Both packages use the standard library only. The service
loads no font file and no image library.

The page holds the title, the issuer line, and the claims in a table. It
holds the QR code, a note, and the footer as well. It lists twenty
claims at most. The QR
symbol grows with its payload, and the service scales it to fit.

The QR payload holds one of two things:

- The credential offer URI, for an offer channel. A wallet reads it.
- The credential in the PixelPass form, for a signed credential. The
  form is CBOR, then zlib, then base45. The MOSIP tools read it.

A page lives as long as its offer. The endpoint
`GET /issuance/pdf/{ref}` serves it with the type `application/pdf` and
the header `Cache-Control: no-store`.

## The senders

ADR-016 decision 5 asks for one sender interface. The service ships
these:

| Sender | What it does |
| --- | --- |
| `log` | Writes one line for each message. |
| `file` | Writes the message and the attachment into a directory. |
| `stub` | Returns `ErrNotConfigured`. |

The email channel and the SMS channel use the stub by default. A
deployment with a gateway replaces the stub. The service keeps no
gateway code, so a deployment picks its own.

## Batches

`IssueBatch` takes rows in the request, or the id of a data source job.
With a job id the service reads the field map and the rows from the data
source service. It maps the columns onto the properties with
`core/mapping`.

The answer streams one message at the start, one message for each row,
and one message at the end. Each message carries the counts. The service
stores every row, so `GetBatch` pages through them later. The flag
`failed_only` returns the rows that failed, with the reason and the next
step.

## Where the records go

ADR-017 decision 1 puts the record of an issuance in the issued
credentials service. The contract `vca.issued.v1` reads and changes
records. The `Append` RPC of that contract takes one new record and
returns its id and its hash. The issuance service calls it with a
Connect client. The file `services/issuance/internal/clients/recorder.go`
holds that code alone. A deployment without the issued credentials
service keeps the record in the log.

## Audit log

The service writes one audit event for each issue, alone or in a batch (ADR-039 decision 1).
The event names the actor, the action, the target, the outcome, and the
request id. It never holds a claim value. A failure names the Connect
code of the answer, never the text of the error. The service checks no
session itself, so the actor is the one its caller names in the
`X-Vca-Actor` header.

The events live in an append only store under `VCA_ISSUANCE_AUDIT_DIR`.
The CLI sets it to `/data/audit`. The service serves the store as
`vca.audit.v1.AuditService` on the internal network. Only the admin
opens it: an admin session that the key set at `VCA_ISSUANCE_ADMIN_JWKS_URL`
signed, or the token in `VCA_ISSUANCE_ADMIN_TOKEN`. The pair proxy does not
route the service. `SetRetention` keeps the events of the last days the
admin sets and removes older ones.

## Tests

Every package has unit tests with fakes. The service tests drive the
real Connect handler behind an `httptest` server, because the batch RPC
streams. The render tests check that the page starts with `%PDF-1.4`,
that it is A4, and that the QR payload reads back.

## Reference

- Service folder: `services/issuance`
- Contract: `proto/vca/issuance/v1/issuance.proto`
- Decisions: ADR-016 decisions 1 to 6, ADR-002 decisions 2 and 5,
  ADR-017 decision 1, ADR-044 decision 1
