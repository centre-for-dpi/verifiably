# Verifier ingestion

This page describes the `verifier-ingest` service (ADR-023). The service
README at
[`services/verifier-ingest/README.md`](../services/verifier-ingest/README.md)
says how to run it. This page says how it works.

## Carriers

Every carrier ends in one `RawPresentation` message
(ADR-023 decisions 1 and 2). The decoders sit in `core/ingest`. They are
pure functions: they take bytes and return a result. Each one has a fuzz
target, so a broken input never stops the service.

| Carrier | Input | Steps |
|---|---|---|
| OID4VP request | An `openid4vp://` URL or an authorization URL. | url. The steps request_uri and jwt follow when the service reads the request object |
| OID4VP response | The `vp_token` of a wallet. | vp_token, then the steps of the token |
| Image | PNG, JPEG, or GIF with a QR code. | image, qr, then the steps of the text |
| PDF | A credential PDF with a QR code image. | pdf, qr, then the steps of the text |
| XML | A document with a credential at a configured path. | xml, then the steps of the text |
| JSON | A pasted document or a pasted compact token. | json, jwt, sd-jwt, or mdoc |
| QR | The text of an ordinary QR code. | the steps of the text |
| Claim 169 QR | The text of a MOSIP 169 QR code. | base45, zlib, cose_sign1, cwt |

The decoder names the carrier itself when the caller sends no hint. It
reads the file header of a PDF or an image. It reads the first character
of an XML or a JSON document. It reads the URL scheme of an OID4VP
request. It reads the alphabet of a base45 payload.

## The Claim 169 decoder

A MOSIP 169 QR code carries a CBOR Web Token inside a COSE_Sign1 message
(ADR-023 decision 3).

1. Strip a scheme prefix such as `HC1:` and decode base45 (RFC 9285).
2. Inflate the zlib stream, up to 4 mebibytes.
3. Read the COSE_Sign1 structure (RFC 9052). The tagged form and the
   untagged form both work.
4. Read the CWT claim set (RFC 8392) and take claim 169.

The decoder reads the structure. It never checks the signature. The
verifier policy service checks the signature with a trusted key. The
result carries the algorithm, the key id, the signature, and the
`Signature1` structure.

A legacy PixelPass code shares the first two steps. The decoder falls
back to the PixelPass reader of `core/pixelpass` when the CWT reader
fails.

## The QR reader and the PDF reader

The QR reader follows ISO/IEC 18004 through the gozxing library. The PDF
reader is a small extractor in `core/ingest`. It reads the image XObjects
of the file body. It supports two stream filters: FlateDecode and
DCTDecode. It supports four colour spaces: DeviceGray, DeviceRGB,
DeviceCMYK, and Indexed. It supports 1, 2, 4, and 8 bits for each
component. It also reverses the PNG predictors of the decode parameters.
The library pdfcpu would also do this. That library pulls a large tree of
vanity module paths. The restricted build network cannot mirror them.

## XML ingestion

An XML document carries a credential at a configured path
(ADR-023 decision 4). The path is a dotted list of local element names.
One example is `Envelope.Body.Credential`. An attribute is the last step
with an at sign. One example is `Body.Credential.@value`. A step written
as `prefix:name` matches only the namespace of that prefix. The step `*`
matches any name.

The text at the path is the credential, or the credential in base64. The
first release attempts no XML signature check.

## OID4VP transactions

`CreateOid4vpRequest` starts one transaction (ADR-023 decision 5). It
reads the DCQL from a presentation template of the discovery service. It
reads the DCQL from the `dcql` member of the request instead when the
caller sends one.

| Step | Behaviour |
|---|---|
| Create | The service writes a transaction with a random id, a random nonce, and a random state. It answers with the request URI and the QR payload. |
| Read | `GET /oid4vp/request/{id}` answers with the request object as a JWT, signed with ES256, `typ` `oauth-authz-req+jwt`. |
| Answer | `POST /oid4vp/response` takes the form of the wallet and calls `ReceiveDirectPost`. |
| Poll | `GetTransaction` answers pending, received, refused, or expired. |
| List | `ListTransactions` lists the transactions, newest first, with a state filter and an offset page token. A pending request past its expiry reads as expired. The verifier overview counts the open requests with it. |

The request object carries `client_id`, `response_type` `vp_token`, and
`response_mode` `direct_post`. It also carries `response_uri`, the nonce,
the state, the DCQL query, and the validity times.

`ReceiveDirectPost` then evaluates the answer. It calls `Evaluate` of the
policy service at `VCA_INGEST_POLICY_URL` with the policy set of the
template. The DCQL builder names that set `query-<template id>`, so a
date rule of the query holds end to end. The service then calls `Store`
of the results service at `VCA_INGEST_RESULTS_URL`. The transaction
keeps the result id. A failed call keeps the answer and names the
failure on the transaction. Both services sit on the compose network
(ADR-047).

A request can go through the verifier of a live stack instead. The
request names the pair in `stack`. The adapter must read the query kind
of the template: `PROTOCOL_OID4VP_DCQL` for a DCQL query, or
`PROTOCOL_OID4VP_PEX` for a PE query. A DCQL query goes to a PE stack
only when its PE form loses nothing. The service calls `CreateRequest`
of the adapter. Each `GetTransaction` of a pending request calls
`GetResult` of the adapter. An answer with credentials takes the same
evaluate and store steps. The checks of the stack stay on the
transaction.

A request lives for the default `REQUEST_TTL`, or for the pick of the
staff member up to one hour. A stack sets its own expiry.

A `request_uri` of another party is different. Three rules apply. The
host must sit on `REQUEST_URI_HOSTS`. The scheme must be https, unless a
development setting allows http. The body stops at
`MAX_REQUEST_URI_BYTES`. An empty host list refuses every request URI.
The old code fetched any URL. That was the highest risk finding of the
review.

## The camera page

The page at `/scan/` reads a QR code in the browser
(ADR-023 decision 6). The script comes from the old `scanner.js`. It
opens the camera. It draws each frame on an offscreen canvas. It gives
the pixels to the vendored jsQR reader. The camera frames never leave the
device. Only the decoded text reaches `POST /scan/ingest`.

The page works without a camera too. A file upload, a paste box, and a
link field post to the same endpoint. An image, a PDF, an XML document,
a pasted credential, and a fetched link all reach the same decoders. The
page uses the vca UI kit. It passes the structural WCAG 2.2 checks of
`ui/a11ytest`.

The camera button is a plain button with the id `scan-start`, as on the
wallet pages. It carries no `aria-controls`, so the disclosure script of
the kit does not toggle the video against the scanner. The script sends
every field of the scan form with the decoded text.

The service fetches a pasted link, never the browser. The fetch goes
through `core/fetchguard` (ADR-002 decision 7). The guard refuses a
private or a loopback address, `http` without `ALLOW_PLAIN_HTTP`, and a
host off `LINK_HOSTS` when that list names hosts. A pasted text that is one
`http` or `https` URL counts as a link too. The result names the source.

When the live adapter of the own pair lists `FEATURE_VERIFY_UPLOAD`,
each form offers "Check with the stack". The service then sends the
input to `VerifyCredential` of the adapter as well. The answer shows the
checks of the stack beside the decoders. The option stays hidden when
the adapter does not list the feature, and a posted choice then does
nothing.

The page sits in the verifier frame of `services/internal/staffshell`,
with Requests marked in the side navigation. `POST /scan/signout` is the
sign out form of the user menu.

The scanner and the QR reader sit in the shared package
`services/internal/qrscan`, which the wallet uses too. The third-party
notices of the vendored files sit in
[`services/internal/qrscan/NOTICE`](../services/internal/qrscan/NOTICE).

## The request pages

The pages under `/scan/requests/` follow board Verifier-Request (spec
VE4). The new request form lists the saved queries of the discovery
service. "Answer through" lists the VCA verifier when the query has a
DCQL form. It also lists each live stack whose adapter reads the query.
A change of the query swaps that list with htmx. The form also picks
the delivery and the expiry.

| Path | Page |
|---|---|
| `GET /scan/requests/` | The requests, newest first, with the verifier, the state, and the result link. |
| `GET /scan/requests/new` | The new request form. `?template=<id>` picks a query. |
| `POST /scan/requests/new/answerers` | The verifier choice of one query, for htmx. |
| `POST /scan/requests/` | Send the request and open its page. |
| `GET /scan/requests/{id}` | One request. `?as=qr`, `link`, or `document` picks the delivery. |
| `GET /scan/requests/{id}/state` | The state block, for htmx. |
| `GET /scan/requests/{id}/document.pdf` | The request as a PDF document of `core/pdf`, with the QR code and the link. |

The state block shows Waiting, Received, and Verified. While the request
waits, htmx asks for the block every 2 seconds. A refresh link does the
same without JavaScript. When the request no longer waits, the poll
stops and the delivery goes away. The verdict card shows the verdict,
the checks, the checks of the stack, and the claims. It ends with "Saved
as result" and a link to the result page of `verifier-results`.

## Storage

The state directory holds one JSON document for each transaction at
`transactions/<id>`. A prune job removes a transaction after
`TRANSACTION_TTL`. An empty `STATE_DIR` keeps the transactions in the
process, so a restart loses them.
