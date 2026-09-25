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

The request object carries `client_id`, `response_type` `vp_token`, and
`response_mode` `direct_post`. It also carries `response_uri`, the nonce,
the state, the DCQL query, and the validity times.

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

The page works without a camera too. A file upload and a paste box post
to the same endpoint. An image, a PDF, an XML document, and a pasted
credential all reach the same decoders. The page uses the vca UI kit. It
passes the structural WCAG 2.2 checks of `ui/a11ytest`.

The scanner and the QR reader sit in the shared package
`services/internal/qrscan`, which the wallet uses too. The third-party
notices of the vendored files sit in
[`services/internal/qrscan/NOTICE`](../services/internal/qrscan/NOTICE).

## Storage

The state directory holds one JSON document for each transaction at
`transactions/<id>`. A prune job removes a transaction after
`TRANSACTION_TTL`. An empty `STATE_DIR` keeps the transactions in the
process, so a restart loses them.
