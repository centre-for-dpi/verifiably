# `verifier-ingest`

The verifier ingestion service takes a presentation in any supported carrier and turns it into one normalised message.

## What it does

- It decodes an OID4VP request, an OID4VP response, an image, a PDF, an XML document, pasted JSON, an ordinary QR code, and a MOSIP Claim 169 QR code.
- It decodes with the pure functions of `core/ingest`, which carry fuzz tests.
- It creates an OID4VP transaction from a presentation template, serves a signed request object, and takes the answer of the wallet at the direct post endpoint.
- It reads a `request_uri` of another party only from an allowed host, and only up to a size limit.
- It serves a camera page. The page reads the QR code on the device and posts only the decoded text.
- It works with every DPG, because every carrier ends in the same message.
- It owns one directory: the state directory with the OID4VP transactions.
- It follows these standards: [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html), [ISO/IEC 18004](https://www.iso.org/standard/83389.html), [RFC 8392](https://www.rfc-editor.org/rfc/rfc8392.html), [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html), [RFC 9285](https://www.rfc-editor.org/rfc/rfc9285.html), and the [MOSIP 169 QR code specification](https://docs.mosip.io/1.2.0/readme/standards-and-specifications/mosip-standards/169-qr-code-specification).

It does not check a signature or a status list. The verifier policy service does that.

## How to run

Planned (ADR-007, ADR-008):

```sh
vca setup --role verifier --dpg waltid
vca deploy --role verifier --dpg waltid
```

Now:

```sh
cd services/verifier-ingest
VCA_INGEST_DISCOVERY_URL=http://localhost:8090 go run .
```

Configuration comes from environment variables. The table lists each one.

| Variable | Meaning | Default |
|---|---|---|
| `VCA_INGEST_LISTEN` | The address the service listens on. | `:8091` |
| `VCA_INGEST_BASE_URL` | The public root URL. The request URI and the response URI carry it. | `http://localhost:8091` |
| `VCA_INGEST_STATE_DIR` | The directory of the transactions. | empty: in memory |
| `VCA_INGEST_DISCOVERY_URL` | The base URL of the discovery service. | empty: a template cannot be read |
| `VCA_INGEST_DISCOVERY_TIMEOUT` | The time limit of one discovery call. | `10s` |
| `VCA_INGEST_CLIENT_ID` | The OID4VP client identifier of the verifier. | the base URL |
| `VCA_INGEST_SIGNING_KEY_FILE` | A PKCS 8 PEM file with the request object key. | empty: one key for this process |
| `VCA_INGEST_REQUEST_TTL` | How long an OID4VP request works. | `5m` |
| `VCA_INGEST_TRANSACTION_TTL` | How long the service keeps a transaction. | `1h` |
| `VCA_INGEST_MAX_INPUT_BYTES` | The size limit of one ingestion. | `16777216` |
| `VCA_INGEST_REQUEST_URI_HOSTS` | The hosts a request object may come from, comma separated. An entry that starts with a dot matches the domain and every name below it. | empty: no request URI is read |
| `VCA_INGEST_MAX_REQUEST_URI_BYTES` | The size limit of a fetched request object. | `131072` |
| `VCA_INGEST_REQUEST_URI_TIMEOUT` | The time limit of one request object fetch. | `10s` |
| `VCA_INGEST_ALLOW_PLAIN_HTTP` | Let the request URI fetcher use `http`. Development only. | `false` |
| `VCA_INGEST_XML_PATH` | The default dotted path of a credential in an XML document. | empty |
| `VCA_INGEST_XML_ENCODING` | The default encoding of the XML text: `text` or `base64`. | `text` |
| `VCA_INGEST_REDIRECT_URI` | The URI the wallet opens after a direct post. | empty |
| `VCA_INGEST_SCANNER_PREFIX` | The URL prefix of the camera page. | `/scan` |
| `VCA_INGEST_AUTH_JWKS_URL` | The JWKS URL of `verifier-auth`. The camera page accept only a session it signed. | empty: the camera page accept no session |
| `VCA_INGEST_AUTH_JWKS_FILE` | A JWKS file that replaces the URL, for a test. | empty |
| `VCA_INGEST_AUTH_JWKS_TTL` | How long a fetched key set stays fresh. | `10m` |
| `VCA_INGEST_AUTH_ISSUER` | The `iss` claim every session must carry. | empty: any issuer of the key set |
| `VCA_INGEST_LOGIN_URL` | The sign in chooser a page request without a session goes to, with `return_to`. | empty: answer 401 |
| `VCA_PEERS` | The candidate pairs of the deployment. The stack switcher of the verifier shell comes from them. | empty: no stack switcher |

The container image is `ghcr.io/centre-for-dpi/vca-verifier-ingest`. It listens on
one port and runs as a non-root user with a read-only file system.
Mount a volume at `/data` to keep the transactions.

## How to check it works

1. Open `http://localhost:8091/healthz`. The response is `200 OK`.
2. Open `http://localhost:8091/readyz`. The response is `200 OK`.
3. Decode a pasted credential:

```sh
curl -sS -X POST http://localhost:8091/vca.ingest.v1.IngestService/Ingest \
  -H 'Content-Type: application/json' \
  -d '{"payload":"'"$(printf 'hello' | base64)"'"}'
```

4. Create an OID4VP request:

```sh
curl -sS -X POST http://localhost:8091/vca.ingest.v1.IngestService/CreateOid4vpRequest \
  -H 'Content-Type: application/json' \
  -d '{"dcql":"{\"credentials\":[{\"id\":\"pid\",\"format\":\"dc+sd-jwt\",\"meta\":{\"vct_values\":[\"v\"]}}]}"}'
```

5. Open the `request_uri` of the answer. The body is a signed request object.
6. Open `http://localhost:8091/scan/`. The page offers the camera, a file
   upload, and a paste box.

## Reference

| Item | Value |
|---|---|
| Service | `vca.ingest.v1.IngestService` |
| Proto | [`proto/vca/ingest/v1/ingest.proto`](../../proto/vca/ingest/v1/ingest.proto) |
| Service document | [`docs/verifier-ingest.md`](../../docs/verifier-ingest.md) |
| ADR | ADR-023 decisions 1 to 6 |
| Wallet endpoints | `GET /oid4vp/request/{id}`, `POST /oid4vp/response` |
| Pages | `GET /scan/`, `POST /scan/ingest` |
| Health | `GET /healthz`, `GET /readyz` |
| Third-party notices | [`internal/scanner/NOTICE`](internal/scanner/NOTICE) |
