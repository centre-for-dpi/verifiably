# issuance

## What it does

This service issues credentials. It serves `vca.issuance.v1` over
Connect. It runs ADR-016.

The service does not sign a credential. It asks a DPG adapter to make
one (ADR-016 decision 1). The configuration names the adapter. The
service reads what the adapter supports, and it refuses a request the
adapter cannot serve (ADR-016 decision 6).

It offers these RPCs:

- `Issue`: one credential for one subject.
- `IssueBatch`: many credentials. The answer streams the progress.
- `GetBatch`: one page of the rows of a batch.
- `GetOffer`: the state of one offer.
- `Deferred`: the state of one deferred issuance at the adapter.

It supports these channels (ADR-016 decision 5):

- `oid4vci`: the adapter builds an offer. A wallet claims it.
- `pdf`: the service renders an A4 page with a QR code. The citizen
  downloads the page.
- `email` and `sms`: the service sends a message with a link. A
  deployment needs a gateway.
- `link`: the service returns a download link only.

The document channel uses `core/pdf` and `core/qr` (ADR-016 decisions 3
and 4). The QR code holds the offer URI, or the credential in the
PixelPass form of `core/pixelpass`. The service writes no external
dependency into the page.

The service records every issuance in the issued credentials service
(ADR-017 decision 1). A deployment without that service keeps the record
in the log.

## How to run

| Variable | Meaning |
| --- | --- |
| `VCA_ISSUANCE_LISTEN` | The address to bind. The default is `:8080`. |
| `VCA_ISSUANCE_PUBLIC_URL` | The address a citizen reaches this service on. |
| `VCA_ISSUANCE_ADAPTER_URL` | The base URL of the DPG adapter. Set it. |
| `VCA_ISSUANCE_ADAPTER_NAME` | The name of the DPG in the issued record. |
| `VCA_ISSUANCE_SCHEMA_URL` | The base URL of the schema registry. Empty skips the claim check. |
| `VCA_ISSUANCE_STATUS_URL` | The base URL of the status service. Empty makes every credential permanent. |
| `VCA_ISSUANCE_ISSUED_URL` | The base URL of the issued credentials service. |
| `VCA_ISSUANCE_DELIVERY_SENDER` | The sender of the offer channels. The values are `log` and `file`. |
| `VCA_ISSUANCE_EMAIL_SENDER` | The sender of the email channel. The values are `stub`, `log`, and `file`. |
| `VCA_ISSUANCE_SMS_SENDER` | The sender of the SMS channel. The values are `stub`, `log`, and `file`. |
| `VCA_ISSUANCE_DELIVERY_DIR` | The directory of the file sender. |
| `VCA_ISSUANCE_DOCUMENT_TITLE` | The heading of a rendered page. |
| `VCA_ISSUANCE_DOCUMENT_ISSUER` | The line above the heading. |
| `VCA_ISSUANCE_DOCUMENT_FOOTER` | The line at the foot of the page. |
| `VCA_ISSUANCE_STORE_FILE` | The directory that keeps the offers. Empty uses memory. |
| `VCA_ISSUANCE_OFFER_TTL` | The life of an offer. The default is `24h`. |
| `VCA_ISSUANCE_TIMEOUT` | The bound of one call. The default is `30s`. |
| `VCA_ISSUANCE_BATCH_WORKERS` | The number of rows the service issues at once. |
| `VCA_ISSUANCE_PAGE_SIZE_MAX` | The cap of one page. The default is `50`. |
| `VCA_ISSUANCE_AUDIT_DIR` | The directory of the audit store. Empty uses memory. |
| `VCA_ISSUANCE_ADMIN_JWKS_URL` | The key set of the admin service. An admin session it signed opens the audit store. |
| `VCA_ISSUANCE_ADMIN_TOKEN` | The admin service token. It opens the audit store too. |

Run the binary:

```
VCA_ISSUANCE_ADAPTER_URL=http://dpg-adapter-waltid:8080 \
VCA_ISSUANCE_SCHEMA_URL=http://schema:8080 \
VCA_ISSUANCE_PUBLIC_URL=https://issuance.example.org \
go run ./services/issuance
```

Build the image from the module root:

```
docker build -f services/issuance/Dockerfile -t issuance .
```

## How to check it works

Ask for the health of the service:

```
curl -s localhost:8080/readyz
```

Issue one credential over the document channel:

```
curl -s -X POST localhost:8080/vca.issuance.v1.IssuanceService/Issue \
  -H 'Content-Type: application/json' \
  -d '{"schemaId":"farmer","subjectData":"{\"fullName\":\"Ada\"}",
       "delivery":{"channel":"CHANNEL_PDF"}}'
```

The answer holds a link. Open the link to read the page.

Run the tests:

```
go test ./services/issuance/...
```

## Reference

- Service document: `docs/issuance.md`
- Contract: `proto/vca/issuance/v1/issuance.proto`
- Decisions: ADR-016 decisions 1 to 6, ADR-002 decisions 2 and 5,
  ADR-017 decision 1
