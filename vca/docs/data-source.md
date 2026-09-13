# Data source

This page describes the `data-source` service (ADR-015). The service
README at [`services/data-source/README.md`](../services/data-source/README.md)
says how to run it. This page says how it works.

## Data model

A source is one connector that issuer staff read rows from
(ADR-015 decision 1). The kind is a oneof with three members.

| Field | Meaning |
|---|---|
| `id` | The source id. The service assigns it. |
| `display_name` | The name shown to people. |
| `tenant_id` | The tenant that owns the source. |
| `csv`, `http`, or `sql` | The kind. The caller sets exactly one. |
| `access` | The role rules of the source. |
| `created_at`, `updated_at` | The times of the first and the last write. |

### The csv kind

A `CsvSource` names an uploaded file, a delimiter, a header flag, and an
encoding. The `file_ref` is a plain file name in the CSV directory, or a
`data:text/csv;base64,` URL that carries the bytes inline. The reader
rejects a path with a directory part, so a staff upload cannot read
another file. The encoding is UTF-8. The reader rejects bytes that are
not valid UTF-8, and it rejects any other encoding name.

### The http kind

An `HttpSource` names a URL and a method. It also names headers without
secrets, a credential reference, a JSON pointer to the array of rows,
and a timeout. The method is GET or POST. The credential is one of
three. It is a bearer token reference. It is a user name with a password
reference. It is an mTLS certificate and key pair of references.

### The sql kind

A `SqlSource` names a driver, a DSN reference, a read only query, and a
timeout. The service uses `database/sql` with an injected driver. The
binary registers no driver, so an operator builds an image with the
driver the deployment needs. The query check accepts one `SELECT` or one
`WITH` statement, with at most one trailing semicolon. It rejects a
second statement.

## Secrets

A source record holds a `SecretRef`, never a secret value
(ADR-015 decision 2). A reference has a store and a name.

| Store | Name | Read from |
|---|---|---|
| `env` | An upper case environment variable name. | The process environment. |
| `file` | A plain file name. | `VCA_DATASOURCE_SECRETS_DIR`. |
| `kms` | A key name. | Not supported yet. The service reports a failed precondition. |

The service resolves a reference only when it opens the source. The
value passes to the source reader and stops there. No response, no
export, and no log carries a value. `Get` and `List` return the
reference, so the portal can show which secret a source needs.

## Role rules

Each source carries three role lists (ADR-015 decision 3).

| Rule | Controls |
|---|---|
| `view_fields` | `Get`, `PreviewFields`, `GetFieldMap`, and `SetFieldMap`. |
| `preview_rows` | `PreviewRows`. |
| `issue` | `RunBulk`. |

The caller sends a session JWT from `issuer-auth`. The service verifies
it against the JWKS of `issuer-auth` and reads the `roles` claim. In
header mode a gateway verified the session and sends `X-VCA-Roles`.

The role `issuer-admin` passes every rule. Another role passes a rule
only when the rule names it. An empty rule admits admins only. A caller
that cannot pass `view_fields` gets `VCA-302` on `Get`, so the rule is
not a way to learn that a source exists. `Create`, `Update`, and
`Delete` need `issuer-admin` or `issuer-operator`. A caller with a
tenant sees the sources of that tenant only.

## Preview

`PreviewFields` reads at most 200 rows and infers one type per field
(ADR-015 decision 4). The types are `integer`, `number`, `boolean`,
`date`, and `string`. A field with no value at all is a string. The
service masks the example value of each field.

`PreviewRows` returns at most 20 rows. The default is 10. The service
masks every value: the first and the last character stay, and the middle
becomes asterisks. A value of two characters or fewer loses every
character. Staff can then check the shape of the data. They read no
personal data.

## Field maps

A `FieldMap` fills the properties of one schema from the fields of one
source (ADR-015 decision 5). One rule fills one property. The transforms
are pure functions in [`core/mapping`](../core/mapping).

| Transform | Source fields | Parameters |
|---|---|---|
| unspecified | One. | None. It copies the value. |
| `TRIM` | One. | None. |
| `DATE_FORMAT` | One. | `input_layout`, `output_layout`. Go reference layouts. |
| `CONSTANT` | None. | `value`. |
| `CONCAT` | One or more. | `separator`. |
| `UPPER` | One. | None. |
| `LOWER` | One. | None. |

`SetFieldMap` rejects a rule with an empty property or a duplicate
property. It rejects a missing source field or too many source fields.
It rejects an unknown transform or a missing parameter. It returns the
schema properties that no rule fills. The portal then warns before a
bulk run.

## The SSRF guard

Every HTTP source read passes the guard first (ADR-015 decision 6). The
guard closes the backlog item of the legacy monolith. The checks run in
this order.

1. The URL must parse and must carry no user name or password.
2. The scheme must be `https`. `VCA_DATASOURCE_ALLOW_HTTP` permits `http` for a local test.
3. The host must be on `VCA_DATASOURCE_ALLOW_HOSTS`. An empty allowlist permits no host. An entry with a leading dot matches the domain and its sub domains.
4. The host resolves to addresses. Every address must be public. One private, loopback, link local, multicast, or unspecified address refuses the whole host.
5. The client dials one of the checked addresses only, so a second DNS answer cannot change the target.
6. The client follows no redirect. A `3xx` status is an error.
7. The response must be JSON. The reader stops at `VCA_DATASOURCE_HTTP_MAX_BYTES` and at `VCA_DATASOURCE_HTTP_TIMEOUT`.

The private, loopback, link local, and multicast blocks come from the
`net` package. The guard refuses these extra blocks as well:
`0.0.0.0/8`, `100.64.0.0/10`, `192.0.0.0/24`, `192.0.2.0/24`,
`198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `240.0.0.0/4`,
`255.255.255.255/32`, `64:ff9b::/96`, and `2001:db8::/32`.

## Errors

The service returns the shared error codes of
[`docs/errors.md`](errors.md).

| Code | Connect code | When |
|---|---|---|
| `VCA-302` | permission denied | A role rule refused the call, or the SSRF guard refused the URL. |
| `VCA-303` | resource exhausted | The CSV file, the response, or the row count passed a limit. |
| `VCA-401` | unavailable | The source did not answer, or the driver is missing. |

## Bulk runs

`RunBulk` checks the `issue` rule and then reports unimplemented. Bulk
issuance is a job of the issuance service (ADR-015 decision 7). The
legacy handler at `verifiably-go/internal/handlers/bulk.go` streamed
progress over server sent events. The replacement is the server
streaming RPC in this proto.
