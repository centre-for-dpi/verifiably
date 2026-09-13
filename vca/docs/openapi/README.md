# OpenAPI 3.1 document

This directory receives the generated OpenAPI 3.1 document `vca.openapi.yaml`
(ADR-003 decision 3). The generator is `protoc-gen-connect-openapi`.

The plugin depends on modules that the Buf Schema Registry hosts under
`buf.build/gen/go/`. Those modules have no GitHub source, so a machine on the
restricted network cannot build the plugin. For this reason `buf.gen.yaml`
does not list the plugin, and the repository does not commit the document.

## How to generate the document

Run these commands on a machine with normal network access:

```sh
go install github.com/sudorandom/protoc-gen-connect-openapi@v0.18.0
cd vca
./hack/openapi.sh
```

The script writes `docs/openapi/vca.openapi.yaml`. Set `OPENAPI_OUT` to write
to a different directory. When the plugin is not on `PATH`, the script prints a
skip message and exits with status 0.

## What the document contains

- One path per RPC of every service in `proto/vca/*/v1/`.
- The request and response schemas from the proto messages.
- The `description` option of each RPC as the operation summary.
- Server streaming RPCs, marked with the `with-streaming` plugin option.

The standard HTTP endpoints (issuer metadata, JWKS, OID4VP `direct_post`,
status list GET) stay outside the proto contract (ADR-003 decision 7). Add
them in `hack/openapi-base.yaml`. The script merges that file when it exists.
