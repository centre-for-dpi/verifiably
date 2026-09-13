# Service document template

Copy this file to `services/<name>/README.md` and to `docs/<name>/README.md`
for each new service. Keep the four section titles as they are (ADR-028).
Write in the style of [style.md](style.md). Use the terms in
[glossary.md](glossary.md). Run `hack/ste-lint.sh` on the result.

Replace each `<...>` placeholder. Delete this introduction.

---

# `<name>`

`<One sentence: what this service adds and for which role.>`

## What it does

- `<The one function it adds, in one sentence.>`
- `<The DPGs it works with: walt.id, Inji, CREDEBL.>`
- `<The data it owns, as a list of tables or files.>`
- `<The standards it follows, as links.>`

It does not `<name one thing that is out of scope>`.

## How to run

Planned (ADR-007, ADR-008):

```sh
vca setup --role <role> --dpg <dpg>
vca deploy --role <role> --dpg <dpg>
```

Now:

```sh
cd services/<name>
go run . --config <path>
```

Configuration comes from environment variables. The table lists each one.

| Variable | Meaning | Default |
|---|---|---|
| `VCA_<NAME>_LISTEN` | The address the service listens on. | `:8080` |
| `<VARIABLE>` | `<Meaning.>` | `<Default>` |

The container image is `ghcr.io/centre-for-dpi/vca-<name>`. It listens on
one port and runs as a non-root user with a read-only file system.

## How to check it works

1. Open `http://localhost:<port>/healthz`. The response is `200 OK`.
2. Open `http://localhost:<port>/readyz`. The response is `200 OK`.
3. Run `<one command that exercises the main function>`.
4. Look for `<the expected output>`.

If a step fails, see [errors.md](errors.md) for the message and the next step.

## Reference

- API: [`proto/vca/<name>/v1/<name>.proto`](../../proto/vca/<name>/v1/<name>.proto)
- OpenAPI: `gen/openapi/<name>.yaml`
- Decision record: [ADR-`<number>`](adr.md#adr-`<number>`)
- Error codes: `<list of codes from errors.md that this service returns>`
- Standards: `<links>`
