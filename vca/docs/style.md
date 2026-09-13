# Writing style

All reader-facing text follows ASD-STE100 Issue 9, Simplified Technical
English ([asd-ste100.org](https://www.asd-ste100.org/)). This applies to
README files, service documents, CLI help, portal text, proto comments,
OpenAPI descriptions, and error messages (ADR-028).

## Rules

1. Use approved words. The list in [`hack/ste-words.txt`](../hack/ste-words.txt) names the words to avoid and their replacements.
2. Write one instruction per sentence.
3. Use the active voice. Name the actor: "The issuer signs the credential."
4. Write sentences of at most 20 words.
5. Use the present tense.
6. Do not use idiom, slang, or humour.
7. Do not use em dashes or en dashes. Use a comma, a colon, or a full stop.
8. Use the same word for the same thing. Take the word from the [glossary](glossary.md).
9. Use the imperative for instructions: "Run the command."
10. Start a paragraph with the most important sentence.
11. Use a list for more than two steps or items.
12. Keep a paragraph to six sentences or fewer.
13. Write numbers as digits, except at the start of a sentence.
14. Put a code name, path, or command in backticks.

## Words to avoid

The linter reports each word in this table. Use the replacement.

| Do not write | Write |
|---|---|
| `utilize`, `leverage` | use |
| `in order to` | to |
| `prior to` | before |
| `commence`, `initiate` | start |
| `terminate` | stop |
| `facilitate`, `assist` | help |
| `ensure` | make sure |
| `should`, `shall` | must |
| `may`, `might` | can |
| `e.g.` | for example |
| `i.e.` | that is |
| `via` | through |

## Before and after

These examples come from the legacy [`README.md`](../../README.md).

```text
Before: "One interface (`backend.Adapter`) drives every screen; swap implementations to point at a different vendor without touching the UI."
After:  "One interface drives every screen. Change the adapter to use a different vendor. The UI does not change."
```

```text
Before: "Everything below refers to that subtree, run the commands from there."
After:  "All commands below apply to that folder. Run them from there."
```

```text
Before: "Go is not required on the host, the test suite runs inside a Docker container:"
After:  "You do not need Go on the host. The tests run in a Docker container."
```

```text
Before: "If `dig` returns nothing, propagation hasn't finished yet, Caddy's Let's Encrypt cert request in step 6 will fail with a "no DNS resolution" error until it does."
After:  "If `dig` returns nothing, DNS has not updated yet. Wait, then try again. Step 6 fails with a DNS error until then."
```

```text
Before: "Expect 8 to 15 minutes. Subsequent runs are idempotent, each bootstrap step checks whether the resource already exists and skips it."
After:  "Wait 8 to 15 minutes. You can run the command again. Each step skips a resource that exists."
```

The "before" lines had em dashes in the source. This page shows them as
commas, because the repository holds no dash characters.

## How to check a document

Run the linter on the files you changed:

```sh
hack/ste-lint.sh docs/*.md README.md proto/vca/*/v1/*.proto
```

The linter prints `file:line: rule: detail` for each problem and exits
with status 1. Fix each line, then run the linter again. Use
`--fix-dashes` to replace all dashes with commas in place. Read the
result, because a comma is not always the best choice.

The linter cannot check every rule. A reviewer checks that each
sentence gives one instruction and that the text uses glossary terms.

The linter does not run on `docs/adr.md`. A decision record is a
historical record of a choice. Do not rewrite it after review.
