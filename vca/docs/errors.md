# Error catalogue

This page lists every error message that a VCA service shows to a user
(ADR-028, decision 5). Each entry has a code, a message in Simplified
Technical English, and the next step for the user.

## Format

| Field | Rule |
|---|---|
| Code | `VCA-` plus three digits. The first digit is the group. A code never changes meaning. |
| Message | One or two sentences, at most 20 words each, in the style of [style.md](style.md). |
| Next step | One instruction that tells the user what to do. |
| Connect code | The Connect error code that the API returns with the message. |

Groups:

- `VCA-1xx`: the credential itself.
- `VCA-2xx`: trust and signatures.
- `VCA-3xx`: the request or the session.
- `VCA-4xx`: the service or a source it depends on.

Rules:

1. Add an entry here before you return a new message from code.
2. Return the code and the message together. Do not change the message in code.
3. Do not put a secret, a key, or a private claim in a message.
4. Run `hack/ste-lint.sh docs/errors.md` after each change.

## Entries

| Code | Message | Next step | Connect code |
|---|---|---|---|
| VCA-101 | This credential has expired. | Ask the issuer for a new credential. | `failed_precondition` |
| VCA-102 | The issuer has revoked this credential. | Contact the issuer to find the reason. | `failed_precondition` |
| VCA-103 | The credential does not match the schema `{schema}`. | Ask the issuer to issue the credential again with the correct schema. | `invalid_argument` |
| VCA-104 | The format `{format}` is not supported. | Present a credential in one of these formats: `{formats}`. | `invalid_argument` |
| VCA-201 | The issuer `{issuer}` is not on the trust list. | Ask the verifier to add the issuer to the trust list. | `permission_denied` |
| VCA-202 | The signature on this credential is not valid. | Ask the issuer for a new credential. | `unauthenticated` |
| VCA-301 | Your session has expired. | Sign in again. | `unauthenticated` |
| VCA-302 | You do not have permission to do this. | Ask an administrator for the `{role}` role. | `permission_denied` |
| VCA-303 | The request is too large. The limit is `{limit}`. | Send a smaller request. | `resource_exhausted` |
| VCA-401 | The service cannot reach `{source}`. | Wait one minute, then try again. If the problem stays, contact the operator. | `unavailable` |

Placeholders in braces come from the request. A service fills them in
before it returns the message. A placeholder never contains a secret.

## How a service uses an entry

1. The service returns a Connect error with the Connect code from the table.
2. The error message is the text from the table with placeholders filled in.
3. The error detail carries the VCA code in the field `code`.
4. The portal shows the message and the next step to the user.
5. The log records the code, not the message.
