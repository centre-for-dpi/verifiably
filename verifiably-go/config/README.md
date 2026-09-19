# Configuration files

This directory holds the committed configuration of the legacy stack.
JSON has no comment syntax, so the notes live here.

## federation.json

The file lists the members of the federation and how the hub reaches each one.

Each member can carry a `verifierConfig.apiKey`.
That key is a bearer token for the member verify API, so it is a secret.
Every `apiKey` in the committed file now holds the value `REPLACE_ME`
(ADR-029 decision 6).

Set a real key in one of these two ways:

1. Copy the file, set the keys in the copy, and mount the copy at
   `/app/config/federation.json`.
2. Set the key through the hub admin pages after the stack starts.

The keys that this file held before are in the git history of a public
repository.
Treat each of them as compromised.
Rotate the key on every member deployment that used one.
The history purge is a release step, and `vca/docs/release-checklist.md`
holds the command lines.
