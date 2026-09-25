# Sources of the vendored schemas

The package `core/pex` validates a presentation definition against these files. They are copies of the upstream files, byte for byte.

| File | Upstream | Commit | SHA-256 | Licence |
|---|---|---|---|---|
| `presentation-definition.json` | [decentralized-identity/presentation-exchange](https://github.com/decentralized-identity/presentation-exchange), `schemas/v2.0.0/presentation-definition.json` | `7cbe949c95fe1e19413b24c9b49dc34f76f5d76a` | `58cbbfdf0ed87f99d18ec92f9fbe5671bab783c39ed873b4acf3b1d500b5a66f` | Apache-2.0 |
| `claim-format-designations.json` | [decentralized-identity/claim-format-registry](https://github.com/decentralized-identity/claim-format-registry), `schemas/presentation-definition-claim-format-designations.json` | `4a15817a7717efdda29912a1eef6e59135d8d02a` | `91eb9058670158488da42771f3836760020c2d24a033354c86e92a037d9be062` | Apache-2.0 |

The copies date from 2026-09-25.

The file `oid4vp-formats.json` is VCA work, not an upstream copy. The upstream registry does not list the credential formats of OpenID for Verifiable Presentations: `jwt_vc_json`, `jwt_vp_json`, `vc+sd-jwt`, and `dc+sd-jwt`. Wallets and verifiers use these names in a presentation definition. The validator adds the patterns of this file to the patterns of the registry file.

To update a copy, fetch the file at a new commit, replace the copy, and change the commit and the hash in this table. The test `TestVendoredSchemasMatchSource` checks the hashes.
