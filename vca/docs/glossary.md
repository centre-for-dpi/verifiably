# Glossary

This page is the project dictionary. Use these words with these meanings
in all documents, portals, error messages, and code comments (ADR-028).
Each entry has one sentence and one link to the standard that defines it.

| Term | Meaning | Standard |
|---|---|---|
| Issuer | The organization that creates a credential for a holder and signs it. | [VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/) |
| Holder | The person or organization that keeps credentials in a wallet and shows them to a verifier. | [VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/) |
| Verifier | The party that receives a presentation and checks it against its policy. | [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) |
| Credential | A set of claims about a subject that an issuer signs. | [VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/) |
| Presentation | The data that a holder sends to a verifier, made from one or more credentials. | [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) |
| Schema | A document that defines the claims that one credential type contains. | [VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/) |
| Status list | A signed list that tells a verifier if a credential is valid, suspended, or revoked. | [Bitstring Status List](https://www.w3.org/TR/vc-bitstring-status-list/), [Token Status List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/) |
| Trust list | A list of the issuers that a verifier accepts, with their keys and credential types. | [ETSI TS 119 602](https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf), [Decentralized Directory Protocol](https://github.com/LF-Decentralized-Trust-labs/decentralized-directory-protocol) |
| Adapter | A small VCA service that adds one function to a DPG and never signs credentials. | [ADR-001](adr.md#adr-001-rebrand-and-redefined-purpose) |
| DPG | A digital public good, here walt.id, Inji, or CREDEBL, that issues and signs credentials. | [ADR-001](adr.md#adr-001-rebrand-and-redefined-purpose) |
| Service | One VCA process with one proto API, one container image, and one document. | [ADR-002](adr.md#adr-002-decompose-the-monolith-into-per-feature-microservices) |
| Wallet | The software that a holder uses to receive, store, and present credentials. | [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) |
| Policy | The rules that a verifier applies to a presentation before it accepts the result. | [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) |
| Disclosure | One claim that a holder chooses to show from an SD-JWT credential. | [RFC 9901 SD-JWT](https://www.rfc-editor.org/rfc/rfc9901.html) |
| Key binding | The proof that the holder who presents a credential also holds its private key. | [RFC 9901 SD-JWT](https://www.rfc-editor.org/rfc/rfc9901.html) |
| DID | A decentralized identifier that points to the public keys of an issuer or a holder. | [DID 1.0](https://www.w3.org/TR/did-1.0/) |

## Rules for new terms

1. Add a new term only when no term in this table has the same meaning.
2. Write the meaning as one sentence with at most 20 words.
3. Link the standard that defines the term.
4. Use the same term in the UI, the API, and the error catalogue.
