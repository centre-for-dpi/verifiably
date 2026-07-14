# Per-DPG implementation guides

Each guide documents one DPG (Digital Public Good) end-to-end as it runs in verifiably — the role
verifiably plays, the flow, every container (image + port), env vars, Caddy blocks, runtime configs,
databases, APIs, and the live-diagnosed gotchas. Guides are **self-contained**: you can implement a
DPG from its guide without hopping between docs.

The DPG abstraction (`backend.Adapter` + the Registry fan-out) is described in
[../architecture.md](../architecture.md); the compatibility matrix in
[../dpg-matrix.md](../dpg-matrix.md); deployment mechanics in [../deploy.md](../deploy.md); writing
a new adapter in [../integration.md](../integration.md).

## Guides

| Guide | `backends.json` type | Adapter | Role verifiably plays | Version |
|---|---|---|---|---|
| [walt.id Community Stack](./walt-id.md) | `walt_community` | `waltid` | orchestrator + proxy + schema registry (full built-in wallet) | v0.18.2 |
| [Inji Certify · Auth-Code](./inji-certify-authcode.md) | `inji_certify_authcode` | `injicertify` | issuer control-plane + **owns the in-app wallet** + DID/metadata proxy | Certify v0.14.0 · eSignet 1.5.1 |
| [Inji Certify · Pre-Auth](./inji-certify-preauth.md) | `inji_certify_preauth` | `injicertify` | server-side OID4VCI client + **PDF renderer** (paper QR) | Certify v0.14.0 |
| [Inji Verify](./inji-verify.md) | `inji_verify` | `injiverify` | OID4VP request builder + result adjudicator (INJIVER-1131 guard) | v0.16.0 |
| [CREDEBL](./credebl.md) | `credebl` | `credebl` | proxy + auth broker + schema store (~23 services) | v2.x |
| [Registries & data sources](./registries.md) | — (data source) | bulk engine | **reads** Sunbird RC / federated registries → `vc_subject` / `identity_registry` | — |

## The two Inji Certify instances

Inji Certify runs as **two independent stacks** with separate containers, databases, DIDs, and
public hosts — never share config between them:

| | Auth-Code | Pre-Auth |
|---|---|---|
| Public host | `inji-certify-authcode.<domain>` | `inji-certify-preauth.<domain>` |
| DB | `certify-postgres` (`inji_certify`) | `certify-preauth-postgres` (`inji_certify`) |
| Issuer DID | `did:web:inji-certify-authcode.<domain>` | `did:web:inji-certify-preauth.<domain>` |
| Token source | eSignet (holder authenticates) | Certify's own pre-auth token |
| Output | wallet credential | printable PDF (QR) |
