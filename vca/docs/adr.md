# Architecture decisions

The ADR set is a read-only document at the repository root: [ADR.md](../../ADR.md).

## New records

The root file holds ADR-001 to ADR-031. It does not change. A new
decision, or a change to an old decision, is a new record in the
[adr](adr) folder. Each record has one file and uses the format of the
root file. A record that replaces an old decision names that decision
in a "Supersedes" line. The [ADR status](adr-status.md) page tracks
each decision of each record.

- [ADR-032: Theme and brand from one declarative file](adr/ADR-032-theme-file.md)
- [ADR-033: Landing service, role picker, and role intro pages](adr/ADR-033-landing-role-picker.md)
- [ADR-034: Backend adaptivity through a peer topology and feature lists](adr/ADR-034-backend-adaptivity.md)
- [ADR-035: Provider agnostic sign in with one realm per role](adr/ADR-035-sign-in-realms.md)
- [ADR-036: Verifier staff sign in](adr/ADR-036-verifier-staff-sign-in.md)
- [ADR-037: Tenants mapped to DPG tenancy](adr/ADR-037-tenant-mapping.md)
- [ADR-038: API keys for VCA and for stacks](adr/ADR-038-api-keys.md)
- [ADR-039: Federated audit log](adr/ADR-039-federated-audit.md)
- [ADR-040: Notifications page before notification delivery](adr/ADR-040-notifications-page.md)
- [ADR-041: Verifier trust cache and offline verification window](adr/ADR-041-verifier-trust-cache.md)
- [ADR-042: DCQL builder and DIF Presentation Exchange queries](adr/ADR-042-dcql-and-pe.md)
- [ADR-043: Issuance channels and bulk sources](adr/ADR-043-issuance-channels.md)
- [ADR-044: Placement of the role pages](adr/ADR-044-role-page-placement.md)
- [ADR-045: Full DPG surfacing](adr/ADR-045-full-dpg-surfacing.md)
- [ADR-046: Issuer identity through the DPG](adr/ADR-046-issuer-identity.md)
- [ADR-047: The public RPC surface of a pair](adr/ADR-047-public-rpc-surface.md)
- [ADR-048: Client assertion keys of a login provider](adr/ADR-048-client-assertion-keys.md)
