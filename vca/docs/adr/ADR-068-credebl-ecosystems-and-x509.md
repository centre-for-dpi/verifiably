## ADR-068: CREDEBL ecosystems and the X.509 issuer identity
- Status: Proposed
- Owner: CDPI Architects
- Scope: The CREDEBL adapter, the backend and admin contracts, and the admin portal and commands. Also the issuer identity page and the bootstrap of the CREDEBL stack.
- Extends: ADR-037 (a tenant is an organisation), ADR-046 decision 2, ADR-066. Closes the P6-C9 rows of the plan.
- Decision:
  1. The tenant backend gains the ecosystem RPCs. They read and set the switch of the platform and list the ecosystems of a tenant. They also create an ecosystem and change its members. The CREDEBL adapter serves them and lists `FEATURE_ECOSYSTEMS`. The walt.id and Inji adapters answer `unimplemented`, since they keep no tenants.
  2. The platform admin of the adapter creates each ecosystem. The platform needs an unused invitation of the platform admin for each create. So the adapter invites the platform admin first. The adapter then signs in again, so the next call carries the lead role.
  3. A member joins through the invitation call of the platform. The platform accepts the member at once when the platform admin created its organisation. The adapter reports when the platform mailed an invitation instead.
  4. The bootstrap of the CREDEBL stack lets the platform realm keep unmanaged user attributes. It also maps the attribute `ecosystem_access` into the tokens of the profile client scope. The run uses the administrator of Keycloak. The management client of the platform keeps its roles.
  5. The admin portal shows an Ecosystems tab beside the tenant list only where a live adapter lists the feature. The admin service reads each ecosystem once and names the lead and the members by their VCA tenants.
  6. The CREDEBL adapter imports an X.509 chain as the issuer identity. It lists `FEATURE_ISSUER_IDENTITY_IMPORT_X509`. The key reference names a certificate row of the platform as `{"certificateId": "<id>"}`. The agent keeps the key of the row. VCA never sends a private key.
  7. The adapter checks that the chain verifies, and that the leaf is the certificate of the row. The leaf must be valid now. The adapter takes the older active rows of the key type out of use and activates the row. It keeps the chain, because the platform keeps the leaf only.
  8. A DID import stays `unimplemented`, since the agent takes no key reference for a DID.
- Consequences:
  1. An operator makes or imports the certificate and its key in the platform first. The identity page of VCA then binds the chain.
  2. The platform signs a template with an X.509 signer option with the active row of the key type. The `x5c` header of such a credential holds the leaf only.
  3. The identity of the organisation shows the subject of the leaf and the chain while the row stays active. A row that the platform takes out of use leaves the identity.
  4. Each create of an ecosystem mails the address of the platform admin when the stack names a mail provider.
