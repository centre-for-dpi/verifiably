## ADR-035: Provider agnostic sign in with one realm per role
- Status: Proposed
- Owner: CDPI Architects
- Scope: Login for the four roles.
- Extends: ADR-010 decisions 1 to 5, ADR-012 decision 5, ADR-020 decision 1.
- Decision:
  1. Each stack Keycloak holds four realms: `vca-admin-realm`, `vca-issuer-realm`, `vca-holder-realm`, `vca-verifier-realm`, each with self registration on.
  2. Keycloak is a default provider record of kind `keycloak`, never a code dependency. A provider record carries its kind, realm label, registration mode, console URL, stacks, roles, and token authentication method.
  3. The register action uses `prompt=create` when the provider supports it. It falls back to the Keycloak registration endpoint for kind `keycloak`. Otherwise the page shows no register action.
  4. Token authentication supports `client_secret_basic`, `client_secret_post`, and `private_key_jwt`, so eSignet works.
  5. The admin portal creates a provider once. It pushes the record to the auth service of every targeted live pair with the admin session token. Each auth service checks that token against the admin key set.
  6. The first admin registers in `vca-admin-realm` and binds with the bootstrap token of ADR-010 decision 4. The first run checklist then asks the operator to turn off self registration.
  7. The CLI generates the Keycloak administrator password per stack.
- Consequences:
  1. A country can use WSO2 IS, eSignet, or its own IdP.
  2. Each role has its own user base.
  3. No default password ships.
