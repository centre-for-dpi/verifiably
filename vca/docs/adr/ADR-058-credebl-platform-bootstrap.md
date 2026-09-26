## ADR-058: The CREDEBL platform runs on generated credentials, its own realm, and the webhook of its gateway
- Status: Proposed
- Owner: CDPI Architects
- Scope: The CREDEBL stack file, `vca setup` and `vca dpg bootstrap credebl`.
- Extends: ADR-055 decisions 1 and 4, ADR-035 decision 1, ADR-045 decision 4.
- Decision:
  1. Setup writes the master table of the CREDEBL initialisation with the generated platform admin password of the stack `.env`. The stack file mounts it over the table that the platform repository publishes.
  2. The Keycloak of the stack holds the realm `credebl-platform` of the platform with an admin client and a management client. Setup writes the realm with a placeholder of each client secret. The secrets live in the stack `.env`. No VCA service signs in at this realm, and the realms of the VCA roles stay as ADR-035 makes them.
  3. The bootstrap run creates the platform realm when the Keycloak of the stack lacks it, before the initialisation.
  4. The shared agent sends its events to `/wh/<organisation>` of the api gateway, with the organisation `Platform-admin`. The bootstrap run writes that address into the stack `.env` and restarts the agent when the address changes.
- Consequences:
  1. No deployment runs with a password that the platform repository publishes.
  2. The platform admin and the adapter sign in on a live stack with no manual step in Keycloak.
  3. The platform records the state of each DIDComm and OID4VC exchange of the shared agent.
