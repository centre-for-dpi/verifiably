## ADR-040: Notifications page before notification delivery
- Status: Proposed
- Owner: CDPI Architects
- Scope: The notifications pages of the admin and issuer portals.
- Decision:
  1. The pages exist and list the channels. VCA delivery by email and SMS shows "Not built in this release".
  2. DPG webhooks and session callbacks show and work when the adapter lists `FEATURE_WEBHOOKS` or `FEATURE_SESSION_CALLBACKS`.
- Consequences:
  1. The UI is ready for the delivery feature.
  2. No page shows a DPG notification feature as missing.
