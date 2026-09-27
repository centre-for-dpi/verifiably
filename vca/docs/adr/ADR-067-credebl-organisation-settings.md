## ADR-067: The webhook, the holder notification address and the client credential of a CREDEBL organisation
- Status: Proposed
- Owner: CDPI Architects
- Scope: The CREDEBL adapter, the backend and admin contracts, the admin portal, and the admin commands.
- Extends: ADR-037 (a tenant is an organisation), ADR-045 decision 4. Closes the P6-C8 rows of the plan.
- Decision:
  1. The adapter sets the webhook of an organisation through the webhook service of the platform. The admin can pass a signing secret of 16 characters or more. The adapter passes the secret on and keeps no copy. A read reports only whether a secret exists.
  2. The platform takes no clear of a webhook. The adapter marks each webhook as fixed and refuses an empty address. The admin portal shows a hint in place of a clear action.
  3. The platform keeps one holder notification address per organisation and reads it back through no call. The adapter keeps the address it registered in its store and reports it as kept by the adapter. It refuses a second registration before the call reaches the platform.
  4. The platform keeps one client credential per organisation. The adapter lists it by its client id and refuses a second create. The secret shows once in the create answer. Neither the adapter nor the admin service stores it.
  5. The answer of `GetCapabilities` lists `FEATURE_WEBHOOKS`, `FEATURE_HOLDER_NOTIFICATIONS` and `FEATURE_TENANT_CLIENT_CREDENTIALS`. The admin portal shows each part only for a stack that lists its feature.
- Consequences:
  1. The Notifications page of the admin portal shows the live webhook of each organisation, with a signed badge. A new section sets the holder notification address.
  2. The API keys page shows the client credential of each organisation of a CREDEBL stack.
  3. The notification route of the platform has no guard. The deploy document publishes one other path of the gateway, so the route stays on the host.
  4. A lost adapter store loses the record of the holder notification address. The platform still holds the row, and a new registration fails with the error of the platform.
