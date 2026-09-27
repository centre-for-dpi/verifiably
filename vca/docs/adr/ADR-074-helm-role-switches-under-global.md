## ADR-074: The role switches of the umbrella chart sit under global
- Status: Proposed
- Owner: CDPI Architects
- Scope: The umbrella chart `deploy/vca/helm/vca` and the service charts.
- Extends: ADR-008 decision 5. Supersedes the switch `roles.<role>.enabled` of that decision.
- Decision:
  1. The umbrella chart turns a role on with `global.roles.<role>.enabled`. A value under `global` reaches every service chart.
  2. A service of one role keeps a condition on its role. A DPG adapter keeps the condition on its DPG.
  3. The chart of a service of several roles names its roles in its values. Each of its templates renders only when one of those roles is on. A chart installed alone renders as before.
  4. The umbrella chart stops the render when a value names the old switch `roles.<role>.enabled`. The message names the new path.
- Consequences:
  1. A condition of helm takes the first path that exists, so it cannot follow several roles. The gate in the templates can.
  2. A DPG adapter runs only for a role that uses it. An admin release with a DPG turned on starts no adapter.
  3. An operator changes the flag of an existing release once.
