## ADR-053: eSignet runs only with a real authenticator
- Status: Proposed
- Owner: CDPI Architects
- Scope: The eSignet containers of the Inji stack, setup, bootstrap and the feature answer of the adapter.
- Extends: ADR-008 decision 3, ADR-045 decision 1.
- Decision:
  1. The stack file keeps eSignet 1.5.1 and its login page under the profile `esignet-inji`. `vca deploy` adds the profile when the pair setting `inji.esignet.authenticator` is `mosip-ida`, `sunbird-rc` or `custom`.
  2. The mock identity system, the mock plugin, the mock key binder and the mock database leave the stack.
  3. The operator supplies the plugin properties file and its secrets. Setup mounts the file as an eSignet profile and writes the secrets with mode 0600.
  4. Bootstrap registers the VCA client at eSignet only when it runs. Setup seeds it as a holder provider of kind `esignet`.
  5. The feature answer of the adapter lists eSignet only for a pair that runs it.
- Consequences:
  1. An Inji pair without a national identity system runs three containers fewer.
  2. An operator with MOSIP IDA or Sunbird RC gets eSignet as their holder login with no VCA change.
  3. The memory floor of an Inji pair drops when eSignet is off. The doctor reports both floors.
