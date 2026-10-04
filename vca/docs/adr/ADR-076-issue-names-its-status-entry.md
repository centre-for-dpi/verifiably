## ADR-076: The answer of Issue names the status entry its credential carries
- Status: Proposed
- Owner: CDPI Architects
- Scope: `IssueResponse` of the backend contract, the issuance service, and the DPG adapters that serve `Issue`.
- Extends: ADR-072 decisions 1 and 2, ADR-016 decision 3.
- Decision:
  1. `IssueResponse` names the status entry of its credential in `status`, as `CreateOfferResponse` does. The rules of ADR-072 decision 1 hold: the entry of the spec, an entry with `dpg_list`, or no entry.
  2. With `dpg_list` set, `credential_id` of the answer is the id that `Revoke` takes.
  3. The issuance service records the entry that the answer of `Issue` names, on the document channel and the identity QR channel. An answer that names no entry gives a record with no entry.
- Consequences:
  1. The adapter now revokes a document channel credential of a stack with its own list. Before, its record named the entry of VCA that the spec carried, whether or not the credential held it.
  2. An adapter that embeds the entry of the spec must now return it. The Inji adapter does.
  3. The items of `IssueBatchResponse` name no entry yet. A native batch keeps the entry of each spec.
- Amendment of 2026-10-04:
  1. Consequence 3 left the items of `IssueBatchResponse` with no entry. A native batch recorded the entry of each spec, whether or not the credential held it.
  2. Each item now names the status entry of its credential in `status` and the id of the credential in `credential_id`. The rules of decisions 1 and 2 hold for each item.
  3. The issuance service records the entry that each item names, on the document channel of a native batch. An item that names no entry gives a record with no entry.
  4. The Inji adapter names the entry of each item. A row that the CREDEBL bulk import mails carries no entry of VCA, so its item names none (ADR-059 decision 4).
