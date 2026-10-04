## ADR-080: A required cross rule that cannot run fails the combined verdict
- Status: Proposed
- Owner: CDPI Architects
- Scope: `vca.combined.v1.CombinedTemplate.Rule`, `services/verifier-combined/internal/rules`, the combined query pages of the discovery service, and the summary card of the results service.
- Extends: ADR-026 decisions 2, 3 and 4, ADR-079 decision 4.
- Decision:
  1. Each cross rule carries `required`. The verifier marks it on the combined query page, and a new rule starts required.
  2. A required rule that cannot run fails. Its outcome is `FAIL`, and its detail starts with "a required rule could not run". So the combined verdict is `INVALID`.
  3. An optional rule that cannot run reports `SKIP`. A `SKIP` leaves the verdict alone, as ADR-026 decision 3 folds it.
  4. The evidence of each rule result names `requirement` as `required` or `optional`. The summary card marks each rule "Required rule" or "Optional rule".
- Consequences:
  1. A verifier who needs a rule never reads a valid verdict from an answer that left the rule unchecked. The answer can lack a named credential or the named value.
  2. A stored rule from before this record carries no `required`, so it stays optional and keeps its old verdict. Staff mark it on the edit page.
  3. The check `REQUIRED_MEMBERS` still fails a missing mandatory member. A required rule adds the same guard for a member of an alternative group. It also guards a value that the credential lacks.
