## ADR-057: The holder sign in reads one row of a data source with a service token of its pair
- Status: Proposed
- Owner: CDPI Architects
- Scope: DataSourceService.Lookup, the holder authorization server of the Inji adapter, and the tab "Claims by sign in".
- Extends: ADR-015 decisions 3 and 4, ADR-047, ADR-052 decision 3, ADR-056 decision 2.
- Decision:
  1. `Lookup` returns the one row of a source whose field holds a value. The field map of a schema turns the row into claims. Two rows give no row.
  2. The holder authorization server calls `Lookup` with a token that it derives from the pair session key. The token opens `Lookup` and no other call. The data source service stays on the compose network.
  3. A source serves the holder sign in only when its issue rule names the role `holder-sign-in`. The staff member who saves the tab adds the role with their own session.
  4. A staff session with the issue rule of the source can call `Lookup` to test it. It gets masked values only.
  5. The SQL kind wraps the query of the source in an outer SELECT. The field is a quoted column of the query, and the value travels as an argument.
  6. The adapter stores a sign in source only for an ID token claim that the holder provider vouches for.
- Consequences:
  1. A holder claims a credential without an offer once the issuer saves the tab.
  2. No unmasked row leaves the data source through a staff call.
  3. A leaked lookup token reads one row at a time of a source that the issuer opened. A new session key ends it.
