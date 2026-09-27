## ADR-060: The CSV bulk import of a stack that mails each row
- Status: Proposed
- Owner: CDPI Architects
- Scope: The adapter contract, the issuance service, the issue pages, the data source pages, and the CREDEBL adapter.
- Extends: ADR-043 decision 4, ADR-045 decisions 1 and 2, ADR-059 decisions 3 and 4.
- Decision:
  1. `GetCapabilitiesResponse.bulk_import` names the bulk import of an adapter that lists `FEATURE_BULK_NATIVE`: its channel, its formats, and the address column of its CSV file. No value means an import that returns each credential, which VCA delivers as a document, as before.
  2. An import on `CHANNEL_EMAIL` mails each holder an offer. `IssueBatchRequest.emails` carries one address per spec. Each row that the stack takes comes back with `delivered` and no credential. The issuance service keeps that row as a delivered offer on the email channel. The offer has no status entry of VCA.
  3. The new service `BulkImportBackendService` runs the CSV import of the stack. It serves the template, the upload, the preview, and the issue. It also serves the history of the issued files and their rows, and the retry of the failed rows. An adapter without such an import answers each RPC with `Unimplemented`.
  4. The issue wizard offers "<stack> bulk import" as a source for a schema that the import issues. The pages show the template, the upload, the preview, the history, and the retry. When the import mails each row, the data source run asks for the column with the address of each holder.
  5. The CREDEBL adapter lists the import only with a mail provider in the stack `.env`. It issues AnonCreds credentials of a credential definition. It also issues W3C JSON-LD credentials of a schema of the schema file server. The template call of the platform answers with a link and not the file. So the adapter builds the template from the claims of the schema.
- Consequences:
  1. An operator issues many CREDEBL credentials from one file and sees what the platform did with each row.
  2. A data source feeds the CREDEBL import like any other stack.
  3. The progress of a run counts a row as done when the stack takes it. The file history of the stack shows whether each mail went out.
