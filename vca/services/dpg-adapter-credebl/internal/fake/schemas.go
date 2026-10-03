// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The fake keeps the schemas and the credential definitions it writes,
// as the platform does, so a second registration can find the first.
// The rules follow the platform at the tag v2.2.1-alpha.4
// (testdata/doc/SOURCE.md): an AnonCreds schema whose name and version
// another AnonCreds schema of any organisation contains answers the
// status conflict, a W3C schema never does, and a credential definition
// answers the status conflict when one with the same schema and tag
// exists. A list with no row answers the status not found.

// schemaRow is one schema the fake keeps.
type schemaRow struct {
	org, kind                         string
	name, version, ledgerID, issuerID string
	alias                             string
	attributes                        json.RawMessage
}

// credDefRow is one credential definition the fake keeps.
type credDefRow struct {
	org, tag, id, schemaLedgerID string
}

// foreignOrg is the organisation of the rows AddForeignSchema adds.
const foreignOrg = "org-foreign"

// AddForeignSchema adds an AnonCreds schema of another organisation,
// which blocks the same name and version for every organisation.
func (f *Server) AddForeignSchema(name, version string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.schemaRows = append(f.schemaRows, schemaRow{
		org: foreignOrg, kind: "indy", name: name, version: version,
		ledgerID: "did:indy:bcovrin:testnet:Foreign/anoncreds/v0/SCHEMA/" + name + "/" + version,
	})
}

// serveSchemas answers the schema and credential definition calls of an
// organisation. It reports whether it answered.
func (f *Server) serveSchemas(w http.ResponseWriter, r *http.Request, body []byte) bool {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 || parts[0] != "v1" || parts[1] != "orgs" {
		return false
	}
	org := parts[2]
	prefix := "/v1/orgs/" + org + "/schemas/"
	switch {
	case len(parts) == 4 && parts[3] == "schemas" && r.Method == http.MethodPost:
		f.writeSchema(w, org, body)
	case len(parts) == 4 && parts[3] == "schemas" && r.Method == http.MethodGet:
		f.listSchemas(w, r, org)
	case len(parts) == 4 && parts[3] == "cred-defs" && r.Method == http.MethodPost:
		f.writeCredDef(w, org, body)
	case strings.HasPrefix(r.URL.Path, prefix) && strings.HasSuffix(r.URL.Path, "/cred-defs") && r.Method == http.MethodGet:
		f.listCredDefs(w, r, org, strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, prefix), "/cred-defs"))
	default:
		return false
	}
	return true
}

// writeSchema stores one schema and answers with its record.
func (f *Server) writeSchema(w http.ResponseWriter, org string, body []byte) {
	var req struct {
		Type    string `json:"type"`
		Alias   string `json:"alias"`
		Payload struct {
			SchemaName    string          `json:"schemaName"`
			SchemaVersion string          `json:"schemaVersion"`
			SchemaType    string          `json:"schemaType"`
			OrgDid        string          `json:"orgDid"`
			Attributes    json.RawMessage `json:"attributes"`
		} `json:"schemaPayload"`
	}
	answer := schemaAnswer(body)
	if json.Unmarshal(body, &req) != nil || answer == "schema-created.json" {
		f.send(w, answer)
		return
	}
	data, err := f.recorded(answer)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	row := schemaRow{
		org: org, name: req.Payload.SchemaName, alias: req.Alias, attributes: req.Payload.Attributes,
		ledgerID: text(data["schemaLedgerId"]), issuerID: text(data["issuerId"]), version: text(data["version"]),
	}
	if req.Type == "indy" {
		for _, s := range f.schemaRows {
			if s.kind == "indy" && containsFold(s.name, req.Payload.SchemaName) && containsFold(s.version, req.Payload.SchemaVersion) {
				conflict(w, "Schema already exists")
				return
			}
		}
		row.kind, row.version = "indy", req.Payload.SchemaVersion
		if req.Payload.OrgDid != "" {
			row.issuerID = req.Payload.OrgDid
			row.ledgerID = req.Payload.OrgDid + "/anoncreds/v0/SCHEMA/" + row.name + "/" + row.version
		}
	} else {
		row.kind = "w3c"
		if n := len(f.schemaRows); n > 0 {
			row.ledgerID += "-" + strconv.Itoa(n)
		}
	}
	f.schemaRows = append(f.schemaRows, row)
	data["name"], data["version"], data["schemaLedgerId"], data["issuerId"] = row.name, row.version, row.ledgerID, row.issuerID
	if row.alias != "" {
		data["alias"] = row.alias
	}
	sendJSON(w, http.StatusCreated, map[string]any{"statusCode": 201, "message": "Schema created successfully", "data": data})
}

// listSchemas answers one page of the schemas of an organisation that
// carry the search text.
func (f *Server) listSchemas(w http.ResponseWriter, r *http.Request, org string) {
	q := r.URL.Query()
	search := q.Get("searchByText")
	f.mu.Lock()
	rows := []map[string]any{}
	total := 0
	for _, s := range f.schemaRows {
		if s.org != org {
			continue
		}
		total++
		if !containsFold(s.name, search) && !containsFold(s.version, search) &&
			!containsFold(s.ledgerID, search) && !containsFold(s.issuerID, search) {
			continue
		}
		attributes := s.attributes
		if len(attributes) == 0 {
			attributes = json.RawMessage("[]")
		}
		rows = append(rows, map[string]any{
			"name": s.name, "version": s.version, "schemaLedgerId": s.ledgerID, "issuerId": s.issuerID,
			"publisherDid": s.issuerID, "orgId": s.org, "alias": nullable(s.alias), "attributes": attributes,
		})
	}
	f.mu.Unlock()
	if total == 0 {
		notFound(w, "Schema not found")
		return
	}
	sendJSON(w, http.StatusOK, map[string]any{"statusCode": 200, "message": "Schemas fetched successfully", "data": page(rows, q)})
}

// writeCredDef stores one credential definition and answers with it.
func (f *Server) writeCredDef(w http.ResponseWriter, org string, body []byte) {
	var req struct {
		Tag            string `json:"tag"`
		SchemaLedgerID string `json:"schemaLedgerId"`
		OrgDid         string `json:"orgDid"`
	}
	data, err := f.recorded("doc/cred-def-created.json")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if json.Unmarshal(body, &req) != nil {
		sendJSON(w, http.StatusCreated, map[string]any{"statusCode": 201, "data": data})
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, d := range f.credDefRows {
		if d.schemaLedgerID == req.SchemaLedgerID && d.tag == req.Tag {
			conflict(w, "Credential definition already exists")
			return
		}
	}
	row := credDefRow{org: org, tag: req.Tag, schemaLedgerID: req.SchemaLedgerID, id: text(data["credentialDefinitionId"])}
	if req.OrgDid != "" {
		row.id = req.OrgDid + "/anoncreds/v0/CLAIM_DEF/" + strconv.Itoa(2107+len(f.credDefRows)) + "/" + req.Tag
	}
	f.credDefRows = append(f.credDefRows, row)
	data["credentialDefinitionId"], data["tag"], data["schemaLedgerId"] = row.id, row.tag, row.schemaLedgerID
	sendJSON(w, http.StatusCreated, map[string]any{"statusCode": 201, "message": "Credential definition created successfully", "data": data})
}

// listCredDefs answers the credential definitions of one schema of an
// organisation.
func (f *Server) listCredDefs(w http.ResponseWriter, r *http.Request, org, schemaLedgerID string) {
	f.mu.Lock()
	var rows []map[string]any
	for _, d := range f.credDefRows {
		if d.org == org && d.schemaLedgerID == schemaLedgerID {
			rows = append(rows, map[string]any{
				"tag": d.tag, "credentialDefinitionId": d.id, "schemaLedgerId": d.schemaLedgerID, "revocable": false,
			})
		}
	}
	f.mu.Unlock()
	if len(rows) == 0 {
		notFound(w, "Credential definitions not found")
		return
	}
	sendJSON(w, http.StatusOK, map[string]any{"statusCode": 200, "message": "Schema fetched successfully", "data": page(rows, r.URL.Query())})
}

// page cuts one page of rows by the query pageNumber and pageSize, with
// the paging fields of the platform.
func page(rows []map[string]any, q map[string][]string) map[string]any {
	number, size := atoi(first(q["pageNumber"]), 1), atoi(first(q["pageSize"]), 10)
	from := min((number-1)*size, len(rows))
	to := min(from+size, len(rows))
	return map[string]any{
		"totalItems": len(rows), "hasNextPage": to < len(rows), "hasPreviousPage": number > 1,
		"nextPage": number + 1, "previousPage": number - 1, "lastPage": (len(rows) + size - 1) / size,
		"data": rows[from:to],
	}
}

// recorded reads the data member of one recorded answer.
func (f *Server) recorded(name string) (map[string]any, error) {
	raw, err := os.ReadFile(filepath.Join(f.dir, name)) //nolint:gosec // G304: the name is one of the fixed answers
	if err != nil {
		return nil, err
	}
	var out struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// conflict answers the status conflict as the platform words it.
func conflict(w http.ResponseWriter, message string) {
	sendJSON(w, http.StatusConflict, map[string]any{"statusCode": 409, "message": message, "error": "Conflict"})
}

// notFound answers the status not found as the platform words it.
func notFound(w http.ResponseWriter, message string) {
	sendJSON(w, http.StatusNotFound, map[string]any{"statusCode": 404, "message": message, "error": "Not Found"})
}

// sendJSON writes one JSON answer with a status code.
func sendJSON(w http.ResponseWriter, status int, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(raw); err != nil {
		return
	}
}

// containsFold reports whether s contains sub, ignoring case, as the
// insensitive contains filter of the platform does.
func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

// text returns a string member, or the empty string.
func text(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// nullable maps the empty string to JSON null, as the platform answers
// a schema with no alias.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// first returns the first value, or the empty string.
func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// atoi reads a positive number, or def.
func atoi(s string, def int) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return def
	}
	return n
}
