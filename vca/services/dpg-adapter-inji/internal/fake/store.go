// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/claims"
)

// The fake reads the VCA claims store as the Postgres data provider of
// the digital credential plugins 0.6.0 does (ADR-051): the subject of
// the token keys the row, and the template of the configuration reads
// the columns of the row. The fake knows no token, so it takes the
// subject of the last staging call: the JSON text of the staged map.

// FakeIssuer is the issuer the fake puts into a template.
const FakeIssuer = "did:web:inji-certify.example.org"

// FakeHolder is the holder id the fake puts into a template.
const FakeHolder = "did:jwk:holder"

// SetClaimsDir makes the fake issue JSON-LD credentials from the rows of
// the claims store in dir. Empty turns it off.
func (f *Server) SetClaimsDir(dir string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claimsDir = dir
}

// stagedSubject returns the subject of a token for the last staging
// call, as Certify writes it.
func (f *Server) stagedSubject() string {
	var staged struct {
		Claims map[string]string `json:"claims"`
	}
	if json.Unmarshal(f.requests["/v1/certify/pre-authorized-data"], &staged) != nil {
		return ""
	}
	return claims.Key(staged.Claims["id"])
}

// fromStore answers a credential request from the claims store. It
// reports false when the store is off, so the recorded answer applies.
func (f *Server) fromStore(w http.ResponseWriter, body []byte) bool {
	var req struct {
		Format string `json:"format"`
	}
	f.mu.Lock()
	dir, subject := f.claimsDir, f.stagedSubject()
	f.mu.Unlock()
	if dir == "" || json.Unmarshal(body, &req) != nil || req.Format != "ldp_vc" {
		return false
	}
	row, ok, err := claims.Writer{Dir: dir}.Find(subject)
	if err != nil || !ok {
		// The plugin answers ERROR_FETCHING_DATA_RECORD_FROM_TABLE when
		// the query finds no row.
		http.Error(w, `{"error":"ERROR_FETCHING_DATA_RECORD_FROM_TABLE"}`, http.StatusBadRequest)
		return true
	}
	f.mu.Lock()
	raw := f.configs.stored[row.ConfigID]
	f.mu.Unlock()
	var entry configEntry
	if json.Unmarshal(raw, &entry) != nil {
		http.Error(w, "unknown configuration", http.StatusBadRequest)
		return true
	}
	text, err := base64.StdEncoding.DecodeString(entry.VcTemplateValue)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return true
	}
	var credential map[string]any
	if err := json.Unmarshal([]byte(render(string(text), row)), &credential); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return true
	}
	f.sendJSON(w, map[string]any{"format": "ldp_vc", "credential": credential})
	return true
}

// variable is one ${name} of a template.
var variable = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// render fills a template from a row: every ${name}, and a #if block
// that the status address guards. Other blocks go.
func render(template string, row claims.Row) string {
	values := map[string]string{
		"_issuer": FakeIssuer, "_holderId": FakeHolder,
		claims.ValidFromColumn: row.ValidFrom, claims.ValidUntilColumn: row.ValidUntil,
		claims.StatusURIColumn: row.StatusURI, claims.StatusIndexColumn: row.StatusIndex,
	}
	for i, v := range row.Claims {
		values[claims.ColumnName(i)] = v
	}
	var out []string
	skip := false
	for _, line := range strings.Split(template, "\n") {
		switch {
		case strings.HasPrefix(line, "#if("):
			skip = !strings.Contains(line, "$"+claims.StatusURIColumn) || row.StatusURI == ""
			continue
		case line == "#end":
			skip = false
			continue
		case skip:
			continue
		}
		out = append(out, line)
	}
	return variable.ReplaceAllStringFunc(strings.Join(out, "\n"), func(m string) string {
		return values[variable.FindStringSubmatch(m)[1]]
	})
}
