// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

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

// SetNow sets the clock of the database, which the query of the claims
// store compares expires_at with. Nil reads the real clock.
func (f *Server) SetNow(now func() time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = now
}

// dbNow reads the clock of the database. The caller holds the lock.
func (f *Server) dbNow() time.Time {
	if f.now != nil {
		return f.now()
	}
	return time.Now()
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

// credentialRequest is the part of a credential request the fake reads.
type credentialRequest struct {
	Format     string `json:"format"`
	Definition struct {
		Type []string `json:"type"`
	} `json:"credential_definition"`
}

// configurationFor returns the stored entry that a credential request
// names, as VCIssuanceUtil.getScopeCredentialMapping of Certify 0.14.0
// picks it: by the format and the types of the request, never by the
// row. Every VCA entry has the same scope. The caller holds the lock.
func (f *Server) configurationFor(req credentialRequest) (configEntry, bool) {
	want := slices.Clone(req.Definition.Type)
	slices.Sort(want)
	for _, raw := range f.configs.stored {
		var e configEntry
		if json.Unmarshal(raw, &e) != nil || e.Format != req.Format {
			continue
		}
		have := slices.Clone(e.Types)
		slices.Sort(have)
		if len(want) > 0 && slices.Equal(have, want) {
			return e, true
		}
	}
	return configEntry{}, false
}

// tokenSubject reads sub of a bearer JWT. The fake checks no
// signature: it models the data provider, which reads sub of the token
// that Certify checked.
func tokenSubject(header string) (string, bool) {
	token, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		return "", false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if json.Unmarshal(raw, &claims) != nil || claims.Sub == "" {
		return "", false
	}
	return claims.Sub, true
}

// fromStore answers a credential request from the claims store. It
// reports false when the store is off, so the recorded answer applies.
// Like Certify, it takes the template of the configuration the request
// names and fills it with the row of the token subject, whatever
// configuration the row was staged for.
func (f *Server) fromStore(w http.ResponseWriter, r *http.Request, body []byte) bool {
	var req credentialRequest
	f.mu.Lock()
	dir, subject, now := f.claimsDir, f.stagedSubject(), f.dbNow()
	f.mu.Unlock()
	if sub, ok := tokenSubject(r.Header.Get("Authorization")); ok {
		subject = sub
	}
	if dir == "" || json.Unmarshal(body, &req) != nil || req.Format != "ldp_vc" {
		return false
	}
	f.mu.Lock()
	entry, known := f.configurationFor(req)
	f.mu.Unlock()
	if !known {
		// Certify answers invalid_scope when no configuration of the
		// scope of the token matches the request.
		http.Error(w, `{"error":"invalid_scope"}`, http.StatusBadRequest)
		return true
	}
	row, ok, err := claims.Writer{Dir: dir}.Find(subject)
	if err != nil || !ok || !now.Before(row.ExpiresAt) {
		// The plugin answers ERROR_FETCHING_DATA_RECORD_FROM_TABLE when
		// the query finds no row. The query reads only a row whose
		// expires_at lies ahead (ADR-056 decision 3).
		http.Error(w, `{"error":"ERROR_FETCHING_DATA_RECORD_FROM_TABLE"}`, http.StatusBadRequest)
		return true
	}
	text, err := base64.StdEncoding.DecodeString(entry.VcTemplateValue)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return true
	}
	var credential map[string]any
	if err := json.Unmarshal([]byte(render(string(text), row)), &credential); err != nil {
		// Certify answers JSON_PROCESSING_ERROR when the template does
		// not render a JSON object.
		http.Error(w, `{"error":"JSON_PROCESSING_ERROR"}`, http.StatusInternalServerError)
		return true
	}
	f.sendJSON(w, map[string]any{"format": "ldp_vc", "credential": credential})
	return true
}

// variable is one ${name} of a template.
var variable = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// The conditions of a #if line that the fake understands: an equality
// with a quoted text, a non empty test, and a bare reference.
var (
	equalsText = regexp.MustCompile(`^\$([A-Za-z_][A-Za-z0-9_]*) == (?:'([^']*)'|"([^"]*)")$`)
	nonEmpty   = regexp.MustCompile(`^\$([A-Za-z_][A-Za-z0-9_]*) && \$([A-Za-z_][A-Za-z0-9_]*) != ""$`)
	reference  = regexp.MustCompile(`^\$([A-Za-z_][A-Za-z0-9_]*)$`)
)

// holds reports whether a #if condition holds for the values. Velocity
// 1.7 compares a null reference as false, so a missing value never
// equals a text.
func holds(condition string, values map[string]string) bool {
	if m := equalsText.FindStringSubmatch(condition); m != nil {
		v, ok := values[m[1]]
		return ok && v == m[2]+m[3]
	}
	if m := nonEmpty.FindStringSubmatch(condition); m != nil && m[1] == m[2] {
		return values[m[1]] != ""
	}
	if m := reference.FindStringSubmatch(condition); m != nil {
		return values[m[1]] != ""
	}
	return false
}

// Render fills a template from a row the way the Velocity engine of
// Certify does for the templates VCA writes: every ${name}, and every
// #if block on lines of their own, nested. A block whose condition
// fails goes.
func Render(template string, row claims.Row) string { return render(template, row) }

// openIf splits a line that opens a #if block into the condition and
// the text after the closing parenthesis, which belongs to the block.
func openIf(line string) (condition, rest string, ok bool) {
	body, found := strings.CutPrefix(line, "#if(")
	if !found {
		return "", "", false
	}
	depth := 1
	for i, r := range body {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return body[:i], body[i+1:], true
			}
		}
	}
	return "", "", false
}

// render fills a template from a row. The row gives the reserved
// columns and the claim columns under their names, as the data provider
// returns them.
func render(template string, row claims.Row) string {
	values := map[string]string{
		"_issuer": FakeIssuer, "_holderId": FakeHolder,
		claims.ValidFromColumn: row.ValidFrom, claims.ValidUntilColumn: row.ValidUntil,
		claims.StatusURIColumn: row.StatusURI, claims.StatusIndexColumn: row.StatusIndex,
	}
	if row.ConfigID != "" {
		values[claims.ConfigColumn] = row.ConfigID
	}
	for i, v := range row.Claims {
		values[claims.ColumnName(i)] = v
	}
	var out []string
	var open []bool
	shown := func() bool { return !slices.Contains(open, false) }
	for _, line := range strings.Split(template, "\n") {
		trimmed := strings.TrimSpace(line)
		if condition, rest, ok := openIf(trimmed); ok {
			open = append(open, holds(condition, values))
			if rest == "" {
				continue
			}
			line = rest
		} else if trimmed == "#end" && len(open) > 0 {
			open = open[:len(open)-1]
			continue
		}
		if shown() {
			out = append(out, line)
		}
	}
	return variable.ReplaceAllStringFunc(strings.Join(out, "\n"), func(m string) string {
		return values[variable.FindStringSubmatch(m)[1]]
	})
}
