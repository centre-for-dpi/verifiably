// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// configsPath is the credential configuration API of Certify 0.14.0.
const configsPath = "/v1/certify/credential-configurations"

// SeededConfiguration is the entry the fake holds from the start, as the
// stack sample does (testdata/doc/config-farmer.json).
const SeededConfiguration = "FarmerCredential"

// configs is the credential configuration store of the fake. Certify
// keeps it in its database and builds its issuer metadata from it.
type configs struct {
	// stored holds the body of every entry by id.
	stored map[string]json.RawMessage
	// written lists the ids a test created or updated. Only these join
	// the recorded metadata, so the recorded catalogue stays as it was.
	written []string
}

// seed loads the entry of the stack sample.
func (c *configs) seed(dir string) {
	c.stored = map[string]json.RawMessage{}
	raw, err := os.ReadFile(filepath.Join(dir, "doc", "config-farmer.json")) //nolint:gosec // G304: a fixed fixture name
	if err == nil {
		c.stored[SeededConfiguration] = raw
	}
}

// configEntry is the part of an entry the fake reads.
type configEntry struct {
	ID              string                     `json:"credentialConfigKeyId"`
	Format          string                     `json:"credentialFormat"`
	Types           []string                   `json:"credentialTypes"`
	Contexts        []string                   `json:"contextURLs"`
	Vct             string                     `json:"sdJwtVct"`
	DocType         string                     `json:"doctype"`
	Scope           string                     `json:"scope"`
	Display         json.RawMessage            `json:"metaDataDisplay"`
	Order           []string                   `json:"displayOrder"`
	Subject         map[string]json.RawMessage `json:"credentialSubjectDefinition"`
	SdJwtClaims     map[string]json.RawMessage `json:"sdJwtClaims"`
	MsoMdocClaims   json.RawMessage            `json:"msoMdocClaims"`
	SignatureSuite  string                     `json:"signatureCryptoSuite"`
	SignatureAlgo   string                     `json:"signatureAlgo"`
	StatusPurposes  []string                   `json:"credentialStatusPurposes"`
	VcTemplateValue string                     `json:"vcTemplate"`
}

// same reports whether two entries collide in the duplicate check of
// Certify: the same types and context for ldp_vc, the same vct for
// vc+sd-jwt, and the same doctype for mso_mdoc.
func (e configEntry) same(o configEntry) bool {
	if e.Format != o.Format || e.ID == o.ID {
		return false
	}
	switch e.Format {
	case "ldp_vc":
		return slices.Equal(e.Types, o.Types) && slices.Equal(e.Contexts, o.Contexts)
	case "vc+sd-jwt":
		return e.Vct == o.Vct
	case "mso_mdoc":
		return e.DocType == o.DocType
	}
	return false
}

// serveConfigs answers the credential configuration API. It reports
// false for a path outside the API.
func (f *Server) serveConfigs(w http.ResponseWriter, r *http.Request, body []byte) bool {
	path := r.URL.Path
	if path != configsPath && !strings.HasPrefix(path, configsPath+"/") {
		return false
	}
	id := strings.TrimPrefix(strings.TrimPrefix(path, configsPath), "/")
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && id == "":
		var entry configEntry
		if json.Unmarshal(body, &entry) != nil || entry.ID == "" {
			f.send(w, "doc/config-not-found.json")
			return true
		}
		if f.clash(entry) {
			f.send(w, "doc/config-exists.json")
			return true
		}
		f.store(entry.ID, body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		f.sendJSON(w, map[string]string{"id": entry.ID, "status": "active"})
	case r.Method == http.MethodGet && id != "":
		stored, ok := f.configs.stored[id]
		if !ok {
			f.send(w, "doc/config-not-found.json")
			return true
		}
		f.sendJSON(w, stored)
	case r.Method == http.MethodPut && id != "":
		if _, ok := f.configs.stored[id]; !ok {
			f.send(w, "doc/config-not-found-update.json")
			return true
		}
		f.store(id, body)
		f.sendJSON(w, map[string]string{"id": id, "status": "active"})
	default:
		http.NotFound(w, r)
	}
	return true
}

// clash reports whether a stored entry fails the duplicate check with e.
func (f *Server) clash(e configEntry) bool {
	for _, raw := range f.configs.stored {
		var other configEntry
		if json.Unmarshal(raw, &other) == nil && e.same(other) {
			return true
		}
	}
	return false
}

// store keeps one written entry.
func (f *Server) store(id string, body []byte) {
	f.configs.stored[id] = append(json.RawMessage(nil), body...)
	if !slices.Contains(f.configs.written, id) {
		f.configs.written = append(f.configs.written, id)
	}
}

// Configuration returns the stored body of one entry.
func (f *Server) Configuration(id string) (json.RawMessage, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, ok := f.configs.stored[id]
	return raw, ok
}

// metadata returns the recorded issuer metadata with every written
// entry added, as Certify builds it from its database.
func (f *Server) metadata() ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(f.dir, "issuer-metadata.json")) //nolint:gosec // G304: a fixed fixture name
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.configs.written) == 0 {
		return raw, nil
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	supported, ok := doc["credential_configurations_supported"].(map[string]any)
	if !ok {
		supported = map[string]any{}
	}
	for _, id := range f.configs.written {
		var e configEntry
		if json.Unmarshal(f.configs.stored[id], &e) != nil {
			continue
		}
		supported[id] = metadataEntry(e)
	}
	doc["credential_configurations_supported"] = supported
	return json.Marshal(doc)
}

// metadataEntry renders one entry the way Certify renders it in the
// issuer metadata.
func metadataEntry(e configEntry) map[string]any {
	out := map[string]any{"format": e.Format, "scope": e.Scope, "order": e.Order}
	if len(e.Display) > 0 {
		out["display"] = e.Display
	}
	switch e.Format {
	case "ldp_vc":
		out["credential_definition"] = map[string]any{
			"@context": e.Contexts, "type": e.Types, "credentialSubject": e.Subject,
		}
		out["credential_signing_alg_values_supported"] = []string{e.SignatureSuite}
	case "vc+sd-jwt":
		out["vct"] = e.Vct
		out["claims"] = e.SdJwtClaims
		out["credential_signing_alg_values_supported"] = []string{e.SignatureAlgo}
	case "mso_mdoc":
		out["doctype"] = e.DocType
		if len(e.MsoMdocClaims) > 0 {
			out["claims"] = e.MsoMdocClaims
		}
		out["credential_signing_alg_values_supported"] = []string{e.SignatureSuite}
	}
	return out
}

// sendJSON writes v as JSON. A json.RawMessage goes out as it is.
func (f *Server) sendJSON(w http.ResponseWriter, v any) {
	raw, ok := v.(json.RawMessage)
	if !ok {
		var err error
		if raw, err = json.Marshal(v); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	if _, err := w.Write(raw); err != nil {
		return
	}
}
