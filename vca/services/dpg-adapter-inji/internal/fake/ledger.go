// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// The ledger fixtures follow the answers of Inji Certify 0.14.0
// (testdata/doc/SOURCE.md).
const (
	// LedgerType is the credential type of every recorded entry, as the
	// ledger stores it.
	LedgerType = "FarmerCredential,VerifiableCredential"
	// LedgerCredential is the id of the first recorded entry.
	//nolint:gosec // G101: the value is a credential id of the ledger, not a secret
	LedgerCredential = "urn:uuid:3f8a1c2e-7d41-4b8e-9a0c-51f2e6d7a901"
)

// ledgerRequest is the part of a search or an update the fake reads.
type ledgerRequest struct {
	CredentialID     string            `json:"credentialId"`
	IssuerID         string            `json:"issuerId"`
	CredentialType   string            `json:"credentialType"`
	Attributes       map[string]string `json:"indexedAttributesEquals"`
	CredentialStatus struct {
		StatusPurpose string `json:"statusPurpose"`
	} `json:"credentialStatus"`
	Status *bool `json:"status"`
}

// serveLedger answers the ledger search, the status update, and the DID
// document. It reports false for another path.
func (f *Server) serveLedger(w http.ResponseWriter, r *http.Request, body []byte) bool {
	switch {
	case r.URL.Path == "/v1/certify/.well-known/did.json" && r.Method == http.MethodGet:
		f.send(w, "doc/did.json")
	case (r.URL.Path == "/v1/certify/v2/ledger-search" || r.URL.Path == "/v1/certify/ledger-search") && r.Method == http.MethodPost:
		f.search(w, body)
	case r.URL.Path == "/v1/certify/credentials/status" && r.Method == http.MethodPost:
		f.updateStatus(w, body)
	default:
		return false
	}
	return true
}

// entries reads the recorded ledger.
func (f *Server) entries() ([]map[string]any, error) {
	raw, err := os.ReadFile(filepath.Join(f.dir, "doc", "ledger-search.json")) //nolint:gosec // G304: a fixed fixture name
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// search answers a ledger search the way Certify does: an error without
// an attribute, 204 when nothing matches, else the matching entries.
func (f *Server) search(w http.ResponseWriter, body []byte) {
	var q ledgerRequest
	if json.Unmarshal(body, &q) != nil || q.IssuerID == "" || q.CredentialType == "" || !anyValue(q.Attributes) {
		f.send(w, "doc/ledger-search-invalid.json")
		return
	}
	all, err := f.entries()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var out []map[string]any
	for _, e := range all {
		if e["credentialType"] != q.CredentialType || e["issuerId"] != q.IssuerID {
			continue
		}
		if q.CredentialID != "" && e["credentialId"] != q.CredentialID {
			continue
		}
		out = append(out, e)
	}
	if len(out) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	f.sendJSON(w, out)
}

// anyValue reports whether one attribute has a name and a value.
func anyValue(m map[string]string) bool {
	for k, v := range m {
		if strings.TrimSpace(k) != "" && strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

// updateStatus answers a status update: 404 for an unknown credential,
// else the entry with the purpose of the request.
func (f *Server) updateStatus(w http.ResponseWriter, body []byte) {
	var q ledgerRequest
	if json.Unmarshal(body, &q) != nil || q.CredentialID == "" || q.Status == nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	all, err := f.entries()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, e := range all {
		if e["credentialId"] != q.CredentialID {
			continue
		}
		if q.CredentialStatus.StatusPurpose != "" {
			e["statusPurpose"] = q.CredentialStatus.StatusPurpose
		}
		e["statusTimestamp"] = "2026-09-26T10:00:00"
		f.sendJSON(w, e)
		return
	}
	http.Error(w, "Credential not found", http.StatusNotFound)
}
