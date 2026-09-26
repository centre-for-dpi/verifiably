// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"encoding/json"
)

// CredentialClaim169 is a JSON-LD credential that carries the identity QR
// code Certify signs when the configuration has qrSettings.
//
//nolint:gosec // G101: the value is a file name, not a credential
const CredentialClaim169 Answer = "doc/credential-ldp-claim169.json"

// identityAnswer swaps a JSON-LD credential for one with an identity QR
// code when the last staged configuration asks Certify for the code, as
// Certify does.
func (f *Server) identityAnswer(selected string) string {
	if selected != string(CredentialLdp) {
		return selected
	}
	var staged struct {
		ID string `json:"credential_configuration_id"`
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if json.Unmarshal(f.requests["/v1/certify/pre-authorized-data"], &staged) != nil {
		return selected
	}
	var entry struct {
		QrSettings []map[string]string `json:"qrSettings"`
	}
	if json.Unmarshal(f.configs.stored[staged.ID], &entry) != nil || len(entry.QrSettings) == 0 {
		return selected
	}
	return string(CredentialClaim169)
}
