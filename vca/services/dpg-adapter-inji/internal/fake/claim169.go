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

// CredentialSdJwtClaim169 is an SD-JWT credential whose identity QR code
// sits in a disclosure, as Certify signs it for a vc+sd-jwt
// configuration with qrSettings.
//
//nolint:gosec // G101: the value is a file name, not a credential
const CredentialSdJwtClaim169 Answer = "doc/credential-sdjwt-claim169.json"

// identityAnswer swaps a JSON-LD credential for one with an identity QR
// code when the last staged configuration asks Certify for the code, as
// Certify does. A request of the format vc+sd-jwt gets the SD-JWT one.
func (f *Server) identityAnswer(selected string, body []byte) string {
	if selected != string(CredentialLdp) {
		return selected
	}
	var req struct {
		Format string `json:"format"`
	}
	withQR := CredentialClaim169
	if json.Unmarshal(body, &req) == nil && req.Format == "vc+sd-jwt" {
		withQR = CredentialSdJwtClaim169
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
	return string(withQR)
}
