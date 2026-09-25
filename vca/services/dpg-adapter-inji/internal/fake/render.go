// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
)

// RenderingTemplate is the id of the SVG template the fake serves
// (testdata/doc/rendering-template.svg).
const RenderingTemplate = "farmer-card"

// CredentialMdoc is an mDoc credential: the base64url IssuerSigned
// structure Certify returns for mso_mdoc.
//
//nolint:gosec // G101: the value is a file name, not a credential
const CredentialMdoc Answer = "doc/credential-mdoc.json"

// credentialAnswer picks the credential answer by the format of the
// request: an mso_mdoc request gets the mDoc, as Certify issues it.
func credentialAnswer(body []byte, selected Answer) string {
	var req struct {
		Format string `json:"format"`
	}
	if json.Unmarshal(body, &req) == nil && req.Format == "mso_mdoc" {
		return string(CredentialMdoc)
	}
	return string(selected)
}

// renderingTemplate serves the SVG template with the id, or 404.
func (f *Server) renderingTemplate(w http.ResponseWriter, id string) {
	if id != RenderingTemplate {
		http.NotFound(w, nil)
		return
	}
	raw, err := os.ReadFile(filepath.Join(f.dir, "doc", "rendering-template.svg")) //nolint:gosec // G304: a fixed fixture name
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	if _, err := w.Write(raw); err != nil {
		return
	}
}
