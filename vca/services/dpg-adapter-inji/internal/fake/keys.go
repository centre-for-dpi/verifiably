// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
)

// serveKeys answers the key management endpoints of Certify 0.14.0
// (system-info). It reports false for another path.
func (f *Server) serveKeys(w http.ResponseWriter, r *http.Request, body []byte) bool {
	switch {
	case r.URL.Path == "/v1/certify/system-info/certificate" && r.Method == http.MethodGet:
		f.send(w, "doc/key-certificate.json")
	case r.URL.Path == "/v1/certify/system-info/uploadCertificate" && r.Method == http.MethodPost:
		if f.matchesStoredKey(body) {
			f.send(w, "doc/upload-certificate.json")
		} else {
			f.send(w, "doc/key-not-matching.json")
		}
	case r.URL.Path == "/v1/certify/system-info/upload-ca-certificate" && r.Method == http.MethodPost:
		f.send(w, "doc/upload-ca-certificate.json")
	default:
		return false
	}
	return true
}

// matchesStoredKey reports whether the uploaded certificate holds the
// public key of the stored certificate, as the key manager checks.
func (f *Server) matchesStoredKey(body []byte) bool {
	var req struct {
		Request struct {
			CertificateData string `json:"certificateData"`
		} `json:"request"`
	}
	if json.Unmarshal(body, &req) != nil {
		return false
	}
	raw, err := os.ReadFile(filepath.Join(f.dir, "doc", "key-certificate.json")) //nolint:gosec // G304: a fixed fixture name
	if err != nil {
		return false
	}
	var stored struct {
		Response struct {
			Certificate string `json:"certificate"`
		} `json:"response"`
	}
	if json.Unmarshal(raw, &stored) != nil {
		return false
	}
	a, b := publicKey(req.Request.CertificateData), publicKey(stored.Response.Certificate)
	return a != nil && bytes.Equal(a, b)
}

// publicKey returns the encoded public key of the first certificate of a
// PEM text, or nil.
func publicKey(text string) []byte {
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return cert.RawSubjectPublicKeyInfo
}
