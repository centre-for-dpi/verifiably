// SPDX-License-Identifier: Apache-2.0

package credebl

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// P6-C9: the X.509 calls of the api gateway.

// importedID is the id of the imported certificate of the fixtures.
const importedID = "6f1d2c3b-4a5e-4f60-8b7a-9c0d1e2f3a4b"

// TestX509Calls: one certificate reads with its key type, status and
// base64 DER. The list asks for a status and a key type. The status
// changes read back. A not found reads as the sentinel error.
func TestX509Calls(t *testing.T) {
	p := newProofServer(t)
	c, ctx := p.client(), context.Background()
	p.answers["GET /v1/x509/org-1/"+importedID] = doc(t, "x509-certificate.json")
	p.answers["GET /v1/x509/org-1"] = doc(t, "x509-certificates.json")
	p.answers["PUT /v1/x509/org-1/activate/"+importedID] = doc(t, "x509-activated.json")
	p.answers["PUT /v1/x509/org-1/deactivate/1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"] = doc(t, "x509-deactivated.json")
	cert, err := c.X509Certificate(ctx, "org-1", importedID)
	if err != nil || cert.ID != importedID || cert.KeyType != X509KeyP256 || cert.Status != X509Pending || cert.CertificateBase64 == "" || cert.Expiry.Year() != 2036 {
		t.Fatalf("certificate = %+v, %v", cert, err)
	}
	list, err := c.X509Certificates(ctx, "org-1", X509Active, X509KeyP256)
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	if q := p.queries["GET /v1/x509/org-1"]; q != "keyType=P-256&pageNumber=1&pageSize=100&status=Active" {
		t.Errorf("list query = %s", q)
	}
	if cert, err = c.ActivateX509(ctx, "org-1", importedID); err != nil || cert.Status != X509Active {
		t.Fatalf("activate = %+v, %v", cert, err)
	}
	if cert, err = c.DeactivateX509(ctx, "org-1", "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"); err != nil || cert.Status != X509Inactive {
		t.Fatalf("deactivate = %+v, %v", cert, err)
	}
	p.status["GET /v1/x509/org-1/"+importedID] = http.StatusNotFound
	if _, err = c.X509Certificate(ctx, "org-1", importedID); !errors.Is(err, ErrNoCertificate) {
		t.Errorf("not found = %v", err)
	}
	for _, key := range []string{"GET /v1/x509/org-1/" + importedID, "GET /v1/x509/org-1", "PUT /v1/x509/org-1/activate/" + importedID} {
		p.status[key] = http.StatusBadGateway
	}
	_, e1 := c.X509Certificate(ctx, "org-1", importedID)
	_, e2 := c.X509Certificates(ctx, "org-1", X509Active, X509KeyP256)
	_, e3 := c.ActivateX509(ctx, "org-1", importedID)
	for i, err := range []error{e1, e2, e3} {
		if err == nil || errors.Is(err, ErrNoCertificate) {
			t.Errorf("call %d = %v", i+1, err)
		}
	}
	var none *Client
	if _, err = none.X509Certificate(ctx, "org-1", importedID); !errors.Is(err, ErrNoPlatform) {
		t.Errorf("no platform = %v", err)
	}
}
