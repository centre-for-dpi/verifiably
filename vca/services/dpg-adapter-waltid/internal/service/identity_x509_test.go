// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

// certOf signs a certificate for pub with the parent key, or self signs
// it when parent is nil. It returns the certificate and its PEM.
func certOf(t *testing.T, cn string, pub crypto.PublicKey, signer crypto.Signer, parent *x509.Certificate, from, to time.Time) (*x509.Certificate, string) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: from, NotAfter: to, IsCA: parent == nil, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// jwkRef returns a walt.id jwk key object of a private key.
func jwkRef(t *testing.T, key crypto.PrivateKey) string {
	t.Helper()
	pub, err := jose.PublicJWK(key, "")
	if err != nil {
		t.Fatal(err)
	}
	m, err := jose.JWKToMap(pub)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{"type": "jwk", "jwk": m})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestImportX509ChecksTheChain refuses a chain whose leaf does not hold
// the referenced key, a chain that does not verify, and a leaf that is
// not valid now. The CREDEBL adapter checks the same.
func TestImportX509ChecksTheChain(t *testing.T) {
	svc, _ := identityService(t, filepath.Join(t.TempDir(), "issuer.json"), "", "")
	now := time.Date(2026, 9, 25, 9, 0, 0, 0, time.UTC)
	from, to := now.AddDate(-1, 0, 0), now.AddDate(1, 0, 0)
	ecKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	caKey, leafKey, otherKey := ecKey(), ecKey(), ecKey()
	ca, caPEM := certOf(t, "Root", &caKey.PublicKey, caKey, nil, from, to)
	_, leafPEM := certOf(t, "Issuer One", &leafKey.PublicKey, caKey, ca, from, to)
	_, oldPEM := certOf(t, "Issuer One", &leafKey.PublicKey, caKey, ca, from, now.AddDate(0, -1, 0))
	_, otherCAPEM := certOf(t, "Other root", &otherKey.PublicKey, otherKey, nil, from, to)
	edPub, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edPEM := certOf(t, "Ed issuer", edPub, edKey, nil, from, to)
	signed := make([]int, len(edPub))
	for i, b := range edPub {
		signed[i] = int(int8(b))
	}
	tse, err := json.Marshal(map[string]any{"type": "tse", "server": "http://vault:8200/v1/transit", "id": "issuer-key", "_publicKey": signed, "_keyType": "Ed25519"})
	if err != nil {
		t.Fatal(err)
	}
	ref := jwkRef(t, leafKey)
	cases := map[string]struct {
		chain, ref string
		want       connect.Code
	}{
		"good chain":        {leafPEM + caPEM, ref, 0},
		"key store key":     {edPEM, string(tse), 0},
		"other key":         {leafPEM + caPEM, jwkRef(t, otherKey), connect.CodeInvalidArgument},
		"broken chain":      {leafPEM + otherCAPEM, ref, connect.CodeInvalidArgument},
		"expired leaf":      {oldPEM + caPEM, ref, connect.CodeFailedPrecondition},
		"no public key":     {leafPEM + caPEM, `{"type":"tse","server":"http://vault:8200/v1/transit","id":"issuer-key"}`, connect.CodeInvalidArgument},
		"key store foreign": {leafPEM + caPEM, string(tse), connect.CodeInvalidArgument},
	}
	for name, c := range cases {
		_, err := importIdentity(svc, &backendv1.ImportIssuerIdentityRequest{
			Subject: &backendv1.ImportIssuerIdentityRequest_X509ChainPem{X509ChainPem: c.chain}, KeyReference: c.ref,
		})
		if c.want == 0 && err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if c.want != 0 && connect.CodeOf(err) != c.want {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
}
