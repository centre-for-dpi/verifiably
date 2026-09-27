// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/service"
)

// P6-C9: the X.509 issuer identity of an organisation (ADR-068).

// testChain reads the chain of the recorded certificate, leaf first.
func testChain(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(testdata, "doc", "x509-chain.pem")) // #nosec G304 -- a fixed test path
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// otherCertificate makes a self-signed certificate that the platform
// does not keep.
func otherCertificate(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "[OTHER ISSUER]"},
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// certificateRef is the key reference of the imported certificate.
const certificateRef = `{"certificateId":"` + fake.ImportedCertificateID + `"}`

// TestImportX509Certificate is P6-C9: the agent keeps the key of each
// certificate of the organisation, so the key reference names a
// certificate row of the platform. The leaf of the chain must be the
// certificate of that row. The adapter takes the older active
// certificate of the key type out of use, activates the row, and keeps
// the chain, so the identity shows the subject and the x5c chain. The
// answer lists the X.509 import, and the DID import stays out.
func TestImportX509Certificate(t *testing.T) {
	svc, f := newService(t, nil)
	ctx := context.Background()
	chain := testChain(t)
	res, err := svc.ImportIssuerIdentity(ctx, connect.NewRequest(&backendv1.ImportIssuerIdentityRequest{
		Subject: &backendv1.ImportIssuerIdentityRequest_X509ChainPem{X509ChainPem: chain}, KeyReference: certificateRef,
	}))
	if err != nil {
		t.Fatalf("ImportIssuerIdentity: %v", err)
	}
	id := res.Msg.GetIdentity()
	if ids := id.GetIdentifiers(); len(id.GetX5C()) != 2 || len(ids) == 0 || ids[len(ids)-1] != "CN=[ISSUER],O=[ORGANISATION]" || id.GetKey().GetType() == "" {
		t.Fatalf("identity = %+v", id)
	}
	block, _ := pem.Decode([]byte(chain))
	if id.GetX5C()[0] != base64.StdEncoding.EncodeToString(block.Bytes) {
		t.Error("x5c does not start with the leaf")
	}
	calls := f.Calls()
	deactivate := slices.Index(calls, "PUT /v1/x509/org-1/deactivate/"+fake.OlderCertificateID)
	activate := -1
	for i, c := range calls {
		if c == "PUT /v1/x509/org-1/activate/"+fake.ImportedCertificateID {
			activate = i
		}
	}
	if deactivate < 0 || activate < deactivate {
		t.Errorf("calls = %v, want the older certificate out of use before the activation", calls)
	}
	got, err := svc.GetIssuerIdentity(ctx, connect.NewRequest(&backendv1.GetIssuerIdentityRequest{}))
	if err != nil || len(got.Msg.GetIdentity().GetX5C()) != 2 {
		t.Fatalf("GetIssuerIdentity = %+v, %v", got, err)
	}
	if _, err = svc.ImportIssuerIdentity(ctx, connect.NewRequest(&backendv1.ImportIssuerIdentityRequest{
		Subject: &backendv1.ImportIssuerIdentityRequest_X509ChainPem{X509ChainPem: chain}, KeyReference: certificateRef,
	})); err != nil {
		t.Errorf("a second import of the active certificate = %v", err)
	}
	caps, err := svc.GetCapabilities(ctx, connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(caps.Msg.GetFeatures(), backendv1.Feature_FEATURE_ISSUER_IDENTITY_IMPORT_X509) ||
		slices.Contains(caps.Msg.GetFeatures(), backendv1.Feature_FEATURE_ISSUER_IDENTITY_IMPORT_DID) {
		t.Errorf("features = %v", caps.Msg.GetFeatures())
	}
}

// TestImportX509Refusals is P6-C9: the adapter refuses a chain that is
// no PEM, a chain that does not verify, a key reference that names no
// certificate, a leaf that differs from the certificate of the row, and
// an unknown row. A row that the platform took out of use leaves the
// identity.
func TestImportX509Refusals(t *testing.T) {
	svc, f := newService(t, nil)
	ctx := context.Background()
	chain := testChain(t)
	leaf, _ := pem.Decode([]byte(chain))
	leafPEM := string(pem.EncodeToMemory(leaf))
	for name, c := range map[string]struct {
		chain, ref string
		want       connect.Code
		text       string
	}{
		"no pem":          {"not a certificate", certificateRef, connect.CodeInvalidArgument, "PEM"},
		"no reference":    {chain, `{"keyId":"k"}`, connect.CodeInvalidArgument, "certificateId"},
		"bad reference":   {chain, `[`, connect.CodeInvalidArgument, "certificateId"},
		"broken chain":    {leafPEM + otherCertificate(t), certificateRef, connect.CodeInvalidArgument, "chain"},
		"other leaf":      {otherCertificate(t), certificateRef, connect.CodeInvalidArgument, "leaf"},
		"unknown row":     {chain, `{"certificateId":"00000000-0000-4000-8000-000000000000"}`, connect.CodeNotFound, "certificate"},
		"expired at time": {chain, certificateRef, connect.CodeFailedPrecondition, "valid"},
	} {
		s := svc
		if name == "expired at time" {
			s, _ = newService(t, withNow(time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)))
		}
		_, err := s.ImportIssuerIdentity(ctx, connect.NewRequest(&backendv1.ImportIssuerIdentityRequest{
			Subject: &backendv1.ImportIssuerIdentityRequest_X509ChainPem{X509ChainPem: c.chain}, KeyReference: c.ref,
		}))
		if connect.CodeOf(err) != c.want || !strings.Contains(err.Error(), c.text) {
			t.Errorf("%s: err = %v, want %v with %q", name, err, c.want, c.text)
		}
	}
	_, err := svc.ImportIssuerIdentity(ctx, connect.NewRequest(&backendv1.ImportIssuerIdentityRequest{
		Subject: &backendv1.ImportIssuerIdentityRequest_Did{Did: "did:web:issuer.example"},
	}))
	wantCode(t, err, connect.CodeUnimplemented)
	if _, err = svc.ImportIssuerIdentity(ctx, connect.NewRequest(&backendv1.ImportIssuerIdentityRequest{
		Subject: &backendv1.ImportIssuerIdentityRequest_X509ChainPem{X509ChainPem: chain}, KeyReference: certificateRef,
	})); err != nil {
		t.Fatal(err)
	}
	// The platform takes the certificate out of use: the identity drops
	// the chain.
	if status := deactivate(t, f, fake.ImportedCertificateID); status != http.StatusOK {
		t.Fatalf("deactivate = %d", status)
	}
	got, err := svc.GetIssuerIdentity(ctx, connect.NewRequest(&backendv1.GetIssuerIdentityRequest{}))
	if err != nil || len(got.Msg.GetIdentity().GetX5C()) != 0 {
		t.Errorf("identity after the deactivation = %+v, %v", got, err)
	}
	f.SetStatus("/v1/x509/org-1/"+fake.ImportedCertificateID, http.StatusBadGateway)
	if _, err = svc.GetIssuerIdentity(ctx, connect.NewRequest(&backendv1.GetIssuerIdentityRequest{})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Errorf("a failed read = %v", err)
	}
	f.SetStatus("/v1/x509/org-1/activate/"+fake.ImportedCertificateID, http.StatusBadGateway)
	if _, err = svc.ImportIssuerIdentity(ctx, connect.NewRequest(&backendv1.ImportIssuerIdentityRequest{
		Subject: &backendv1.ImportIssuerIdentityRequest_X509ChainPem{X509ChainPem: chain}, KeyReference: certificateRef,
	})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Errorf("a failed activation = %v", err)
	}
}

// deactivate takes one certificate row out of use at the fake, as an
// admin of the platform does.
func deactivate(t *testing.T, f *fake.Server, id string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, f.URL()+"/v1/x509/org-1/deactivate/"+id, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := f.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if cerr := resp.Body.Close(); cerr != nil {
		t.Error(cerr)
	}
	return resp.StatusCode
}

// withNow sets the clock of the service.
func withNow(at time.Time) func(*service.Options) {
	return func(o *service.Options) { o.Now = func() time.Time { return at } }
}
