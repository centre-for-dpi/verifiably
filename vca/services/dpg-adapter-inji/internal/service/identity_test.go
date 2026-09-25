// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

// readPEM reads a certificate chain of the documented fixtures.
func readPEM(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(testdata + "/doc/" + name) //nolint:gosec // G304: a fixed fixture name
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestGetIdentityReadsDidDocument returns the did:web of Certify with its
// document, the certificate of the signing key, and the key type. The
// stack keeps the key.
func TestGetIdentityReadsDidDocument(t *testing.T) {
	svc, f := newService(t, both)
	res, err := svc.GetIssuerIdentity(context.Background(), connect.NewRequest(&backendv1.GetIssuerIdentityRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	id := res.Msg.GetIdentity()
	if len(id.GetIdentifiers()) != 2 || id.GetIdentifiers()[0] != "did:web:certify.inji.example" ||
		!strings.Contains(id.GetIdentifiers()[1], "CN=www.example.com") {
		t.Fatalf("identifiers %v", id.GetIdentifiers())
	}
	if !strings.Contains(id.GetDidDocument(), "Ed25519VerificationKey2020") || len(id.GetX5C()) != 1 {
		t.Fatalf("document or chain missing: %v", id)
	}
	if id.GetKey().GetType() != "Ed25519" || id.GetKey().GetBackend() != "certify-keymanager" {
		t.Fatalf("key %v", id.GetKey())
	}
	if q := f.Query("/v1/certify/system-info/certificate"); q.Get("applicationId") != "CERTIFY_VC_SIGN_ED25519" || q.Get("referenceId") != "ED25519_SIGN" {
		t.Fatalf("certificate query %v", q)
	}
	f.SetStatus("/v1/certify/system-info/certificate", 500)
	res, err = svc.GetIssuerIdentity(context.Background(), connect.NewRequest(&backendv1.GetIssuerIdentityRequest{}))
	if err != nil || len(res.Msg.GetIdentity().GetX5C()) != 0 || len(res.Msg.GetIdentity().GetIdentifiers()) != 1 {
		t.Fatalf("a failed certificate call still gives the DID: %v %v", res, err)
	}
	f.SetStatus("/v1/certify/.well-known/did.json", 503)
	_, err = svc.GetIssuerIdentity(context.Background(), connect.NewRequest(&backendv1.GetIssuerIdentityRequest{}))
	wantCode(t, err, connect.CodeUnavailable)
	verifier, _ := newService(t, roles{verify: true})
	_, err = verifier.GetIssuerIdentity(context.Background(), connect.NewRequest(&backendv1.GetIssuerIdentityRequest{}))
	wantCode(t, err, connect.CodeUnimplemented)
}

// TestProvisionGeneratesKey asks the key manager of Certify for the key
// of the chosen type, which it makes when it has none, and keeps the
// organisation of the request.
func TestProvisionGeneratesKey(t *testing.T) {
	svc, f := newService(t, both)
	ctx := context.Background()
	res, err := svc.ProvisionIssuerIdentity(ctx, connect.NewRequest(&backendv1.ProvisionIssuerIdentityRequest{
		Method: "did:web", KeyType: "secp256r1", DisplayName: "Ministry of Agriculture", LegalIdentifier: "KE-MOA-001",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if q := f.Query("/v1/certify/system-info/certificate"); q.Get("applicationId") != "CERTIFY_VC_SIGN_EC_R1" || q.Get("referenceId") != "EC_SECP256R1_SIGN" {
		t.Fatalf("the key manager took %v", q)
	}
	id := res.Msg.GetIdentity()
	if id.GetKey().GetType() != "secp256r1" || id.GetMetadata().GetDisplayName() != "Ministry of Agriculture" || len(id.GetX5C()) != 1 {
		t.Fatalf("identity %v", id)
	}
	got, err := svc.GetIssuerIdentity(ctx, connect.NewRequest(&backendv1.GetIssuerIdentityRequest{}))
	if err != nil || got.Msg.GetIdentity().GetMetadata().GetLegalIdentifier() != "KE-MOA-001" {
		t.Fatalf("the organisation is not kept: %v %v", got, err)
	}
	for _, bad := range []*backendv1.ProvisionIssuerIdentityRequest{{Method: "did:key", KeyType: "Ed25519"}, {Method: "did:web", KeyType: "P-521"}} {
		_, perr := svc.ProvisionIssuerIdentity(ctx, connect.NewRequest(bad))
		wantCode(t, perr, connect.CodeInvalidArgument)
	}
	f.SetStatus("/v1/certify/system-info/certificate", 503)
	_, err = svc.ProvisionIssuerIdentity(ctx, connect.NewRequest(&backendv1.ProvisionIssuerIdentityRequest{Method: "did:web", KeyType: "Ed25519"}))
	wantCode(t, err, connect.CodeUnavailable)
}

// TestImportUploadsCertificate uploads the CA of a chain to the trust
// store of Certify and the leaf onto the key it names. A leaf of another
// key fails with the reason of the key manager.
func TestImportUploadsCertificate(t *testing.T) {
	svc, f := newService(t, both)
	ctx := context.Background()
	ref := `{"applicationId":"CERTIFY_VC_SIGN_ED25519","referenceId":"ED25519_SIGN"}`
	res, err := svc.ImportIssuerIdentity(ctx, connect.NewRequest(&backendv1.ImportIssuerIdentityRequest{
		Subject:      &backendv1.ImportIssuerIdentityRequest_X509ChainPem{X509ChainPem: readPEM(t, "x509-chain.pem")},
		KeyReference: ref, DisplayName: "Ministry of Agriculture",
	}))
	if err != nil {
		t.Fatal(err)
	}
	id := res.Msg.GetIdentity()
	if len(id.GetX5C()) != 2 || !slices.ContainsFunc(id.GetIdentifiers(), func(s string) bool { return strings.Contains(s, "CN=Farmer Registry Issuer") }) {
		t.Fatalf("identity %v", id)
	}
	var ca struct {
		Request struct {
			CertificateData string `json:"certificateData"`
			PartnerDomain   string `json:"partnerDomain"`
		} `json:"request"`
	}
	if rerr := f.RequestJSON("/v1/certify/system-info/upload-ca-certificate", &ca); rerr != nil {
		t.Fatal(rerr)
	}
	if ca.Request.PartnerDomain != "DEVICE" || !strings.Contains(ca.Request.CertificateData, "BEGIN CERTIFICATE") {
		t.Fatalf("the CA upload %+v", ca)
	}
	var leaf struct {
		Request struct {
			ApplicationID   string `json:"applicationId"`
			ReferenceID     string `json:"referenceId"`
			CertificateData string `json:"certificateData"`
		} `json:"request"`
	}
	if rerr := f.RequestJSON("/v1/certify/system-info/uploadCertificate", &leaf); rerr != nil {
		t.Fatal(rerr)
	}
	if leaf.Request.ApplicationID != "CERTIFY_VC_SIGN_ED25519" || leaf.Request.ReferenceID != "ED25519_SIGN" {
		t.Fatalf("the leaf upload %+v", leaf)
	}

	_, err = svc.ImportIssuerIdentity(ctx, connect.NewRequest(&backendv1.ImportIssuerIdentityRequest{
		Subject:      &backendv1.ImportIssuerIdentityRequest_X509ChainPem{X509ChainPem: readPEM(t, "x509-other.pem")},
		KeyReference: ref,
	}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	if !strings.Contains(err.Error(), "KER-KMS-014") {
		t.Errorf("the reason is lost: %v", err)
	}
	for _, bad := range []*backendv1.ImportIssuerIdentityRequest{
		{Subject: &backendv1.ImportIssuerIdentityRequest_X509ChainPem{X509ChainPem: "not pem"}, KeyReference: ref},
		{Subject: &backendv1.ImportIssuerIdentityRequest_X509ChainPem{X509ChainPem: readPEM(t, "x509-chain.pem")}, KeyReference: "ED25519_SIGN"},
		{Subject: &backendv1.ImportIssuerIdentityRequest_X509ChainPem{X509ChainPem: readPEM(t, "x509-chain.pem")}, KeyReference: `{"referenceId":"x"}`},
	} {
		_, ierr := svc.ImportIssuerIdentity(ctx, connect.NewRequest(bad))
		wantCode(t, ierr, connect.CodeInvalidArgument)
	}
	_, err = svc.ImportIssuerIdentity(ctx, connect.NewRequest(&backendv1.ImportIssuerIdentityRequest{
		Subject: &backendv1.ImportIssuerIdentityRequest_Did{Did: "did:web:issuer.example"}, KeyReference: ref,
	}))
	wantCode(t, err, connect.CodeUnimplemented)
	f.SetStatus("/v1/certify/system-info/upload-ca-certificate", 503)
	_, err = svc.ImportIssuerIdentity(ctx, connect.NewRequest(&backendv1.ImportIssuerIdentityRequest{
		Subject:      &backendv1.ImportIssuerIdentityRequest_X509ChainPem{X509ChainPem: readPEM(t, "x509-chain.pem")},
		KeyReference: ref,
	}))
	wantCode(t, err, connect.CodeUnavailable)
}

// TestIdentityFeaturesAndPluginsListed lists provision and X.509 import,
// never DID import, the did:web method, the key types of the key alias
// mapper, and the plugins of Certify in the DPG information.
func TestIdentityFeaturesAndPluginsListed(t *testing.T) {
	svc, _ := newServiceWith(t, both, func(o *serviceOptions) { o.Plugins = []string{"MockCSVDataProviderPlugin"} })
	caps, err := svc.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	m := caps.Msg
	if !slices.Contains(m.GetFeatures(), backendv1.Feature_FEATURE_ISSUER_IDENTITY_PROVISION) ||
		!slices.Contains(m.GetFeatures(), backendv1.Feature_FEATURE_ISSUER_IDENTITY_IMPORT_X509) ||
		slices.Contains(m.GetFeatures(), backendv1.Feature_FEATURE_ISSUER_IDENTITY_IMPORT_DID) {
		t.Fatalf("features %v", m.GetFeatures())
	}
	if !slices.Equal(m.GetDidMethods(), []string{"did:web"}) || !slices.Equal(m.GetKeyTypes(), []string{"Ed25519", "secp256r1", "secp256k1", "RSA"}) {
		t.Fatalf("methods %v, key types %v", m.GetDidMethods(), m.GetKeyTypes())
	}
	if !slices.Equal(m.GetDpgInfo().GetPlugins(), []string{"MockCSVDataProviderPlugin"}) {
		t.Fatalf("plugins %v", m.GetDpgInfo().GetPlugins())
	}
	verifier, _ := newService(t, roles{verify: true})
	caps, err = verifier.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil || len(caps.Msg.GetDpgInfo().GetPlugins()) != 0 || len(caps.Msg.GetDidMethods()) != 0 {
		t.Fatalf("a verifier only adapter names issuer plugins: %v", caps.Msg)
	}
}
