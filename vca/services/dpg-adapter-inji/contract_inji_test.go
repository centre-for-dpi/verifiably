// SPDX-License-Identifier: Apache-2.0

//go:build contract_inji

// This file runs against a real Inji deployment. The build tag keeps it
// out of the normal test run (ADR-004 decision 4). The script
// hack/contract-tests.sh runs it in the nightly job.
package main

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/ingest"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/config"
)

// contractEnv reads the URLs of the real deployment. The test skips
// itself when no Inji Certify URL is set.
func contractEnv(t *testing.T) config.Config {
	t.Helper()
	certify := os.Getenv("VCA_INJI_CONTRACT_CERTIFY_URL")
	verify := os.Getenv("VCA_INJI_CONTRACT_VERIFY_URL")
	if certify == "" && verify == "" {
		t.Skip("set VCA_INJI_CONTRACT_CERTIFY_URL to run the Inji contract test")
	}
	return config.Config{
		CertifyURL:     certify,
		VerifyURL:      verify,
		MetadataPath:   envOr("VCA_INJI_CONTRACT_METADATA_PATH", "/v1/certify/issuance/.well-known/openid-credential-issuer"),
		VerifyClientID: os.Getenv("VCA_INJI_CONTRACT_VERIFY_CLIENT_ID"),
		DpgVersion:     envOr("VCA_INJI_CONTRACT_DPG_VERSION", "0.14.0"),
		PublicURL:      os.Getenv("VCA_INJI_CONTRACT_PUBLIC_URL"),
		Timeout:        30 * time.Second,
		Retries:        1,
		MaxBytes:       8 << 20,
		OfferTTL:       15 * time.Minute,
	}
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// newContractApp wires the adapter against the real deployment.
func newContractApp(t *testing.T) *app.App {
	t.Helper()
	a, err := app.Build(contractEnv(t), app.Deps{HTTP: &http.Client{Timeout: 30 * time.Second}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return a
}

func TestContractIssuerMetadata(t *testing.T) {
	if contractEnv(t).CertifyURL == "" {
		t.Skip("set VCA_INJI_CONTRACT_CERTIFY_URL to run the issuer contract test")
	}
	a := newContractApp(t)
	resp, err := a.Service.GetIssuerMetadata(context.Background(),
		connect.NewRequest(&backendv1.GetIssuerMetadataRequest{}))
	if err != nil {
		t.Fatalf("GetIssuerMetadata: %v", err)
	}
	if resp.Msg.GetIssuer() == "" {
		t.Fatal("the real issuer returned no identifier")
	}
	if len(resp.Msg.GetConfigurations()) == 0 {
		t.Fatal("the real issuer advertises no credential configuration")
	}
}

func TestContractIssueThroughThePreAuthorizedFlow(t *testing.T) {
	cfg := contractEnv(t)
	if cfg.CertifyURL == "" {
		t.Skip("set VCA_INJI_CONTRACT_CERTIFY_URL to run the issuer contract test")
	}
	configurationID := os.Getenv("VCA_INJI_CONTRACT_CONFIGURATION_ID")
	subject := os.Getenv("VCA_INJI_CONTRACT_SUBJECT_DATA")
	if configurationID == "" || subject == "" {
		t.Skip("set VCA_INJI_CONTRACT_CONFIGURATION_ID and VCA_INJI_CONTRACT_SUBJECT_DATA")
	}
	a := newContractApp(t)
	resp, err := a.Service.Issue(context.Background(), connect.NewRequest(&backendv1.IssueRequest{
		Spec: &backendv1.IssueSpec{ConfigurationId: configurationID, SubjectData: subject},
	}))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(resp.Msg.GetCredential().GetPayload()) == 0 {
		t.Fatal("the real issuer returned no credential")
	}
}

func TestContractCreateRequestAndReadTheResult(t *testing.T) {
	cfg := contractEnv(t)
	if cfg.VerifyURL == "" {
		t.Skip("set VCA_INJI_CONTRACT_VERIFY_URL to run the verifier contract test")
	}
	a := newContractApp(t)
	ctx := context.Background()
	definition := `{"id":"contract","input_descriptors":[{"id":"d1",` +
		`"format":{"ldp_vc":{"proof_type":["Ed25519Signature2020"]}},` +
		`"constraints":{"fields":[{"path":["$.credentialSubject.fullName"]}]}}]}`
	created, err := a.Service.CreateRequest(ctx, connect.NewRequest(&backendv1.CreateRequestRequest{
		PresentationDefinition: definition,
	}))
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if !strings.HasPrefix(created.Msg.GetRequestUri(), "openid4vp://") {
		t.Fatalf("request URI = %q", created.Msg.GetRequestUri())
	}
	result, err := a.Service.GetResult(ctx, connect.NewRequest(&backendv1.GetResultRequest{
		State: created.Msg.GetState(),
	}))
	if err != nil {
		t.Fatalf("GetResult: %v", err)
	}
	if result.Msg.GetState() != backendv1.GetResultResponse_STATE_PENDING {
		t.Fatalf("state = %v, a new transaction is pending", result.Msg.GetState())
	}
}

// writeEnv skips a contract case that changes the real stack unless the
// nightly job allows writes.
func writeEnv(t *testing.T) config.Config {
	t.Helper()
	cfg := contractEnv(t)
	if cfg.CertifyURL == "" || os.Getenv("VCA_INJI_CONTRACT_WRITE") == "" {
		t.Skip("set VCA_INJI_CONTRACT_CERTIFY_URL and VCA_INJI_CONTRACT_WRITE to run a contract case that writes")
	}
	return cfg
}

// TestContractRegisterConfiguration creates a configuration through the
// configuration API, replaces it, and finds it in the issuer metadata.
func TestContractRegisterConfiguration(t *testing.T) {
	writeEnv(t)
	a := newContractApp(t)
	ctx := context.Background()
	id := "VcaContract" + time.Now().UTC().Format("20060102150405")
	cfg := &backendv1.CredentialConfiguration{
		Id: id, Format: commonv1.Format_FORMAT_LDP_VC, Type: id,
		JsonSchema: `{"type":"object","properties":{"fullName":{"type":"string"}}}`,
		Display:    `[{"name":"VCA contract","locale":"en"}]`,
	}
	for i := 0; i < 2; i++ {
		resp, err := a.Service.RegisterCredentialConfiguration(ctx,
			connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{Configuration: cfg}))
		if err != nil {
			t.Fatalf("register %d: %v", i, err)
		}
		if resp.Msg.GetId() != id {
			t.Fatalf("register %d: id = %q", i, resp.Msg.GetId())
		}
	}
	meta, err := a.Service.GetIssuerMetadata(ctx, connect.NewRequest(&backendv1.GetIssuerMetadataRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range meta.Msg.GetConfigurations() {
		if c.GetId() == id {
			return
		}
	}
	t.Fatalf("the issuer metadata does not list %s", id)
}

// ledgerEnv reads the ledger search of the contract run.
func ledgerEnv(t *testing.T) *backendv1.ListIssuedCredentialsRequest {
	t.Helper()
	typ, attr, value := os.Getenv("VCA_INJI_CONTRACT_LEDGER_TYPE"), os.Getenv("VCA_INJI_CONTRACT_LEDGER_ATTRIBUTE"),
		os.Getenv("VCA_INJI_CONTRACT_LEDGER_VALUE")
	if contractEnv(t).CertifyURL == "" || typ == "" || attr == "" || value == "" {
		t.Skip("set VCA_INJI_CONTRACT_LEDGER_TYPE, _ATTRIBUTE, and _VALUE to run the ledger contract case")
	}
	return &backendv1.ListIssuedCredentialsRequest{CredentialType: typ, Attributes: map[string]string{attr: value}}
}

// TestContractLedgerSearch finds issued credentials in the Certify
// ledger by type and one indexed attribute.
func TestContractLedgerSearch(t *testing.T) {
	req := ledgerEnv(t)
	a := newContractApp(t)
	resp, err := a.Service.ListIssuedCredentials(context.Background(), connect.NewRequest(req))
	if err != nil {
		t.Fatalf("ListIssuedCredentials: %v", err)
	}
	for _, e := range resp.Msg.GetCredentials() {
		if e.GetCredentialId() == "" || e.GetIssuedAt() == nil {
			t.Fatalf("a ledger entry without an id or a time: %v", e)
		}
	}
}

// TestContractRevokeLedgerCredential revokes the first credential the
// ledger search finds. It needs writes, since a revoke is final.
func TestContractRevokeLedgerCredential(t *testing.T) {
	writeEnv(t)
	req := ledgerEnv(t)
	a := newContractApp(t)
	ctx := context.Background()
	resp, err := a.Service.ListIssuedCredentials(ctx, connect.NewRequest(req))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Msg.GetCredentials()) == 0 {
		t.Skip("the ledger holds no credential for the search")
	}
	e := resp.Msg.GetCredentials()[0]
	if _, err := a.Service.Revoke(ctx, connect.NewRequest(&backendv1.RevokeRequest{
		CredentialId: e.GetCredentialId(), Status: e.GetStatus(), Reason: "contract",
	})); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
}

// TestContractIssueMdoc registers an mDL configuration and issues one
// credential of it. It needs writes.
func TestContractIssueMdoc(t *testing.T) {
	writeEnv(t)
	a := newContractApp(t)
	ctx := context.Background()
	id := "VcaContractMdl" + time.Now().UTC().Format("20060102150405")
	if _, err := a.Service.RegisterCredentialConfiguration(ctx, connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{
		Configuration: &backendv1.CredentialConfiguration{
			Id: id, Format: commonv1.Format_FORMAT_MSO_MDOC, Type: "org.iso.18013.5.1.mDL",
			JsonSchema: `{"type":"object","properties":{"family_name":{"type":"string"},"given_name":{"type":"string"}}}`,
		},
	})); err != nil {
		t.Fatalf("register: %v", err)
	}
	resp, err := a.Service.Issue(ctx, connect.NewRequest(&backendv1.IssueRequest{Spec: &backendv1.IssueSpec{
		ConfigurationId: id, SubjectData: `{"family_name":"Njeri","given_name":"Wanjiku"}`,
	}}))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if resp.Msg.GetCredential().GetFormat() != commonv1.Format_FORMAT_MSO_MDOC {
		t.Fatalf("format = %v", resp.Msg.GetCredential().GetFormat())
	}
}

// TestContractVerifyCredential checks a credential through the credential
// check of Inji Verify. The nightly job names a file that holds one.
func TestContractVerifyCredential(t *testing.T) {
	cfg := contractEnv(t)
	path := os.Getenv("VCA_INJI_CONTRACT_CREDENTIAL_FILE")
	if cfg.VerifyURL == "" || path == "" {
		t.Skip("set VCA_INJI_CONTRACT_VERIFY_URL and VCA_INJI_CONTRACT_CREDENTIAL_FILE to run the credential check")
	}
	payload, err := os.ReadFile(path) //nolint:gosec // G304: the nightly job names the file
	if err != nil {
		t.Fatal(err)
	}
	a := newContractApp(t)
	resp, err := a.Service.VerifyCredential(context.Background(), connect.NewRequest(&backendv1.VerifyCredentialRequest{Payload: payload}))
	if err != nil {
		t.Fatalf("VerifyCredential: %v", err)
	}
	if len(resp.Msg.GetDpgChecks()) == 0 {
		t.Fatal("the answer holds no check")
	}
}

// TestContractIssuerIdentity reads the did:web and the signing key of a
// real Certify.
func TestContractIssuerIdentity(t *testing.T) {
	if contractEnv(t).CertifyURL == "" {
		t.Skip("set VCA_INJI_CONTRACT_CERTIFY_URL to run the identity contract case")
	}
	a := newContractApp(t)
	resp, err := a.Service.GetIssuerIdentity(context.Background(), connect.NewRequest(&backendv1.GetIssuerIdentityRequest{}))
	if err != nil {
		t.Fatalf("GetIssuerIdentity: %v", err)
	}
	if ids := resp.Msg.GetIdentity().GetIdentifiers(); len(ids) == 0 || !strings.HasPrefix(ids[0], "did:web:") {
		t.Fatalf("identifiers = %v", ids)
	}
}

// TestContractProvisionIdentity asks the real key manager for the key of
// one type. It needs writes, since the key manager may make a key.
func TestContractProvisionIdentity(t *testing.T) {
	writeEnv(t)
	a := newContractApp(t)
	if _, err := a.Service.ProvisionIssuerIdentity(context.Background(), connect.NewRequest(&backendv1.ProvisionIssuerIdentityRequest{
		Method: "did:web", KeyType: "Ed25519",
	})); err != nil {
		t.Fatalf("ProvisionIssuerIdentity: %v", err)
	}
}

// TestContractIdentityQR registers a configuration with identity claims
// and issues one credential of it. Certify signs a Claim 169 QR code per
// the QR code specification 1.1.0, and the ingest decoder reads it. It
// needs writes.
func TestContractIdentityQR(t *testing.T) {
	writeEnv(t)
	a := newContractApp(t)
	ctx := context.Background()
	id := "VcaContractIdentity" + time.Now().UTC().Format("20060102150405")
	if _, err := a.Service.RegisterCredentialConfiguration(ctx, connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{
		Configuration: &backendv1.CredentialConfiguration{
			Id: id, Format: commonv1.Format_FORMAT_LDP_VC, Type: id,
			JsonSchema: `{"type":"object","properties":{"fullName":{"type":"string"},"dateOfBirth":{"type":"string"}}}`,
		},
	})); err != nil {
		t.Fatalf("register: %v", err)
	}
	resp, err := a.Service.Issue(ctx, connect.NewRequest(&backendv1.IssueRequest{Spec: &backendv1.IssueSpec{
		ConfigurationId: id, SubjectData: `{"fullName":"Wanjiku Njeri","dateOfBirth":"1987-04-12"}`,
	}}))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cwt, _, err := ingest.DecodeClaim169(resp.Msg.GetClaim169Qr())
	if err != nil {
		t.Fatalf("the identity QR does not decode: %v", err)
	}
	if cwt.Data["4"] != "Wanjiku Njeri" {
		t.Fatalf("claim 169 = %v", cwt.Data)
	}
}
