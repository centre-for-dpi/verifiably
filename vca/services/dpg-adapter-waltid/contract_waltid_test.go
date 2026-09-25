// SPDX-License-Identifier: Apache-2.0

//go:build contract_waltid

// This file runs against a real walt.id stack. The build tag keeps it out
// of the normal test run (ADR-004 decision 4). The script
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

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/config"
)

// contractEnv reads the URLs of the real stack. The test skips itself
// when no issuer URL is set.
func contractEnv(t *testing.T) config.Config {
	t.Helper()
	issuer := os.Getenv("VCA_WALTID_CONTRACT_ISSUER_URL")
	if issuer == "" {
		t.Skip("set VCA_WALTID_CONTRACT_ISSUER_URL to run the walt.id contract test")
	}
	return config.Config{
		IssuerURL:       issuer,
		VerifierURL:     os.Getenv("VCA_WALTID_CONTRACT_VERIFIER_URL"),
		Verifier2URL:    os.Getenv("VCA_WALTID_CONTRACT_VERIFIER2_URL"),
		WalletURL:       os.Getenv("VCA_WALTID_CONTRACT_WALLET_URL"),
		StandardVersion: envOr("VCA_WALTID_CONTRACT_STANDARD_VERSION", "draft13"),
		DpgVersion:      envOr("VCA_WALTID_CONTRACT_DPG_VERSION", "0.18.2"),
		Timeout:         30 * time.Second,
		Retries:         1,
		MaxBytes:        8 << 20,
	}
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// newContractApp wires the adapter against the real stack.
func newContractApp(t *testing.T) *app.App {
	t.Helper()
	a, err := app.Build(contractEnv(t), app.Deps{HTTP: &http.Client{Timeout: 30 * time.Second}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return a
}

func TestContractIssuerMetadata(t *testing.T) {
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

func TestContractCreateOfferForTheFirstConfiguration(t *testing.T) {
	a := newContractApp(t)
	ctx := context.Background()
	meta, err := a.Service.GetIssuerMetadata(ctx, connect.NewRequest(&backendv1.GetIssuerMetadataRequest{}))
	if err != nil {
		t.Fatalf("GetIssuerMetadata: %v", err)
	}
	var pick *backendv1.CredentialConfiguration
	for _, cfg := range meta.Msg.GetConfigurations() {
		if cfg.GetFormat() == commonv1.Format_FORMAT_JWT_VC_JSON {
			pick = cfg
			break
		}
	}
	if pick == nil {
		t.Skip("the real issuer advertises no jwt_vc_json configuration")
	}
	resp, err := a.Service.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{
			ConfigurationId: pick.GetId(),
			SubjectData:     `{"holder":"Contract test"}`,
		},
		Channel: backendv1.Channel_CHANNEL_OID4VCI_PREAUTH,
	}))
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	if !strings.HasPrefix(resp.Msg.GetOfferUri(), "openid-credential-offer://") {
		t.Fatalf("offer URI = %q", resp.Msg.GetOfferUri())
	}
}

func TestContractCreateRequestAndReadTheSession(t *testing.T) {
	cfg := contractEnv(t)
	if cfg.VerifierURL == "" {
		t.Skip("set VCA_WALTID_CONTRACT_VERIFIER_URL to run the verifier contract test")
	}
	a := newContractApp(t)
	ctx := context.Background()
	definition := `{"id":"contract","input_descriptors":[{"id":"d1",` +
		`"format":{"jwt_vc_json":{"alg":["ES256"]}},"constraints":{}}]}`
	created, err := a.Service.CreateRequest(ctx, connect.NewRequest(&backendv1.CreateRequestRequest{
		PresentationDefinition: definition,
		DpgPolicies:            []string{"signature"},
	}))
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if created.Msg.GetState() == "" {
		t.Fatal("the real verifier returned no state")
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

// TestContractDcqlRoundTrip sends a DCQL query to the real verifier-api2
// and reads the new session back. The fixtures in testdata/doc follow the
// documentation; this test proves their shape against the release.
func TestContractDcqlRoundTrip(t *testing.T) {
	cfg := contractEnv(t)
	if cfg.Verifier2URL == "" {
		t.Skip("set VCA_WALTID_CONTRACT_VERIFIER2_URL to run the verifier 2 contract test")
	}
	a := newContractApp(t)
	ctx := context.Background()
	caps, err := a.Service.GetCapabilities(ctx, connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatalf("GetCapabilities: %v", err)
	}
	listed := false
	for _, p := range caps.Msg.GetProtocols() {
		listed = listed || p == backendv1.Protocol_PROTOCOL_OID4VP_DCQL
	}
	if !listed {
		t.Fatal("the adapter does not list DCQL with verifier 2 configured")
	}
	query := `{"credentials":[{"id":"contract","format":"dc+sd-jwt","meta":{"vct_values":["https://example.org/contract"]}}]}`
	created, err := a.Service.CreateRequest(ctx, connect.NewRequest(&backendv1.CreateRequestRequest{
		Dcql: query, DpgPolicies: []string{"signature"},
	}))
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if !strings.HasPrefix(created.Msg.GetRequestUri(), "openid4vp://") {
		t.Fatalf("request URI = %q", created.Msg.GetRequestUri())
	}
	result, err := a.Service.GetResult(ctx, connect.NewRequest(&backendv1.GetResultRequest{State: created.Msg.GetState()}))
	if err != nil {
		t.Fatalf("GetResult: %v", err)
	}
	if result.Msg.GetState() != backendv1.GetResultResponse_STATE_PENDING {
		t.Fatalf("state = %v, a new session is pending", result.Msg.GetState())
	}
}

// TestContractDcApiSession starts a Digital Credentials API session of
// the real verifier-api2. The page needs a request object back.
func TestContractDcApiSession(t *testing.T) {
	cfg := contractEnv(t)
	if cfg.Verifier2URL == "" {
		t.Skip("set VCA_WALTID_CONTRACT_VERIFIER2_URL to run the verifier 2 contract test")
	}
	a := newContractApp(t)
	query := `{"credentials":[{"id":"contract","format":"dc+sd-jwt","meta":{"vct_values":["https://example.org/contract"]}}]}`
	created, err := a.Service.CreateRequest(context.Background(), connect.NewRequest(&backendv1.CreateRequestRequest{
		Dcql: query, DcApi: true, ExpectedOrigins: []string{envOr("VCA_WALTID_CONTRACT_ORIGIN", "http://localhost:17004")},
	}))
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if !strings.Contains(created.Msg.GetDcApiRequest(), "protocol") {
		t.Fatalf("the DC API request has no protocol: %q", created.Msg.GetDcApiRequest())
	}
}

// TestContractProvisionEveryMethod asks the real issuer for a key and a
// DID of each local method and key type. did:cheqd calls the public
// cheqd registrar, so it runs only with VCA_WALTID_CONTRACT_CHEQD=1. A
// key store runs with the VCA_WALTID_CONTRACT_KMS_* variables.
func TestContractProvisionEveryMethod(t *testing.T) {
	cfg := contractEnv(t)
	cfg.KMSBackend = os.Getenv("VCA_WALTID_CONTRACT_KMS_BACKEND")
	cfg.KMSServer = os.Getenv("VCA_WALTID_CONTRACT_KMS_SERVER")
	cfg.KMSToken = os.Getenv("VCA_WALTID_CONTRACT_KMS_TOKEN")
	cfg.CheqdNetwork = "testnet"
	a, err := app.Build(cfg, app.Deps{HTTP: &http.Client{Timeout: 60 * time.Second}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	caps, err := a.Service.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatalf("GetCapabilities: %v", err)
	}
	for _, method := range caps.Msg.GetDidMethods() {
		for _, keyType := range caps.Msg.GetKeyTypes() {
			if method == "did:cheqd" && (keyType != "Ed25519" || os.Getenv("VCA_WALTID_CONTRACT_CHEQD") != "1") {
				continue
			}
			res, err := a.Service.ProvisionIssuerIdentity(context.Background(), connect.NewRequest(&backendv1.ProvisionIssuerIdentityRequest{
				Method: method, KeyType: keyType, Domain: "issuer.contract.example",
			}))
			if err != nil {
				t.Errorf("%s %s: %v", method, keyType, err)
				continue
			}
			if got := res.Msg.GetIdentity().GetIdentifiers(); len(got) == 0 || !strings.HasPrefix(got[0], method+":") {
				t.Errorf("%s %s: identifiers %v", method, keyType, got)
			}
		}
	}
}
