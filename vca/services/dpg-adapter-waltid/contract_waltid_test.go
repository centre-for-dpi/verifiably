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
