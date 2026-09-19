// SPDX-License-Identifier: Apache-2.0

//go:build contract_credebl

// This file runs against a real CREDEBL platform. The build tag keeps it
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

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/config"
)

// contractEnv reads the settings of the real platform. The test skips
// itself when no api gateway URL is set.
func contractEnv(t *testing.T) config.Config {
	t.Helper()
	api := os.Getenv("VCA_CREDEBL_CONTRACT_API_URL")
	if api == "" {
		t.Skip("set VCA_CREDEBL_CONTRACT_API_URL to run the CREDEBL contract test")
	}
	return config.Config{
		APIURL:       api,
		Email:        os.Getenv("VCA_CREDEBL_CONTRACT_EMAIL"),
		Password:     os.Getenv("VCA_CREDEBL_CONTRACT_PASSWORD"),
		CryptoKey:    os.Getenv("VCA_CREDEBL_CONTRACT_CRYPTO_KEY"),
		OrgID:        os.Getenv("VCA_CREDEBL_CONTRACT_ORG_ID"),
		IssuerID:     os.Getenv("VCA_CREDEBL_CONTRACT_ISSUER_ID"),
		VerifierID:   os.Getenv("VCA_CREDEBL_CONTRACT_VERIFIER_ID"),
		VerifierName: "verifiable-credentials-adapters-contract",
		PublicURL:    os.Getenv("VCA_CREDEBL_CONTRACT_PUBLIC_URL"),
		InternalURL:  os.Getenv("VCA_CREDEBL_CONTRACT_INTERNAL_URL"),
		DpgVersion:   "2.x",
		Timeout:      30 * time.Second,
		Retries:      1,
		MaxBytes:     8 << 20,
	}
}

// newContractApp wires the adapter against the real platform.
func newContractApp(t *testing.T) *app.App {
	t.Helper()
	a, err := app.Build(contractEnv(t), app.Deps{HTTP: &http.Client{Timeout: 30 * time.Second}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return a
}

func TestContractListCredentialTypes(t *testing.T) {
	a := newContractApp(t)
	resp, err := a.Service.ListCredentialTypes(context.Background(),
		connect.NewRequest(&backendv1.ListCredentialTypesRequest{}))
	if err != nil {
		t.Fatalf("ListCredentialTypes: %v", err)
	}
	if resp.Msg.GetPage() == nil {
		t.Fatal("the answer carries no page")
	}
}

func TestContractCreateOfferForTheFirstTemplate(t *testing.T) {
	a := newContractApp(t)
	ctx := context.Background()
	list, err := a.Service.ListCredentialTypes(ctx,
		connect.NewRequest(&backendv1.ListCredentialTypesRequest{}))
	if err != nil {
		t.Fatalf("ListCredentialTypes: %v", err)
	}
	if len(list.Msg.GetConfigurations()) == 0 {
		t.Skip("the real platform has no credential template")
	}
	subject := os.Getenv("VCA_CREDEBL_CONTRACT_SUBJECT_DATA")
	if subject == "" {
		t.Skip("set VCA_CREDEBL_CONTRACT_SUBJECT_DATA to run the offer contract test")
	}
	resp, err := a.Service.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{
			ConfigurationId: list.Msg.GetConfigurations()[0].GetId(),
			SubjectData:     subject,
		},
	}))
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	if !strings.HasPrefix(resp.Msg.GetOfferUri(), "openid-credential-offer://") {
		t.Fatalf("offer URI = %q", resp.Msg.GetOfferUri())
	}
}

func TestContractCreateRequestAndReadTheResult(t *testing.T) {
	a := newContractApp(t)
	ctx := context.Background()
	query := `{"credentials":[{"id":"vc-1","format":"dc+sd-jwt",` +
		`"claims":[{"path":["fullName"]}]}]}`
	created, err := a.Service.CreateRequest(ctx,
		connect.NewRequest(&backendv1.CreateRequestRequest{Dcql: query}))
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if created.Msg.GetState() == "" {
		t.Fatal("the real platform returned no state")
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
