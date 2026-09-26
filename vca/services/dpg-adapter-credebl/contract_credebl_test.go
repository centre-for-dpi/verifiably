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
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
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
		DpgVersion:   "latest",
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

// TestContractTenantLifecycle creates an organisation with a wallet in
// the shared agent and a did:key, reads it with its members, and
// deletes it (P6-C1). It needs a platform that vca dpg bootstrap
// credebl prepared, so the shared agent is bound.
func TestContractTenantLifecycle(t *testing.T) {
	a := newContractApp(t)
	if os.Getenv("VCA_CREDEBL_CONTRACT_TENANTS") == "" {
		t.Skip("set VCA_CREDEBL_CONTRACT_TENANTS to create and delete an organisation on the real platform")
	}
	ctx := context.Background()
	name := "vca-contract-" + time.Now().UTC().Format("150405")
	created, err := a.Service.CreateTenant(ctx, connect.NewRequest(&backendv1.CreateTenantRequest{Name: name}))
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	id := created.Msg.GetTenant().GetId()
	t.Cleanup(func() {
		if _, err := a.Service.DeleteTenant(context.Background(), connect.NewRequest(&backendv1.DeleteTenantRequest{Id: id})); err != nil {
			t.Errorf("DeleteTenant: %v", err)
		}
	})
	if !strings.HasPrefix(created.Msg.GetTenant().GetPrimaryDid(), "did:key:") {
		t.Errorf("tenant = %v, want a primary did:key", created.Msg.GetTenant())
	}
	got, err := a.Service.GetTenant(ctx, connect.NewRequest(&backendv1.GetTenantRequest{Id: id}))
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if got.Msg.GetTenant().GetName() != name || len(got.Msg.GetTenant().GetMembers()) == 0 {
		t.Errorf("tenant = %v, want the name and the platform admin as a member", got.Msg.GetTenant())
	}
}

// TestContractIssuerIdentity reads the DIDs of the organisation of the
// adapter (P6-C1).
func TestContractIssuerIdentity(t *testing.T) {
	a := newContractApp(t)
	res, err := a.Service.GetIssuerIdentity(context.Background(), connect.NewRequest(&backendv1.GetIssuerIdentityRequest{}))
	if err != nil {
		t.Fatalf("GetIssuerIdentity: %v", err)
	}
	for _, id := range res.Msg.GetIdentity().GetIdentifiers() {
		if !strings.HasPrefix(id, "did:") {
			t.Errorf("identifier %q is not a DID", id)
		}
	}
}

// TestContractSchemaTargets reads the ledgers and the schema formats of
// the capability answer, and writes an AnonCreds schema with its
// credential definition on the ledger that VCA_CREDEBL_CONTRACT_LEDGER
// names, when it names one (P6-C2).
func TestContractSchemaTargets(t *testing.T) {
	a := newContractApp(t)
	ctx := context.Background()
	caps, err := a.Service.GetCapabilities(ctx, connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatalf("GetCapabilities: %v", err)
	}
	if len(caps.Msg.GetSchemaFormats()) == 0 {
		t.Fatal("the answer lists no schema format")
	}
	ledger := os.Getenv("VCA_CREDEBL_CONTRACT_LEDGER")
	if ledger == "" {
		t.Skip("set VCA_CREDEBL_CONTRACT_LEDGER to write an AnonCreds schema on the real ledger")
	}
	res, err := a.Service.RegisterCredentialConfiguration(ctx, connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{
		Configuration: &backendv1.CredentialConfiguration{
			Id: "ContractCheck", Format: commonv1.Format_FORMAT_ANONCREDS, Type: "ContractCheck" + time.Now().UTC().Format("150405"),
			JsonSchema: `{"type":"object","properties":{"check":{"type":"string"}},"required":["check"]}`, Ledger: ledger,
		},
	}))
	if err != nil {
		t.Fatalf("RegisterCredentialConfiguration: %v", err)
	}
	if res.Msg.GetId() == "" {
		t.Fatal("the answer carries no credential definition id")
	}
}
