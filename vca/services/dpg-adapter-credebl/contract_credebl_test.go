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
		if _, delErr := a.Service.DeleteTenant(context.Background(), connect.NewRequest(&backendv1.DeleteTenantRequest{Id: id})); delErr != nil {
			t.Errorf("DeleteTenant: %v", delErr)
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

// TestContractOfferStateAndIssuedList creates an offer, reads its state
// from the issuance session, and reads the issued list of its type
// (P6-C5).
func TestContractOfferStateAndIssuedList(t *testing.T) {
	a := newContractApp(t)
	ctx := context.Background()
	subject := os.Getenv("VCA_CREDEBL_CONTRACT_SUBJECT_DATA")
	if subject == "" {
		t.Skip("set VCA_CREDEBL_CONTRACT_SUBJECT_DATA to run the offer state contract test")
	}
	list, err := a.Service.ListCredentialTypes(ctx, connect.NewRequest(&backendv1.ListCredentialTypesRequest{}))
	if err != nil || len(list.Msg.GetConfigurations()) == 0 {
		t.Skipf("the real platform has no credential template: %v", err)
	}
	config := list.Msg.GetConfigurations()[0].GetId()
	offer, err := a.Service.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{ConfigurationId: config, SubjectData: subject},
	}))
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	state, err := a.Service.GetIssuanceStatus(ctx, connect.NewRequest(&backendv1.GetIssuanceStatusRequest{OfferId: offer.Msg.GetOfferId()}))
	if err != nil {
		t.Fatalf("GetIssuanceStatus: %v", err)
	}
	if state.Msg.GetState() != backendv1.GetIssuanceStatusResponse_STATE_PENDING {
		t.Errorf("state = %v, a new offer is pending", state.Msg.GetState())
	}
	if _, listErr := a.Service.ListIssuedCredentials(ctx, connect.NewRequest(&backendv1.ListIssuedCredentialsRequest{CredentialType: config})); listErr != nil {
		t.Fatalf("ListIssuedCredentials: %v", listErr)
	}
}

// TestContractDidcommOffers makes an out of band offer of the AnonCreds
// credential definition that VCA_CREDEBL_CONTRACT_CRED_DEF names, reads
// the state of its exchange, and lists the connections (P6-C3).
func TestContractDidcommOffers(t *testing.T) {
	a := newContractApp(t)
	credDef := os.Getenv("VCA_CREDEBL_CONTRACT_CRED_DEF")
	if credDef == "" {
		t.Skip("set VCA_CREDEBL_CONTRACT_CRED_DEF to run the DIDComm offer contract test")
	}
	ctx := context.Background()
	claims := os.Getenv("VCA_CREDEBL_CONTRACT_CRED_DEF_CLAIMS")
	if claims == "" {
		t.Skip("set VCA_CREDEBL_CONTRACT_CRED_DEF_CLAIMS to the claims of the credential definition as JSON")
	}
	offer, err := a.Service.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec:    &backendv1.IssueSpec{ConfigurationId: credDef, Format: commonv1.Format_FORMAT_ANONCREDS, SubjectData: claims},
		Channel: backendv1.Channel_CHANNEL_DIDCOMM_OOB,
	}))
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	if !strings.Contains(offer.Msg.GetOfferUri(), "oob=") {
		t.Fatalf("offer = %v", offer.Msg)
	}
	state, err := a.Service.GetIssuanceStatus(ctx, connect.NewRequest(&backendv1.GetIssuanceStatusRequest{OfferId: offer.Msg.GetOfferId()}))
	if err != nil || state.Msg.GetState() != backendv1.GetIssuanceStatusResponse_STATE_PENDING {
		t.Fatalf("state = %v, %v", state, err)
	}
	if _, err := a.Service.ListConnections(ctx, connect.NewRequest(&backendv1.ListConnectionsRequest{})); err != nil {
		t.Fatalf("ListConnections: %v", err)
	}
}

// TestContractBulkImport uploads a file for the AnonCreds credential
// definition that VCA_CREDEBL_CONTRACT_CRED_DEF names, reads its
// preview, and lists the issued files. It issues nothing, so it mails
// no one. The stack needs a mail provider (P6-C4).
func TestContractBulkImport(t *testing.T) {
	env := contractEnv(t)
	credDef := os.Getenv("VCA_CREDEBL_CONTRACT_CRED_DEF")
	file := os.Getenv("VCA_CREDEBL_CONTRACT_BULK_FILE")
	if credDef == "" || file == "" {
		t.Skip("set VCA_CREDEBL_CONTRACT_CRED_DEF and VCA_CREDEBL_CONTRACT_BULK_FILE, a filled CSV file, to run the bulk contract test")
	}
	content, err := os.ReadFile(file) // #nosec G304 -- the operator names the file
	if err != nil {
		t.Fatal(err)
	}
	env.MailOffers = true
	a, err := app.Build(env, app.Deps{HTTP: &http.Client{Timeout: 30 * time.Second}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	ctx := context.Background()
	up, err := a.Service.UploadBulkFile(ctx, connect.NewRequest(&backendv1.UploadBulkFileRequest{
		ConfigurationId: credDef, Format: commonv1.Format_FORMAT_ANONCREDS, FileName: "contract.csv", Content: content,
	}))
	if err != nil {
		t.Fatalf("UploadBulkFile: %v", err)
	}
	prev, err := a.Service.PreviewBulkFile(ctx, connect.NewRequest(&backendv1.PreviewBulkFileRequest{UploadId: up.Msg.GetUploadId()}))
	if err != nil || len(prev.Msg.GetRows()) == 0 || prev.Msg.GetRows()[0].GetEmail() == "" {
		t.Fatalf("preview = %v, %v", prev, err)
	}
	if _, err := a.Service.ListBulkFiles(ctx, connect.NewRequest(&backendv1.ListBulkFilesRequest{})); err != nil {
		t.Fatalf("ListBulkFiles: %v", err)
	}
}

// TestContractDidcommProofRequest makes an out of band AnonCreds proof
// request for one attribute of the schema that
// VCA_CREDEBL_CONTRACT_PROOF_SCHEMA names, reads its state, and lists
// the proof requests and the AnonCreds schemas (P6-C6). No wallet
// answers, so the request stays pending.
func TestContractDidcommProofRequest(t *testing.T) {
	a := newContractApp(t)
	schema := os.Getenv("VCA_CREDEBL_CONTRACT_PROOF_SCHEMA")
	attribute := os.Getenv("VCA_CREDEBL_CONTRACT_PROOF_ATTRIBUTE")
	if schema == "" || attribute == "" {
		t.Skip("set VCA_CREDEBL_CONTRACT_PROOF_SCHEMA and VCA_CREDEBL_CONTRACT_PROOF_ATTRIBUTE to run the proof contract test")
	}
	ctx := context.Background()
	request := `{"name":"Contract","version":"1.0","requested_attributes":{"a":{"name":"` + attribute +
		`","restrictions":[{"schema_id":"` + schema + `"}]}},"requested_predicates":{}}`
	created, err := a.Service.CreateRequest(ctx, connect.NewRequest(&backendv1.CreateRequestRequest{AnoncredsRequest: request}))
	if err != nil || !strings.Contains(created.Msg.GetRequestUri(), "oob=") {
		t.Fatalf("CreateRequest = %v, %v", created, err)
	}
	result, err := a.Service.GetResult(ctx, connect.NewRequest(&backendv1.GetResultRequest{State: created.Msg.GetState()}))
	if err != nil || result.Msg.GetState() != backendv1.GetResultResponse_STATE_PENDING {
		t.Fatalf("GetResult = %v, %v", result, err)
	}
	if _, err := a.Service.ListProofRequests(ctx, connect.NewRequest(&backendv1.ListProofRequestsRequest{})); err != nil {
		t.Fatalf("ListProofRequests: %v", err)
	}
	schemas, err := a.Service.ListProofSchemas(ctx, connect.NewRequest(&backendv1.ListProofSchemasRequest{}))
	if err != nil || len(schemas.Msg.GetSchemas()) == 0 {
		t.Fatalf("ListProofSchemas = %v, %v", schemas, err)
	}
}
