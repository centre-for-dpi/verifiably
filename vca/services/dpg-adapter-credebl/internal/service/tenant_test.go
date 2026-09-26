// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/fake"
)

// P6-C1 (ADR-037, ADR-046): CREDEBL organisations are the DPG tenants.
// A tenant gets a wallet in the shared agent and a did:key that the
// agent makes, so it can sign at once. The answers come from the
// platform sources in testdata/doc.

const (
	// fixtureOrg is the organisation of the answers in testdata/doc.
	fixtureOrg = "0b6c2f0e-5a38-4a1e-9d2b-3f7c1e6a9d41"
	// fixtureDid is its primary DID.
	fixtureDid = "did:key:z6MkfVKJk2cHkCvA3YVXS5Zs7J7p9vB1m3r8XyQw2eT4aLgH"
	// fixtureIndyDid is its second DID, on the BCovrin test ledger.
	fixtureIndyDid = "did:indy:bcovrin:testnet:Ra8FGb2mXsTg1d4VqVnYpS"
)

// TestCreateTenantCreatesOrg: a tenant is an organisation with a wallet
// in the shared agent and a primary did:key, in that order.
func TestCreateTenantCreatesOrg(t *testing.T) {
	svc, f := newService(t, nil)
	res, err := svc.CreateTenant(context.Background(), connect.NewRequest(&backendv1.CreateTenantRequest{Name: "[ORGANISATION]"}))
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	tenant := res.Msg.GetTenant()
	if tenant.GetId() != fixtureOrg || tenant.GetName() != "[ORGANISATION]" {
		t.Errorf("tenant = %v", tenant)
	}
	if tenant.GetAgentType() != backendv1.DpgTenant_AGENT_TYPE_SHARED {
		t.Errorf("agent type = %v, want shared", tenant.GetAgentType())
	}
	if tenant.GetPrimaryDid() != fixtureDid || len(tenant.GetDids()) == 0 {
		t.Errorf("DIDs = %v, primary %q", tenant.GetDids(), tenant.GetPrimaryDid())
	}
	var org map[string]string
	if orgErr := f.RequestJSON("/v1/orgs", &org); orgErr != nil || org["name"] != "[ORGANISATION]" {
		t.Errorf("the organisation request = %v, %v", org, orgErr)
	}
	var wallet map[string]string
	if walletErr := f.RequestJSON("/v1/orgs/"+fixtureOrg+"/agents/wallet", &wallet); walletErr != nil || wallet["label"] != "[ORGANISATION]" {
		t.Errorf("the wallet request = %v, %v", wallet, walletErr)
	}
	var did map[string]any
	if didErr := f.RequestJSON("/v1/orgs/"+fixtureOrg+"/agents/did", &did); didErr != nil {
		t.Fatalf("the DID request: %v", didErr)
	}
	if did["method"] != "key" || did["keyType"] != "ed25519" || did["isPrimaryDid"] != true {
		t.Errorf("the DID request = %v", did)
	}
	for _, secret := range []string{"seed", "privatekey"} {
		if _, ok := did[secret]; ok {
			t.Errorf("the DID request carries %s; the agent makes the key", secret)
		}
	}
	order := strings.Join(f.Calls(), "\n")
	create := strings.Index(order, "POST /v1/orgs\n")
	walletAt := strings.Index(order, "POST /v1/orgs/"+fixtureOrg+"/agents/wallet")
	didAt := strings.Index(order, "POST /v1/orgs/"+fixtureOrg+"/agents/did")
	if create < 0 || walletAt < create || didAt < walletAt {
		t.Errorf("calls out of order:\n%s", order)
	}
	_, err = svc.CreateTenant(context.Background(), connect.NewRequest(&backendv1.CreateTenantRequest{Name: " "}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

// TestCreateTenantRemovesAHalfMadeOrg: when the wallet fails, the
// organisation goes again, so no half made tenant stays.
func TestCreateTenantRemovesAHalfMadeOrg(t *testing.T) {
	svc, f := newService(t, nil)
	f.SetStatus("/v1/orgs/"+fixtureOrg+"/agents/wallet", 500)
	_, err := svc.CreateTenant(context.Background(), connect.NewRequest(&backendv1.CreateTenantRequest{Name: "[ORGANISATION]"}))
	if err == nil {
		t.Fatal("a failed wallet passed")
	}
	if !strings.Contains(strings.Join(f.Calls(), "\n"), "DELETE /v1/orgs/"+fixtureOrg) {
		t.Errorf("the half made organisation stayed: %v", f.Calls())
	}
}

// TestAgentTypeChoice: the shared agent serves the default and the
// shared choice. The stack file mounts no Docker socket, so the
// platform cannot start a dedicated agent, and the adapter says so
// before it calls the platform.
func TestAgentTypeChoice(t *testing.T) {
	for _, agent := range []backendv1.DpgTenant_AgentType{
		backendv1.DpgTenant_AGENT_TYPE_UNSPECIFIED, backendv1.DpgTenant_AGENT_TYPE_SHARED,
	} {
		svc, _ := newService(t, nil)
		res, err := svc.CreateTenant(context.Background(), connect.NewRequest(&backendv1.CreateTenantRequest{Name: "[ORGANISATION]", AgentType: agent}))
		if err != nil {
			t.Fatalf("%v: %v", agent, err)
		}
		if res.Msg.GetTenant().GetAgentType() != backendv1.DpgTenant_AGENT_TYPE_SHARED {
			t.Errorf("%v gave %v", agent, res.Msg.GetTenant().GetAgentType())
		}
	}
	svc, f := newService(t, nil)
	caps, err := svc.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if got := caps.Msg.GetTenantAgentTypes(); len(got) != 1 || got[0] != backendv1.DpgTenant_AGENT_TYPE_SHARED {
		t.Errorf("tenant agent types = %v, want the shared agent only", got)
	}
	before := len(f.Calls())
	_, err = svc.CreateTenant(context.Background(), connect.NewRequest(&backendv1.CreateTenantRequest{
		Name: "[ORGANISATION]", AgentType: backendv1.DpgTenant_AGENT_TYPE_DEDICATED,
	}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	if !strings.Contains(err.Error(), "shared agent") {
		t.Errorf("the message %q does not name the shared agent", err)
	}
	if len(f.Calls()) != before {
		t.Errorf("the refused request called the platform: %v", f.Calls()[before:])
	}
}

// TestListDids: a tenant shows every DID of its organisation, the
// primary DID first, and marks the primary DID.
func TestListDids(t *testing.T) {
	svc, _ := newService(t, nil)
	res, err := svc.GetTenant(context.Background(), connect.NewRequest(&backendv1.GetTenantRequest{Id: fixtureOrg}))
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	tenant := res.Msg.GetTenant()
	if got := strings.Join(tenant.GetDids(), " "); got != fixtureDid+" "+fixtureIndyDid {
		t.Errorf("DIDs = %s", got)
	}
	if tenant.GetPrimaryDid() != fixtureDid || tenant.GetAgentType() != backendv1.DpgTenant_AGENT_TYPE_SHARED {
		t.Errorf("tenant = %v", tenant)
	}
	_, err = svc.GetTenant(context.Background(), connect.NewRequest(&backendv1.GetTenantRequest{}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

// TestTenantUsersListed: the members of the organisation show with the
// roles they hold there, read only. A role in another organisation
// stays out.
func TestTenantUsersListed(t *testing.T) {
	svc, _ := newService(t, nil)
	res, err := svc.GetTenant(context.Background(), connect.NewRequest(&backendv1.GetTenantRequest{Id: fixtureOrg}))
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	members := res.Msg.GetTenant().GetMembers()
	if len(members) != 2 {
		t.Fatalf("members = %v", members)
	}
	if members[0].GetLogin() != "[PLATFORM ADMIN EMAIL]" || strings.Join(members[0].GetRoles(), ",") != "owner" {
		t.Errorf("first member = %v", members[0])
	}
	if members[1].GetLogin() != "[ISSUER EMAIL]" || strings.Join(members[1].GetRoles(), ",") != "issuer" {
		t.Errorf("second member = %v", members[1])
	}
}

// TestSetPrimaryDid: a new issuer identity becomes the primary DID of
// the organisation of the adapter, and the identity reads the primary
// DID first.
func TestSetPrimaryDid(t *testing.T) {
	svc, f := newService(t, nil)
	res, err := svc.ProvisionIssuerIdentity(context.Background(), connect.NewRequest(&backendv1.ProvisionIssuerIdentityRequest{
		Method: "did:key", KeyType: "secp256r1",
	}))
	if err != nil {
		t.Fatalf("ProvisionIssuerIdentity: %v", err)
	}
	var did map[string]any
	if err := f.RequestJSON("/v1/orgs/org-1/agents/did", &did); err != nil {
		t.Fatalf("the DID request: %v", err)
	}
	if did["method"] != "key" || did["keyType"] != "p256" || did["isPrimaryDid"] != true {
		t.Errorf("the DID request = %v", did)
	}
	id := res.Msg.GetIdentity()
	if len(id.GetIdentifiers()) == 0 || id.GetIdentifiers()[0] != fixtureDid {
		t.Errorf("identifiers = %v, want the primary DID first", id.GetIdentifiers())
	}
	if id.GetKey().GetType() != "Ed25519" || id.GetKey().GetBackend() != "askar" {
		t.Errorf("key = %v", id.GetKey())
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(id.GetDidDocument()), &doc); err != nil || doc["id"] != fixtureDid {
		t.Errorf("DID document = %s, %v", id.GetDidDocument(), err)
	}
	if id.GetMetadata().GetDisplayName() != "[ORGANISATION]" {
		t.Errorf("metadata = %v", id.GetMetadata())
	}
	for _, bad := range []*backendv1.ProvisionIssuerIdentityRequest{
		{Method: "did:web", KeyType: "Ed25519", Domain: "issuer.example"},
		{Method: "did:indy", KeyType: "Ed25519"},
		{Method: "did:key", KeyType: "RSA"},
	} {
		_, err := svc.ProvisionIssuerIdentity(context.Background(), connect.NewRequest(bad))
		wantCode(t, err, connect.CodeInvalidArgument)
	}
}

// TestGetIssuerIdentityReadsTheOrganisation: the identity is the DIDs
// of the organisation of the adapter. An organisation with no DID has
// no identity yet.
func TestGetIssuerIdentityReadsTheOrganisation(t *testing.T) {
	svc, f := newService(t, nil)
	res, err := svc.GetIssuerIdentity(context.Background(), connect.NewRequest(&backendv1.GetIssuerIdentityRequest{}))
	if err != nil {
		t.Fatalf("GetIssuerIdentity: %v", err)
	}
	if got := res.Msg.GetIdentity().GetIdentifiers(); len(got) != 2 || got[0] != fixtureDid || got[1] != fixtureIndyDid {
		t.Errorf("identifiers = %v", got)
	}
	f.SetStatus("/v1/orgs/org-1/dids", 404)
	_, err = svc.GetIssuerIdentity(context.Background(), connect.NewRequest(&backendv1.GetIssuerIdentityRequest{}))
	wantCode(t, err, connect.CodeNotFound)
}

// TestListAndDeleteTenants: the list leaves out the platform admin
// organisation, which holds the shared agent. Delete removes an
// organisation once and refuses the organisations the stack needs.
func TestListAndDeleteTenants(t *testing.T) {
	svc, f := newService(t, nil)
	ctx := context.Background()
	res, err := svc.ListTenants(ctx, connect.NewRequest(&backendv1.ListTenantsRequest{}))
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	if len(res.Msg.GetTenants()) != 1 || res.Msg.GetTenants()[0].GetName() != "[ORGANISATION]" {
		t.Errorf("tenants = %v", res.Msg.GetTenants())
	}
	if got := res.Msg.GetTenants()[0]; got.GetPrimaryDid() != fixtureDid || got.GetAgentType() != backendv1.DpgTenant_AGENT_TYPE_SHARED {
		t.Errorf("tenant = %v", got)
	}
	f.SetOrgs(fake.NoOrgs)
	empty, err := svc.ListTenants(ctx, connect.NewRequest(&backendv1.ListTenantsRequest{}))
	if err != nil || len(empty.Msg.GetTenants()) != 0 {
		t.Errorf("an empty platform gave %v, %v", empty, err)
	}
	if _, delErr := svc.DeleteTenant(ctx, connect.NewRequest(&backendv1.DeleteTenantRequest{Id: fixtureOrg})); delErr != nil {
		t.Fatalf("DeleteTenant: %v", delErr)
	}
	_, err = svc.DeleteTenant(ctx, connect.NewRequest(&backendv1.DeleteTenantRequest{Id: fixtureOrg}))
	wantCode(t, err, connect.CodeNotFound)
	_, err = svc.DeleteTenant(ctx, connect.NewRequest(&backendv1.DeleteTenantRequest{Id: "org-1"}))
	wantCode(t, err, connect.CodeFailedPrecondition)
}

// TestTenantCallsReportThePlatform: each step names what failed, and a
// failed DID removes the organisation again.
func TestTenantCallsReportThePlatform(t *testing.T) {
	ctx := context.Background()
	svc, f := newService(t, nil)
	f.SetStatus("/v1/orgs", 400)
	_, err := svc.CreateTenant(ctx, connect.NewRequest(&backendv1.CreateTenantRequest{Name: "[ORGANISATION]"}))
	wantCode(t, err, connect.CodeInvalidArgument)
	svc, f = newService(t, nil)
	f.SetStatus("/v1/orgs/"+fixtureOrg+"/agents/did", 500)
	if _, didErr := svc.CreateTenant(ctx, connect.NewRequest(&backendv1.CreateTenantRequest{Name: "[ORGANISATION]"})); didErr == nil {
		t.Fatal("a failed DID passed")
	}
	if !strings.Contains(strings.Join(f.Calls(), "\n"), "DELETE /v1/orgs/"+fixtureOrg) {
		t.Errorf("the half made organisation stayed: %v", f.Calls())
	}
	for _, path := range []string{"/v1/orgs/" + fixtureOrg, "/v1/orgs/" + fixtureOrg + "/dids", "/v1/orgs/" + fixtureOrg + "/users"} {
		svc, f = newService(t, nil)
		f.SetStatus(path, 403)
		_, getErr := svc.GetTenant(ctx, connect.NewRequest(&backendv1.GetTenantRequest{Id: fixtureOrg}))
		wantCode(t, getErr, connect.CodePermissionDenied)
	}
	svc, f = newService(t, nil)
	f.SetStatus("/v1/orgs/org-1/agents/did", 409)
	_, err = svc.ProvisionIssuerIdentity(ctx, connect.NewRequest(&backendv1.ProvisionIssuerIdentityRequest{Method: "did:key"}))
	wantCode(t, err, connect.CodeAlreadyExists)
	svc, f = newService(t, nil)
	f.SetStatus("/v1/orgs/org-1", 403)
	_, err = svc.GetIssuerIdentity(ctx, connect.NewRequest(&backendv1.GetIssuerIdentityRequest{}))
	wantCode(t, err, connect.CodePermissionDenied)
	svc, f = newService(t, nil)
	f.SetStatus("/v1/orgs", 500)
	_, err = svc.ListTenants(ctx, connect.NewRequest(&backendv1.ListTenantsRequest{}))
	wantCode(t, err, connect.CodeUnavailable)
	svc, f = newService(t, nil)
	f.SetStatus("/v1/orgs/"+fixtureOrg, 200, 500)
	_, err = svc.DeleteTenant(ctx, connect.NewRequest(&backendv1.DeleteTenantRequest{Id: fixtureOrg}))
	if err == nil {
		t.Error("a failed delete passed")
	}
	_, err = svc.DeleteTenant(ctx, connect.NewRequest(&backendv1.DeleteTenantRequest{}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

// TestListTenantsPages: the page token is the next page number of the
// platform, and a bad token fails.
func TestListTenantsPages(t *testing.T) {
	svc, f := newService(t, nil)
	ctx := context.Background()
	res, err := svc.ListTenants(ctx, connect.NewRequest(&backendv1.ListTenantsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	// The page size of the test service is one, so a second page exists.
	if res.Msg.GetPage().GetNextPageToken() != "2" {
		t.Errorf("next page = %q", res.Msg.GetPage().GetNextPageToken())
	}
	if _, err := svc.ListTenants(ctx, connect.NewRequest(&backendv1.ListTenantsRequest{})); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(f.Calls(), " "), "GET /v1/orgs") {
		t.Errorf("calls = %v", f.Calls())
	}
	for _, token := range []string{"x", "0"} {
		_, err := svc.ListTenants(ctx, connect.NewRequest(&backendv1.ListTenantsRequest{Page: &commonv1.Pagination{PageToken: token}}))
		wantCode(t, err, connect.CodeInvalidArgument)
	}
	if _, err := svc.ListTenants(ctx, connect.NewRequest(&backendv1.ListTenantsRequest{Page: &commonv1.Pagination{PageToken: "2"}})); err != nil {
		t.Errorf("page 2: %v", err)
	}
}
