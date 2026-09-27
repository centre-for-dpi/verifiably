// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"slices"
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
// in the shared agent, in that order. The pinned platform makes a DID
// only with its private key in the request, so the tenant gets no DID
// from the adapter. The operator makes one in the platform, and the
// admin pages make it primary (P6-C1b).
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
	if tenant.GetPrimaryDid() != "" || len(tenant.GetDids()) != 0 {
		t.Errorf("DIDs = %v, primary %q; the adapter makes no DID", tenant.GetDids(), tenant.GetPrimaryDid())
	}
	var org map[string]string
	if orgErr := f.RequestJSON("/v1/orgs", &org); orgErr != nil || org["name"] != "[ORGANISATION]" {
		t.Errorf("the organisation request = %v, %v", org, orgErr)
	}
	var wallet map[string]string
	if walletErr := f.RequestJSON("/v1/orgs/"+fixtureOrg+"/agents/wallet", &wallet); walletErr != nil || wallet["label"] != "[ORGANISATION]" {
		t.Errorf("the wallet request = %v, %v", wallet, walletErr)
	}
	order := strings.Join(f.Calls(), "\n")
	create := strings.Index(order, "POST /v1/orgs\n")
	walletAt := strings.Index(order, "POST /v1/orgs/"+fixtureOrg+"/agents/wallet")
	if create < 0 || walletAt < create || strings.Contains(order, "/agents/did") {
		t.Errorf("calls:\n%s", order)
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

// TestProvisionNeedsTheKeyOfTheOperator: the pinned gateway refuses a
// DID of any method without its private key in the request (Validator
// validateDid of libs/common/src/validator.ts at the platform tag
// v2.2.1-alpha.4). The adapter never holds such a key, so a provision
// answers Unimplemented and names the way through the platform. It
// calls no platform route (P6-C1b).
func TestProvisionNeedsTheKeyOfTheOperator(t *testing.T) {
	svc, f := newService(t, nil)
	for _, req := range []*backendv1.ProvisionIssuerIdentityRequest{
		{Method: "did:key", KeyType: "Ed25519"},
		{Method: "did:web", KeyType: "Ed25519", Domain: "issuer.example"},
		{Method: "did:indy", KeyType: "Ed25519"},
	} {
		_, err := svc.ProvisionIssuerIdentity(context.Background(), connect.NewRequest(req))
		wantCode(t, err, connect.CodeUnimplemented)
		if !strings.Contains(err.Error(), "private key") {
			t.Errorf("%s: the message %q does not say why", req.GetMethod(), err)
		}
	}
	if len(f.Calls()) != 0 {
		t.Errorf("a provision called the platform: %v", f.Calls())
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
	for _, path := range []string{"/v1/orgs/" + fixtureOrg, "/v1/orgs/" + fixtureOrg + "/dids", "/v1/orgs/" + fixtureOrg + "/users"} {
		svc, f = newService(t, nil)
		f.SetStatus(path, 403)
		_, getErr := svc.GetTenant(ctx, connect.NewRequest(&backendv1.GetTenantRequest{Id: fixtureOrg}))
		wantCode(t, getErr, connect.CodePermissionDenied)
	}
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

// TestSetTenantPrimaryDid makes one DID of an organisation its primary
// DID, such as a did:indy the operator made in the platform with a seed
// VCA never sees (P6-C1b). The platform takes the DID and its record
// id. A DID the organisation does not hold fails before the platform
// call.
func TestSetTenantPrimaryDid(t *testing.T) {
	svc, f := newService(t, nil)
	ctx := context.Background()
	res, err := svc.SetTenantPrimaryDid(ctx, connect.NewRequest(&backendv1.SetTenantPrimaryDidRequest{TenantId: fixtureOrg, Did: fixtureIndyDid}))
	if err != nil {
		t.Fatalf("SetTenantPrimaryDid: %v", err)
	}
	var body map[string]string
	if rerr := f.RequestJSON("/v1/orgs/"+fixtureOrg+"/primary-did", &body); rerr != nil {
		t.Fatalf("the primary DID request: %v", rerr)
	}
	if body["did"] != fixtureIndyDid || body["id"] != "6f1a2b3c-4d5e-4f6a-8b7c-9d0e1f2a3b4c" {
		t.Errorf("the primary DID request = %v", body)
	}
	if res.Msg.GetTenant().GetId() != fixtureOrg || len(res.Msg.GetTenant().GetDids()) != 2 {
		t.Errorf("tenant = %v", res.Msg.GetTenant())
	}
	for name, req := range map[string]*backendv1.SetTenantPrimaryDidRequest{
		"no tenant": {Did: fixtureIndyDid},
		"no DID":    {TenantId: fixtureOrg},
	} {
		_, rerr := svc.SetTenantPrimaryDid(ctx, connect.NewRequest(req))
		if connect.CodeOf(rerr) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, rerr)
		}
	}
	calls := len(f.Calls())
	_, err = svc.SetTenantPrimaryDid(ctx, connect.NewRequest(&backendv1.SetTenantPrimaryDidRequest{TenantId: fixtureOrg, Did: "did:web:elsewhere.example"}))
	wantCode(t, err, connect.CodeNotFound)
	for _, c := range f.Calls()[calls:] {
		if strings.HasSuffix(c, "/primary-did") {
			t.Errorf("a DID the organisation does not hold reached the platform: %s", c)
		}
	}
	f.SetStatus("/v1/orgs/"+fixtureOrg+"/primary-did", 500)
	_, err = svc.SetTenantPrimaryDid(ctx, connect.NewRequest(&backendv1.SetTenantPrimaryDidRequest{TenantId: fixtureOrg, Did: fixtureIndyDid}))
	wantCode(t, err, connect.CodeUnavailable)
}

// TestOperatorDidMethodsAndLimitsListed: the platform needs the private
// key for every DID, so the operator makes each DID in the platform and
// the answer names the methods. The adapter provisions none. The answer also names the
// primary DID feature, the key reference of an X.509 import, and the
// one client credential of an organisation (P6-C1b).
func TestOperatorDidMethodsAndLimitsListed(t *testing.T) {
	svc, _ := newService(t, nil)
	caps, err := svc.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	c := caps.Msg
	if strings.Join(c.GetOperatorDidMethods(), ",") != "did:key,did:indy,did:web" || len(c.GetDidMethods()) != 0 || len(c.GetKeyTypes()) != 0 {
		t.Errorf("operator DID methods = %v, DID methods %v, key types %v", c.GetOperatorDidMethods(), c.GetDidMethods(), c.GetKeyTypes())
	}
	if !slices.Contains(c.GetFeatures(), backendv1.Feature_FEATURE_TENANT_PRIMARY_DID) ||
		slices.Contains(c.GetFeatures(), backendv1.Feature_FEATURE_ISSUER_IDENTITY_PROVISION) {
		t.Errorf("features = %v", c.GetFeatures())
	}
	if c.GetX509KeyReference() != `{"certificateId": "<certificate id>"}` || c.GetTenantClientCredentialLimit() != 1 {
		t.Errorf("key reference %q, limit %d", c.GetX509KeyReference(), c.GetTenantClientCredentialLimit())
	}
}
