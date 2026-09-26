// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/credebl"
)

// CREDEBL organisations are the DPG tenants (ADR-037, P6-C1). A new
// tenant is an organisation with a tenant wallet in the shared agent of
// the stack file and a did:key that the agent makes, so it can sign at
// once. The capability answer lists FEATURE_MULTI_TENANCY.

// clientCredentialMessage says why the client credential RPCs answer
// Unimplemented. The capability answer lists no
// FEATURE_TENANT_CLIENT_CREDENTIALS, so the admin pages offer no stack
// credential on this stack (ADR-038 decision 2).
const clientCredentialMessage = "the adapter makes no client credential of a CREDEBL organisation yet"

// dedicatedMessage says why a dedicated agent is refused. The platform
// starts a dedicated agent through the Docker socket, which the stack
// file does not mount (ADR-005 decision 3).
const dedicatedMessage = "this deployment runs one shared agent and starts no dedicated agent; choose the shared agent"

// tenantDidKeyType is the key of the did:key of a new tenant.
const tenantDidKeyType = "ed25519"

// CreateTenant creates an organisation, its wallet in the shared agent
// and its primary did:key. When a later step fails, the organisation
// goes again, so no half made tenant stays.
func (s *Service) CreateTenant(
	ctx context.Context, req *connect.Request[backendv1.CreateTenantRequest],
) (*connect.Response[backendv1.CreateTenantResponse], error) {
	name := strings.TrimSpace(req.Msg.GetName())
	if name == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the tenant needs a name"))
	}
	if req.Msg.GetAgentType() == backendv1.DpgTenant_AGENT_TYPE_DEDICATED {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New(dedicatedMessage))
	}
	org, err := s.client.CreateOrg(ctx, name, "Verifiable Credentials Adapters tenant "+name)
	if err != nil {
		return nil, failed("create the organisation", err)
	}
	if walletErr := s.client.CreateSharedWallet(ctx, org.ID, name); walletErr != nil {
		anyval.Discard(s.client.DeleteOrg(ctx, org.ID))
		return nil, failed("create the wallet in the shared agent", walletErr)
	}
	did, err := s.client.CreateDid(ctx, org.ID, credebl.DidRequest{Method: "key", KeyType: tenantDidKeyType, IsPrimaryDid: true})
	if err != nil {
		anyval.Discard(s.client.DeleteOrg(ctx, org.ID))
		return nil, failed("create the DID of the organisation", err)
	}
	return connect.NewResponse(&backendv1.CreateTenantResponse{Tenant: &backendv1.DpgTenant{
		Id: org.ID, Name: org.Name, AgentType: backendv1.DpgTenant_AGENT_TYPE_SHARED,
		Dids: []string{did.Did}, PrimaryDid: did.Did,
	}}), nil
}

// GetTenant reads one organisation with its DIDs and its members.
func (s *Service) GetTenant(
	ctx context.Context, req *connect.Request[backendv1.GetTenantRequest],
) (*connect.Response[backendv1.GetTenantResponse], error) {
	id := strings.TrimSpace(req.Msg.GetId())
	if id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the tenant id is empty"))
	}
	org, err := s.client.GetOrg(ctx, id)
	if err != nil {
		return nil, orgFailed(err)
	}
	tenant := tenantOf(org)
	dids, err := s.client.OrgDids(ctx, id)
	if err != nil {
		return nil, failed("read the DIDs of the organisation", err)
	}
	tenant.Dids, tenant.PrimaryDid = nil, ""
	for _, d := range dids {
		tenant.Dids = append(tenant.Dids, d.Did)
		if d.IsPrimaryDid {
			tenant.PrimaryDid = d.Did
		}
	}
	members, err := s.client.OrgMembers(ctx, id)
	if err != nil {
		return nil, failed("read the members of the organisation", err)
	}
	for _, m := range members {
		tenant.Members = append(tenant.Members, &backendv1.TenantMember{Login: m.Email, Roles: m.Roles})
	}
	return connect.NewResponse(&backendv1.GetTenantResponse{Tenant: tenant}), nil
}

// orgFailed maps the error of an organisation read onto a Connect
// error. An organisation the platform does not know is not found.
func orgFailed(err error) *connect.Error {
	if errors.Is(err, credebl.ErrNoOrganisation) {
		return connect.NewError(connect.CodeNotFound, err)
	}
	return failed("read the organisation", err)
}

// tenantOf converts an organisation into a tenant with the primary DID
// of its agent.
func tenantOf(org credebl.Org) *backendv1.DpgTenant {
	t := &backendv1.DpgTenant{Id: org.ID, Name: org.Name}
	switch org.AgentType() {
	case credebl.AgentShared:
		t.AgentType = backendv1.DpgTenant_AGENT_TYPE_SHARED
	case credebl.AgentDedicated:
		t.AgentType = backendv1.DpgTenant_AGENT_TYPE_DEDICATED
	}
	if len(org.Agents) > 0 && org.Agents[0].OrgDid != "" {
		t.Dids = []string{org.Agents[0].OrgDid}
		t.PrimaryDid = org.Agents[0].OrgDid
	}
	return t
}

// ListTenants reads one page of organisations. The platform admin
// organisation holds the shared agent, so it is not a tenant.
func (s *Service) ListTenants(
	ctx context.Context, req *connect.Request[backendv1.ListTenantsRequest],
) (*connect.Response[backendv1.ListTenantsResponse], error) {
	size := int(req.Msg.GetPage().GetPageSize())
	if size <= 0 || size > s.pageSizeMax {
		size = s.pageSizeMax
	}
	page := 1
	if token := req.Msg.GetPage().GetPageToken(); token != "" {
		n, err := parseToken(token)
		if err != nil || n < 1 {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("service: bad page token"))
		}
		page = n
	}
	orgs, total, err := s.client.ListOrgs(ctx, page, size)
	if err != nil {
		return nil, failed("list the organisations", err)
	}
	out := &backendv1.ListTenantsResponse{Page: &commonv1.PageResult{TotalSize: int64(total)}}
	for _, org := range orgs {
		if org.Name == credebl.PlatformOrgName {
			out.Page.TotalSize--
			continue
		}
		out.Tenants = append(out.Tenants, tenantOf(org))
	}
	if page*size < total {
		out.Page.NextPageToken = strconv.Itoa(page + 1)
	}
	return connect.NewResponse(out), nil
}

// DeleteTenant removes one organisation. The organisation of the
// adapter and the platform admin organisation stay: the issuer and the
// shared agent need them.
func (s *Service) DeleteTenant(
	ctx context.Context, req *connect.Request[backendv1.DeleteTenantRequest],
) (*connect.Response[backendv1.DeleteTenantResponse], error) {
	id := strings.TrimSpace(req.Msg.GetId())
	if id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the tenant id is empty"))
	}
	if id == s.client.OrgID() {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("the adapter issues and verifies in this organisation; it stays"))
	}
	org, err := s.client.GetOrg(ctx, id)
	if err != nil {
		return nil, orgFailed(err)
	}
	if org.Name == credebl.PlatformOrgName {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("the platform admin organisation holds the shared agent; it stays"))
	}
	if err := s.client.DeleteOrg(ctx, id); err != nil {
		return nil, failed("delete the organisation", err)
	}
	return connect.NewResponse(&backendv1.DeleteTenantResponse{}), nil
}

// ListClientCredentials is not available. See clientCredentialMessage.
func (s *Service) ListClientCredentials(
	context.Context, *connect.Request[backendv1.ListClientCredentialsRequest],
) (*connect.Response[backendv1.ListClientCredentialsResponse], error) {
	return nil, unimplemented(clientCredentialMessage)
}

// CreateClientCredential is not available. See clientCredentialMessage.
func (s *Service) CreateClientCredential(
	context.Context, *connect.Request[backendv1.CreateClientCredentialRequest],
) (*connect.Response[backendv1.CreateClientCredentialResponse], error) {
	return nil, unimplemented(clientCredentialMessage)
}

// DeleteClientCredential is not available. See clientCredentialMessage.
func (s *Service) DeleteClientCredential(
	context.Context, *connect.Request[backendv1.DeleteClientCredentialRequest],
) (*connect.Response[backendv1.DeleteClientCredentialResponse], error) {
	return nil, unimplemented(clientCredentialMessage)
}
