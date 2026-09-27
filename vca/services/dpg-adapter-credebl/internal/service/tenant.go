// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"fmt"
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
// the stack file. The platform makes a DID only with its private key, so
// the operator makes the DID of a tenant in the platform, and the admin
// pages make it primary (P6-C1b, ADR-070). The capability answer lists
// FEATURE_MULTI_TENANCY.

// An organisation holds one client credential: the client of the
// organisation in the Keycloak of the platform (P6-C8, ADR-038 decision
// 2). A create returns the secret once. The platform keeps the secret
// masked and returns it masked, so the adapter drops it from a list and
// keeps no copy. A second create would replace the secret of the client
// that machines already use, so the adapter refuses it.

// dedicatedMessage says why a dedicated agent is refused. The platform
// starts a dedicated agent through the Docker socket, which the stack
// file does not mount (ADR-005 decision 3).
const dedicatedMessage = "this deployment runs one shared agent and starts no dedicated agent; choose the shared agent"

// CreateTenant creates an organisation and its wallet in the shared
// agent. When the wallet fails, the organisation goes again, so no half
// made tenant stays.
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
	return connect.NewResponse(&backendv1.CreateTenantResponse{Tenant: &backendv1.DpgTenant{
		Id: org.ID, Name: org.Name, AgentType: backendv1.DpgTenant_AGENT_TYPE_SHARED,
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

// ListClientCredentials returns the client credential of one
// organisation, without its secret.
func (s *Service) ListClientCredentials(
	ctx context.Context, req *connect.Request[backendv1.ListClientCredentialsRequest],
) (*connect.Response[backendv1.ListClientCredentialsResponse], error) {
	tenant, err := tenantID(req.Msg.GetTenantId())
	if err != nil {
		return nil, err
	}
	cred, found, err := s.client.OrgClientCredential(ctx, tenant)
	if err != nil {
		return nil, failed("read the client credential of the organisation", err)
	}
	out := &backendv1.ListClientCredentialsResponse{}
	if found {
		out.Credentials = []*backendv1.ClientCredential{s.clientCredential(ctx, tenant, cred.ClientID)}
	}
	return connect.NewResponse(out), nil
}

// clientCredential names the client of an organisation after the
// organisation, because the platform keeps no name of its own.
func (s *Service) clientCredential(ctx context.Context, tenant, clientID string) *backendv1.ClientCredential {
	name := tenant
	if org, err := s.client.GetOrg(ctx, tenant); err == nil && org.Name != "" {
		name = org.Name
	}
	return &backendv1.ClientCredential{Id: clientID, ClientId: clientID, Name: name}
}

// CreateClientCredential creates the client credential of one
// organisation and returns its secret once.
func (s *Service) CreateClientCredential(
	ctx context.Context, req *connect.Request[backendv1.CreateClientCredentialRequest],
) (*connect.Response[backendv1.CreateClientCredentialResponse], error) {
	tenant, err := tenantID(req.Msg.GetTenantId())
	if err != nil {
		return nil, err
	}
	_, found, err := s.client.OrgClientCredential(ctx, tenant)
	if err != nil {
		return nil, failed("read the client credential of the organisation", err)
	}
	if found {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New(
			"the organisation holds one client credential; delete it before you make a new one"))
	}
	clientID, secret, err := s.client.CreateOrgClientCredential(ctx, tenant)
	if err != nil {
		return nil, failed("create the client credential of the organisation", err)
	}
	return connect.NewResponse(&backendv1.CreateClientCredentialResponse{
		Credential: s.clientCredential(ctx, tenant, clientID), ClientSecret: secret,
	}), nil
}

// DeleteClientCredential removes the client credential of one
// organisation. The id must name its client.
func (s *Service) DeleteClientCredential(
	ctx context.Context, req *connect.Request[backendv1.DeleteClientCredentialRequest],
) (*connect.Response[backendv1.DeleteClientCredentialResponse], error) {
	tenant, err := tenantID(req.Msg.GetTenantId())
	if err != nil {
		return nil, err
	}
	id := strings.TrimSpace(req.Msg.GetId())
	if id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the call names no client credential"))
	}
	cred, found, err := s.client.OrgClientCredential(ctx, tenant)
	if err != nil {
		return nil, failed("read the client credential of the organisation", err)
	}
	if !found || cred.ClientID != id {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("the organisation holds no client credential of that client"))
	}
	if err := s.client.DeleteOrgClientCredential(ctx, tenant); err != nil {
		return nil, failed("delete the client credential of the organisation", err)
	}
	return connect.NewResponse(&backendv1.DeleteClientCredentialResponse{}), nil
}

// SetTenantPrimaryDid makes one DID of an organisation the DID it signs
// with (P6-C1b). The DID may come from the agent, or from the operator
// who made a did:indy or a did:web in the platform with a private key
// that VCA never sees. The platform takes the DID with the id of its record, so
// the adapter reads the DIDs of the organisation first.
func (s *Service) SetTenantPrimaryDid(
	ctx context.Context, req *connect.Request[backendv1.SetTenantPrimaryDidRequest],
) (*connect.Response[backendv1.SetTenantPrimaryDidResponse], error) {
	tenant, did := strings.TrimSpace(req.Msg.GetTenantId()), strings.TrimSpace(req.Msg.GetDid())
	if tenant == "" || did == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the request needs the tenant id and the DID"))
	}
	dids, err := s.client.OrgDids(ctx, tenant)
	if err != nil {
		return nil, failed("read the DIDs of the organisation", err)
	}
	var record credebl.OrgDid
	for _, d := range dids {
		if d.Did == did {
			record = d
		}
	}
	if record.ID == "" {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("the organisation holds no DID %s", did))
	}
	if serr := s.client.SetPrimaryDid(ctx, tenant, record); serr != nil {
		return nil, failed("set the primary DID of the organisation", serr)
	}
	res, err := s.GetTenant(ctx, connect.NewRequest(&backendv1.GetTenantRequest{Id: tenant}))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&backendv1.SetTenantPrimaryDidResponse{Tenant: res.Msg.GetTenant()}), nil
}
