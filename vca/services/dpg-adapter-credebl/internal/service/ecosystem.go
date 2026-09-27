// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/credebl"
	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// The ecosystems of the platform (P6-C9, ADR-068). An ecosystem is a
// group of organisations that one lead organisation runs. A tenant is an
// organisation (ADR-037), so the lead and each member are tenants. The
// platform admin of the adapter creates each ecosystem and adds each
// member, and the platform accepts the membership at once for an
// organisation that the platform admin created. The capability answer
// lists FEATURE_ECOSYSTEMS.

// The limits of the create body of the platform (create-ecosystem-dto.ts).
const (
	ecosystemNameMin        = 2
	ecosystemNameMax        = 50
	ecosystemDescriptionMin = 2
	ecosystemDescriptionMax = 255
)

// realmMessage says why the platform refuses to turn ecosystems on.
const realmMessage = "the platform turns ecosystems on only when its Keycloak realm keeps the ecosystem roles of each user; " +
	"run the bootstrap of the CREDEBL stack, which sets the realm up (ADR-068)"

// GetEcosystemSettings reports whether the ecosystems of the platform
// are on.
func (s *Service) GetEcosystemSettings(
	ctx context.Context, _ *connect.Request[backendv1.GetEcosystemSettingsRequest],
) (*connect.Response[backendv1.GetEcosystemSettingsResponse], error) {
	on, err := s.client.EcosystemsEnabled(ctx)
	if err != nil {
		return nil, failed("read the ecosystem switch of the platform", err)
	}
	return connect.NewResponse(&backendv1.GetEcosystemSettingsResponse{Enabled: on}), nil
}

// SetEcosystemSettings turns the ecosystems of the platform on or off,
// and reads the switch back.
func (s *Service) SetEcosystemSettings(
	ctx context.Context, req *connect.Request[backendv1.SetEcosystemSettingsRequest],
) (*connect.Response[backendv1.SetEcosystemSettingsResponse], error) {
	if err := s.client.SetEcosystemsEnabled(ctx, req.Msg.GetEnabled()); err != nil {
		if dpgclient.IsStatus(err, 400) {
			return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("%s: %w", realmMessage, err))
		}
		return nil, failed("set the ecosystem switch of the platform", err)
	}
	on, err := s.client.EcosystemsEnabled(ctx)
	if err != nil {
		return nil, failed("read the ecosystem switch of the platform", err)
	}
	return connect.NewResponse(&backendv1.SetEcosystemSettingsResponse{Enabled: on}), nil
}

// ecosystemOf converts an ecosystem of the platform.
func ecosystemOf(e credebl.Ecosystem) *backendv1.Ecosystem {
	out := &backendv1.Ecosystem{
		Id: e.ID, Name: e.Name, Description: e.Description,
		MemberCount: int32(min(max(e.MemberCount, 0), 1<<31-1)), // #nosec G115 -- min and max bound the value
	}
	if e.Lead != nil {
		out.LeadTenantId, out.LeadTenantName = e.Lead.ID, e.Lead.Name
	}
	return out
}

// ListEcosystems lists the ecosystems that one tenant leads or belongs
// to.
func (s *Service) ListEcosystems(
	ctx context.Context, req *connect.Request[backendv1.ListEcosystemsRequest],
) (*connect.Response[backendv1.ListEcosystemsResponse], error) {
	tenant, err := tenantID(req.Msg.GetTenantId())
	if err != nil {
		return nil, err
	}
	list, err := s.client.Ecosystems(ctx, tenant)
	if err != nil {
		return nil, failed("list the ecosystems of the organisation", err)
	}
	out := &backendv1.ListEcosystemsResponse{}
	for _, e := range list {
		out.Ecosystems = append(out.Ecosystems, ecosystemOf(e))
	}
	return connect.NewResponse(out), nil
}

// textBetween trims a text and checks its length in characters.
func textBetween(field, v string, lo, hi int) (string, error) {
	v = strings.TrimSpace(v)
	if n := utf8.RuneCountInString(v); n < lo || n > hi {
		return "", connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("the %s needs %d to %d characters", field, lo, hi))
	}
	return v, nil
}

// CreateEcosystem creates one ecosystem that a tenant leads.
func (s *Service) CreateEcosystem(
	ctx context.Context, req *connect.Request[backendv1.CreateEcosystemRequest],
) (*connect.Response[backendv1.CreateEcosystemResponse], error) {
	lead, err := tenantID(req.Msg.GetLeadTenantId())
	if err != nil {
		return nil, err
	}
	name, err := textBetween("name", req.Msg.GetName(), ecosystemNameMin, ecosystemNameMax)
	if err != nil {
		return nil, err
	}
	description, err := textBetween("description", req.Msg.GetDescription(), ecosystemDescriptionMin, ecosystemDescriptionMax)
	if err != nil {
		return nil, err
	}
	created, err := s.client.CreateEcosystem(ctx, lead, name, description)
	if err != nil {
		return nil, failed("create the ecosystem", err)
	}
	out := ecosystemOf(created)
	out.LeadTenantId = lead
	// The create answer names no lead, so the list of the lead fills it.
	if list, lerr := s.client.Ecosystems(ctx, lead); lerr == nil {
		for _, e := range list {
			if e.ID == created.ID {
				out = ecosystemOf(e)
			}
		}
	}
	return connect.NewResponse(&backendv1.CreateEcosystemResponse{Ecosystem: out}), nil
}

// ecosystemID checks the ecosystem id of a call.
func ecosystemID(id string) (string, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", connect.NewError(connect.CodeInvalidArgument, errors.New("the call names no ecosystem"))
	}
	return id, nil
}

// members reads the members of one ecosystem.
func (s *Service) members(ctx context.Context, id string) ([]credebl.EcosystemMember, error) {
	list, err := s.client.EcosystemMembers(ctx, id)
	if err != nil {
		return nil, failed("list the members of the ecosystem", err)
	}
	return list, nil
}

// isMember reports whether a tenant is a member of the list.
func isMember(list []credebl.EcosystemMember, tenant string) bool {
	for _, m := range list {
		if m.Org.ID == tenant {
			return true
		}
	}
	return false
}

// ListEcosystemMembers lists the member tenants of one ecosystem,
// without the lead.
func (s *Service) ListEcosystemMembers(
	ctx context.Context, req *connect.Request[backendv1.ListEcosystemMembersRequest],
) (*connect.Response[backendv1.ListEcosystemMembersResponse], error) {
	id, err := ecosystemID(req.Msg.GetEcosystemId())
	if err != nil {
		return nil, err
	}
	list, err := s.members(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &backendv1.ListEcosystemMembersResponse{}
	for _, m := range list {
		member := &backendv1.EcosystemMember{TenantId: m.Org.ID, TenantName: m.Org.Name, Status: m.Status}
		if !m.At.IsZero() {
			member.JoinedAt = timestamppb.New(m.At)
		}
		out.Members = append(out.Members, member)
	}
	return connect.NewResponse(out), nil
}

// AddEcosystemMember adds one tenant to an ecosystem. The platform
// accepts the membership at once for an organisation that the platform
// admin created, and mails the creator otherwise, so the answer says
// which happened.
func (s *Service) AddEcosystemMember(
	ctx context.Context, req *connect.Request[backendv1.AddEcosystemMemberRequest],
) (*connect.Response[backendv1.AddEcosystemMemberResponse], error) {
	id, err := ecosystemID(req.Msg.GetEcosystemId())
	if err != nil {
		return nil, err
	}
	tenant, err := tenantID(req.Msg.GetTenantId())
	if err != nil {
		return nil, err
	}
	before, err := s.members(ctx, id)
	if err != nil {
		return nil, err
	}
	if isMember(before, tenant) {
		return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("the tenant is a member of the ecosystem"))
	}
	if ierr := s.client.InviteEcosystemMember(ctx, id, tenant); ierr != nil {
		return nil, failed("add the tenant to the ecosystem; the platform refuses the lead as a member", ierr)
	}
	after, err := s.members(ctx, id)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&backendv1.AddEcosystemMemberResponse{Invited: !isMember(after, tenant)}), nil
}

// RemoveEcosystemMember removes one member tenant from an ecosystem.
func (s *Service) RemoveEcosystemMember(
	ctx context.Context, req *connect.Request[backendv1.RemoveEcosystemMemberRequest],
) (*connect.Response[backendv1.RemoveEcosystemMemberResponse], error) {
	id, err := ecosystemID(req.Msg.GetEcosystemId())
	if err != nil {
		return nil, err
	}
	tenant, err := tenantID(req.Msg.GetTenantId())
	if err != nil {
		return nil, err
	}
	if err := s.client.RemoveEcosystemMember(ctx, id, tenant); err != nil {
		if dpgclient.IsStatus(err, 400) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("the tenant is no member of the ecosystem"))
		}
		return nil, failed("remove the tenant from the ecosystem", err)
	}
	return connect.NewResponse(&backendv1.RemoveEcosystemMemberResponse{}), nil
}
