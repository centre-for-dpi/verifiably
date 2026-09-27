// SPDX-License-Identifier: Apache-2.0

package credebl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// The organisation calls of the api gateway (P6-C1). CREDEBL separates
// tenants as organisations. An organisation gets an agent of its own or
// a tenant wallet in the shared agent, and holds DIDs, one of them
// primary. The sources are the organisation and agent controllers of
// the platform, read on 2026-09-26:
// https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/organization/organization.controller.ts
// https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/agent-service/agent-service.controller.ts

// PlatformOrgName is the organisation that the database initialisation
// of the release makes for the platform admin. It holds the shared agent,
// so it is not a tenant.
const PlatformOrgName = "Platform-admin"

// Agent types as the platform names them in org_agent_type.
const (
	// AgentShared is a tenant wallet in the shared agent.
	AgentShared = "SHARED"
	// AgentDedicated is an agent of the organisation alone.
	AgentDedicated = "DEDICATED"
)

// ErrNoOrganisation reports an organisation the platform does not know.
var ErrNoOrganisation = errors.New("credebl: no such organisation")

// Org is one organisation of the platform.
type Org struct {
	// ID is the identifier of the organisation.
	ID string `json:"id"`
	// Name is the name of the organisation.
	Name string `json:"name"`
	// Description is the text of the organisation.
	Description string `json:"description"`
	// Agents holds the agent of the organisation, when it has one.
	Agents []OrgAgent `json:"org_agents"`
}

// OrgAgent is the agent record of one organisation.
type OrgAgent struct {
	// OrgDid is the primary DID the agent signs with.
	OrgDid string `json:"orgDid"`
	// TenantID names the tenant wallet in the shared agent. Empty for a
	// dedicated agent.
	TenantID string `json:"tenantId"`
	// DidDocument is the DID document of the primary DID.
	DidDocument json.RawMessage `json:"didDocument"`
	// Type names the agent type, when the answer carries it.
	Type struct {
		Agent string `json:"agent"`
	} `json:"org_agent_type"`
}

// AgentType returns the agent type of the organisation: AgentShared,
// AgentDedicated, or "" for an organisation with no agent.
func (o Org) AgentType() string {
	if len(o.Agents) == 0 {
		return ""
	}
	a := o.Agents[0]
	if t := strings.ToUpper(strings.TrimSpace(a.Type.Agent)); t != "" {
		return t
	}
	if a.TenantID != "" {
		return AgentShared
	}
	return AgentDedicated
}

// OrgDid is one DID of an organisation.
type OrgDid struct {
	// ID is the record identifier the primary DID call takes.
	ID string `json:"id"`
	// Did is the DID.
	Did string `json:"did"`
	// IsPrimaryDid marks the DID the organisation signs with.
	IsPrimaryDid bool `json:"isPrimaryDid"`
	// DidDocument is the DID document, when the answer carries it.
	DidDocument json.RawMessage `json:"didDocument"`
	// Created is the creation time.
	Created time.Time `json:"createDateTime"`
}

// OrgMember is one person of an organisation with the roles there.
type OrgMember struct {
	// Email is the login of the person.
	Email string
	// Roles are the roles of the person in the organisation.
	Roles []string
}

// envelope is the answer shape of the api gateway.
type envelope[T any] struct {
	Data T `json:"data"`
}

// CreateOrg creates one organisation and returns it.
func (c *Client) CreateOrg(ctx context.Context, name, description string) (Org, error) {
	if c == nil {
		return Org{}, ErrNoPlatform
	}
	body := map[string]string{"name": name, "description": description}
	var out envelope[Org]
	if err := c.call(ctx, http.MethodPost, "/v1/orgs", body, &out); err != nil {
		return Org{}, err
	}
	if out.Data.ID == "" {
		return Org{}, errors.New("credebl: the organisation answer has no identifier")
	}
	if out.Data.Name == "" {
		out.Data.Name = name
	}
	return out.Data, nil
}

// GetOrg reads one organisation with its agent.
func (c *Client) GetOrg(ctx context.Context, id string) (Org, error) {
	if c == nil {
		return Org{}, ErrNoPlatform
	}
	var out envelope[Org]
	if err := c.call(ctx, http.MethodGet, "/v1/orgs/"+url.PathEscape(id), nil, &out); err != nil {
		return Org{}, err
	}
	if out.Data.ID == "" {
		return Org{}, fmt.Errorf("%w: %s", ErrNoOrganisation, id)
	}
	return out.Data, nil
}

// orgPage is the answer of GET /v1/orgs.
type orgPage struct {
	TotalCount    int   `json:"totalCount"`
	TotalPages    int   `json:"totalPages"`
	Organizations []Org `json:"organizations"`
}

// ListOrgs reads one page of the organisations the platform admin
// belongs to. Page numbers start at one. The platform answers the
// status not found for an empty list, which reads as no organisation.
func (c *Client) ListOrgs(ctx context.Context, page, size int) ([]Org, int, error) {
	if c == nil {
		return nil, 0, ErrNoPlatform
	}
	q := url.Values{"pageNumber": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(size)}}
	var out envelope[orgPage]
	if err := c.call(ctx, http.MethodGet, "/v1/orgs?"+q.Encode(), nil, &out); err != nil {
		if dpgclient.IsStatus(err, http.StatusNotFound) {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	return out.Data.Organizations, out.Data.TotalCount, nil
}

// DeleteOrg removes one organisation.
func (c *Client) DeleteOrg(ctx context.Context, id string) error {
	if c == nil {
		return ErrNoPlatform
	}
	return c.call(ctx, http.MethodDelete, "/v1/orgs/"+url.PathEscape(id), nil, nil)
}

// CreateSharedWallet gives one organisation a tenant wallet in the
// shared agent. The platform takes a label of 2 to 25 characters.
func (c *Client) CreateSharedWallet(ctx context.Context, orgID, label string) error {
	if c == nil {
		return ErrNoPlatform
	}
	if r := []rune(strings.TrimSpace(label)); len(r) > 25 {
		label = string(r[:25])
	}
	body := map[string]string{"label": strings.TrimSpace(label)}
	return c.call(ctx, http.MethodPost, "/v1/orgs/"+url.PathEscape(orgID)+"/agents/wallet", body, nil)
}

// OrgDids reads the DIDs of one organisation, the primary DID first.
func (c *Client) OrgDids(ctx context.Context, orgID string) ([]OrgDid, error) {
	if c == nil {
		return nil, ErrNoPlatform
	}
	var out envelope[[]OrgDid]
	if err := c.call(ctx, http.MethodGet, "/v1/orgs/"+url.PathEscape(orgID)+"/dids", nil, &out); err != nil {
		return nil, err
	}
	dids := out.Data
	primaryFirst(dids)
	return dids, nil
}

// primaryFirst moves the primary DID to the front and keeps the order
// of the others.
func primaryFirst(dids []OrgDid) {
	for i, d := range dids {
		if d.IsPrimaryDid && i > 0 {
			copy(dids[1:i+1], dids[:i])
			dids[0] = d
			return
		}
	}
}

// SetPrimaryDid makes one DID of the organisation the one it signs
// with. The platform takes the DID and its record identifier.
func (c *Client) SetPrimaryDid(ctx context.Context, orgID string, did OrgDid) error {
	if c == nil {
		return ErrNoPlatform
	}
	body := map[string]string{"did": did.Did, "id": did.ID}
	return c.call(ctx, http.MethodPut, "/v1/orgs/"+url.PathEscape(orgID)+"/primary-did", body, nil)
}

// userPage is the answer of GET /v1/orgs/{org}/users.
type userPage struct {
	Users []struct {
		Email string `json:"email"`
		Roles []struct {
			OrgID string `json:"orgId"`
			Role  struct {
				Name string `json:"name"`
			} `json:"orgRole"`
		} `json:"userOrgRoles"`
	} `json:"users"`
}

// OrgMembers reads the people of one organisation with their roles
// there. It reads the first page of up to one hundred people.
func (c *Client) OrgMembers(ctx context.Context, orgID string) ([]OrgMember, error) {
	if c == nil {
		return nil, ErrNoPlatform
	}
	q := url.Values{"pageNumber": {"1"}, "pageSize": {"100"}}
	var out envelope[userPage]
	if err := c.call(ctx, http.MethodGet, "/v1/orgs/"+url.PathEscape(orgID)+"/users?"+q.Encode(), nil, &out); err != nil {
		return nil, err
	}
	members := make([]OrgMember, 0, len(out.Data.Users))
	for _, u := range out.Data.Users {
		m := OrgMember{Email: u.Email}
		for _, r := range u.Roles {
			if (r.OrgID == "" || r.OrgID == orgID) && r.Role.Name != "" {
				m.Roles = append(m.Roles, r.Role.Name)
			}
		}
		members = append(members, m)
	}
	return members, nil
}
