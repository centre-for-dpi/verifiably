// SPDX-License-Identifier: Apache-2.0

package credebl

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// The ecosystems of the platform (P6-C9, ADR-068). An ecosystem is a
// group of organisations that one lead organisation runs. The sources
// are the platform and ecosystem controllers and the ecosystem service
// of the release the stack file runs, read on 2026-09-27:
// https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/api-gateway/src/platform/platform.controller.ts
// https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/api-gateway/src/ecosystem/ecosystem.controller.ts
// https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/ecosystem/src/ecosystem.service.ts
// https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/ecosystem/repositories/ecosystem.repository.ts

// ecosystemPageSize is the largest page the platform serves.
const ecosystemPageSize = 100

// EcosystemOrg names one organisation of an ecosystem.
type EcosystemOrg struct {
	// ID is the id of the organisation.
	ID string `json:"id"`
	// Name is the name of the organisation.
	Name string `json:"name"`
}

// Ecosystem is one ecosystem as the list of an organisation shows it.
type Ecosystem struct {
	// ID is the id of the ecosystem.
	ID string `json:"id"`
	// Name is the name. The platform keeps each name once.
	Name string `json:"name"`
	// Description says what the ecosystem is for.
	Description string `json:"description"`
	// MemberCount counts the members without the lead.
	MemberCount int `json:"memberCount"`
	// Role is the role of the organisation of the list in the ecosystem.
	Role string `json:"role"`
	// Lead is the lead organisation. Nil when the platform names none.
	Lead *EcosystemOrg `json:"leadOrg"`
}

// EcosystemMember is one member organisation of an ecosystem.
type EcosystemMember struct {
	// Status is the state of the membership, such as ACTIVE.
	Status string `json:"status"`
	// At is when the organisation joined.
	At time.Time `json:"createDateTime"`
	// Org is the member organisation.
	Org EcosystemOrg `json:"organisation"`
}

// page is one page of a list of the ecosystem service.
type page[T any] struct {
	TotalPages int `json:"totalPages"`
	Data       []T `json:"data"`
}

// EcosystemsEnabled reports whether the ecosystems of the platform are
// on.
func (c *Client) EcosystemsEnabled(ctx context.Context) (bool, error) {
	if c == nil {
		return false, ErrNoPlatform
	}
	var out envelope[bool]
	if err := c.call(ctx, http.MethodGet, "/v1/ecosystem/status", nil, &out); err != nil {
		return false, err
	}
	return out.Data, nil
}

// SetEcosystemsEnabled turns the ecosystems of the platform on or off.
// The platform turns them on only when its realm keeps unmanaged user
// attributes.
func (c *Client) SetEcosystemsEnabled(ctx context.Context, on bool) error {
	if c == nil {
		return ErrNoPlatform
	}
	return c.call(ctx, http.MethodPut, "/v1/config/ecosystem", map[string]bool{"isEcosystemEnabled": on}, nil)
}

// CreateEcosystem creates one ecosystem that an organisation leads. The
// platform lets a user create an ecosystem only with an accepted
// invitation of the platform admin that no ecosystem used yet, so the
// platform admin of the adapter invites itself first. The platform
// writes the lead role to the Keycloak user of the caller, so the
// client forgets its token and the next call carries the role.
func (c *Client) CreateEcosystem(ctx context.Context, leadOrg, name, description string) (Ecosystem, error) {
	if c == nil {
		return Ecosystem{}, ErrNoPlatform
	}
	if err := c.call(ctx, http.MethodPost, "/v1/invitations", map[string]string{"email": c.account.Email}, nil); err != nil {
		return Ecosystem{}, err
	}
	var out envelope[Ecosystem]
	path := "/v1/ecosystem?" + url.Values{"orgId": {leadOrg}}.Encode()
	if err := c.call(ctx, http.MethodPost, path, map[string]string{"name": name, "description": description}, &out); err != nil {
		return Ecosystem{}, err
	}
	c.Forget()
	return out.Data, nil
}

// Ecosystems lists the ecosystems that one organisation leads or
// belongs to, page by page.
func (c *Client) Ecosystems(ctx context.Context, orgID string) ([]Ecosystem, error) {
	if c == nil {
		return nil, ErrNoPlatform
	}
	return readPages[Ecosystem](ctx, c, "/v1/ecosystem", url.Values{"orgId": {orgID}})
}

// EcosystemMembers lists the member organisations of one ecosystem,
// without the lead. The platform answers not found for none.
func (c *Client) EcosystemMembers(ctx context.Context, ecosystemID string) ([]EcosystemMember, error) {
	if c == nil {
		return nil, ErrNoPlatform
	}
	list, err := readPages[EcosystemMember](ctx, c, "/v1/ecosystem/members", url.Values{"ecosystemId": {ecosystemID}})
	if dpgclient.IsStatus(err, http.StatusNotFound) {
		return nil, nil
	}
	return list, err
}

// InviteEcosystemMember invites one organisation into an ecosystem. The
// platform accepts the invitation at once when the caller created the
// organisation. It mails the creator of the organisation otherwise.
func (c *Client) InviteEcosystemMember(ctx context.Context, ecosystemID, orgID string) error {
	if c == nil {
		return ErrNoPlatform
	}
	return c.call(ctx, http.MethodPost, "/v1/ecosystem/invitation", map[string]string{"ecosystemId": ecosystemID, "orgId": orgID}, nil)
}

// RemoveEcosystemMember removes one member organisation from an
// ecosystem. The platform answers bad request when no member matched.
func (c *Client) RemoveEcosystemMember(ctx context.Context, ecosystemID, orgID string) error {
	if c == nil {
		return ErrNoPlatform
	}
	body := map[string]any{"ecosystemId": ecosystemID, "orgIds": []string{orgID}}
	return c.call(ctx, http.MethodDelete, "/v1/ecosystem/member", body, nil)
}

// readPages reads every page of a list of the ecosystem service.
func readPages[T any](ctx context.Context, c *Client, path string, query url.Values) ([]T, error) {
	var all []T
	for n := 1; ; n++ {
		query.Set("pageNumber", strconv.Itoa(n))
		query.Set("pageSize", strconv.Itoa(ecosystemPageSize))
		var out envelope[page[T]]
		if err := c.call(ctx, http.MethodGet, path+"?"+query.Encode(), nil, &out); err != nil {
			return nil, err
		}
		all = append(all, out.Data.Data...)
		if n >= out.Data.TotalPages || len(out.Data.Data) == 0 {
			return all, nil
		}
	}
}
