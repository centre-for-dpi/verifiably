// SPDX-License-Identifier: Apache-2.0

package credebl

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// The webhook of an organisation, the address of the notification
// service, and the client credential of an organisation (P6-C8). The
// sources are the webhook, notification and organisation controllers of
// the release the stack file runs, read on 2026-09-27:
// https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/api-gateway/src/webhook/webhook.controller.ts
// https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/webhook/src/webhook.repository.ts
// https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/api-gateway/src/notification/notification.controller.ts
// https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/api-gateway/src/organization/organization.controller.ts
// https://raw.githubusercontent.com/credebl/platform/v2.2.1-alpha.4/apps/organization/src/organization.service.ts

// OrgWebhook is the webhook of one organisation. The platform keeps it
// on the agent row of the organisation.
type OrgWebhook struct {
	// URL is the address. Empty means none.
	URL string `json:"webhookUrl"`
	// Secret is the signing secret as the platform keeps it, encrypted.
	// The adapter reads only whether one exists.
	Secret *string `json:"webhookSecret"`
}

// Signed reports a webhook with a signing secret.
func (w OrgWebhook) Signed() bool { return w.Secret != nil && *w.Secret != "" }

// OrgWebhook reads the webhook of one organisation. An organisation with
// no agent row answers not found, which reads as no webhook.
func (c *Client) OrgWebhook(ctx context.Context, orgID string) (OrgWebhook, error) {
	if c == nil {
		return OrgWebhook{}, ErrNoPlatform
	}
	var out envelope[OrgWebhook]
	path := "/v1/webhooks/orgs/webhookurl?" + url.Values{"orgId": {orgID}}.Encode()
	if err := c.call(ctx, http.MethodGet, path, nil, &out); err != nil {
		if dpgclient.IsStatus(err, http.StatusNotFound) {
			return OrgWebhook{}, nil
		}
		return OrgWebhook{}, err
	}
	return out.Data, nil
}

// SetOrgWebhook registers the webhook of one organisation. The platform
// updates the agent row, so the call also changes an address. An empty
// secret keeps the secret the platform holds.
func (c *Client) SetOrgWebhook(ctx context.Context, orgID, address, secret string) (OrgWebhook, error) {
	if c == nil {
		return OrgWebhook{}, ErrNoPlatform
	}
	body := map[string]string{"webhookUrl": address}
	if secret != "" {
		body["webhookSecret"] = secret
	}
	var out envelope[OrgWebhook]
	if err := c.call(ctx, http.MethodPost, "/v1/webhooks/orgs/"+url.PathEscape(orgID)+"/register", body, &out); err != nil {
		return OrgWebhook{}, err
	}
	return out.Data, nil
}

// RegisterNotificationEndpoint registers the address that the
// notification service posts the notifications of the holders of one
// organisation to. The platform keeps one row per organisation and
// reads it back through no call. It returns the time of the row.
func (c *Client) RegisterNotificationEndpoint(ctx context.Context, orgID, address string) (time.Time, error) {
	if c == nil {
		return time.Time{}, ErrNoPlatform
	}
	var out envelope[struct {
		CreatedAt time.Time `json:"createDateTime"`
	}]
	body := map[string]string{"orgId": orgID, "notificationWebhook": address}
	if err := c.call(ctx, http.MethodPost, "/v1/notification/register/webhook-endpoint", body, &out); err != nil {
		return time.Time{}, err
	}
	return out.Data.CreatedAt, nil
}

// OrgClientCredential is the client credential of one organisation,
// without its secret. The platform returns the secret masked, and the
// adapter drops it.
type OrgClientCredential struct {
	// ClientID is the OAuth client id.
	ClientID string `json:"clientId"`
}

// OrgClientCredential reads the client credential of one organisation.
// It reports false for an organisation with none.
func (c *Client) OrgClientCredential(ctx context.Context, orgID string) (OrgClientCredential, bool, error) {
	if c == nil {
		return OrgClientCredential{}, false, ErrNoPlatform
	}
	var out envelope[OrgClientCredential]
	if err := c.call(ctx, http.MethodGet, "/v1/orgs/"+url.PathEscape(orgID)+"/client_credentials", nil, &out); err != nil {
		if dpgclient.IsStatus(err, http.StatusNotFound) {
			return OrgClientCredential{}, false, nil
		}
		return OrgClientCredential{}, false, err
	}
	return out.Data, out.Data.ClientID != "", nil
}

// CreateOrgClientCredential creates the client credential of one
// organisation. It returns the client id and the secret, which the
// platform never returns again.
func (c *Client) CreateOrgClientCredential(ctx context.Context, orgID string) (clientID, secret string, err error) {
	if c == nil {
		return "", "", ErrNoPlatform
	}
	var out envelope[struct {
		ClientID string `json:"clientId"`
		Secret   string `json:"clientSecret"`
	}]
	if err := c.call(ctx, http.MethodPost, "/v1/orgs/"+url.PathEscape(orgID)+"/client_credentials", nil, &out); err != nil {
		return "", "", err
	}
	if out.Data.ClientID == "" || out.Data.Secret == "" {
		return "", "", errors.New("credebl: the client credential answer has no client or no secret")
	}
	return out.Data.ClientID, out.Data.Secret, nil
}

// DeleteOrgClientCredential removes the client credential of one
// organisation and its client in the Keycloak of the platform.
func (c *Client) DeleteOrgClientCredential(ctx context.Context, orgID string) error {
	if c == nil {
		return ErrNoPlatform
	}
	return c.call(ctx, http.MethodDelete, "/v1/orgs/"+url.PathEscape(orgID)+"/client_credentials", nil, nil)
}
