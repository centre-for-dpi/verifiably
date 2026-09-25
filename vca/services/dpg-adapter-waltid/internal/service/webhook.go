// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

// webhookMessage says why the notification service answers
// Unimplemented. The community stack keeps no tenants to hold a webhook.
// The capability answer lists no FEATURE_WEBHOOKS, so the admin
// notifications page shows no webhook form for this stack (ADR-040
// decision 2).
const webhookMessage = "the adapter sets no walt.id webhook for a tenant; the community stack keeps no tenants"

// GetWebhook is not available. See webhookMessage.
func (s *Service) GetWebhook(
	context.Context, *connect.Request[backendv1.GetWebhookRequest],
) (*connect.Response[backendv1.GetWebhookResponse], error) {
	return nil, unimplemented(webhookMessage)
}

// SetWebhook is not available. See webhookMessage.
func (s *Service) SetWebhook(
	context.Context, *connect.Request[backendv1.SetWebhookRequest],
) (*connect.Response[backendv1.SetWebhookResponse], error) {
	return nil, unimplemented(webhookMessage)
}
