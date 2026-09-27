// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// The webhook of an organisation and the address of the notification
// service of the platform (P6-C8, ADR-067). A tenant is an organisation
// (ADR-037). The platform calls the webhook on the events of the
// organisation and signs each call with the secret the tenant set. The
// notification service posts the push notifications of the holders of
// the organisation to its address. The capability answer lists
// FEATURE_WEBHOOKS and FEATURE_HOLDER_NOTIFICATIONS.

// MinSigningSecret is the shortest signing secret the platform takes
// (register-webhook-dto.ts).
const MinSigningSecret = 16

// fixedMessage says why a webhook stays once set.
const fixedMessage = "the platform keeps the webhook of an organisation once set; set another address instead"

// GetWebhook reads the webhook of one organisation.
func (s *Service) GetWebhook(
	ctx context.Context, req *connect.Request[backendv1.GetWebhookRequest],
) (*connect.Response[backendv1.GetWebhookResponse], error) {
	tenant, err := tenantID(req.Msg.GetTenantId())
	if err != nil {
		return nil, err
	}
	hook, err := s.client.OrgWebhook(ctx, tenant)
	if err != nil {
		return nil, failed("read the webhook of the organisation", err)
	}
	return connect.NewResponse(&backendv1.GetWebhookResponse{
		Webhook: &backendv1.Webhook{Url: hook.URL, Signed: hook.Signed(), Fixed: true},
	}), nil
}

// SetWebhook sets the address and, when the call names one, the
// signing secret of the webhook of one organisation. The adapter passes
// the secret on and keeps no copy. The platform takes no clear.
func (s *Service) SetWebhook(
	ctx context.Context, req *connect.Request[backendv1.SetWebhookRequest],
) (*connect.Response[backendv1.SetWebhookResponse], error) {
	tenant, err := tenantID(req.Msg.GetTenantId())
	if err != nil {
		return nil, err
	}
	address := strings.TrimSpace(req.Msg.GetUrl())
	if address == "" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New(fixedMessage))
	}
	if uerr := httpsURL(address); uerr != nil {
		return nil, uerr
	}
	secret := req.Msg.GetSigningSecret()
	if secret != "" && len(secret) < MinSigningSecret {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("the signing secret needs %d characters or more", MinSigningSecret))
	}
	hook, err := s.client.SetOrgWebhook(ctx, tenant, address, secret)
	if err != nil {
		return nil, failed("set the webhook of the organisation", err)
	}
	return connect.NewResponse(&backendv1.SetWebhookResponse{
		Webhook: &backendv1.Webhook{Url: hook.URL, Signed: hook.Signed(), Fixed: true},
	}), nil
}

// notifyRecord is what the store keeps of the address of the
// notification service of one organisation. The platform reports none.
type notifyRecord struct {
	// URL is the address.
	URL string `json:"url"`
	// At is when the platform took it.
	At time.Time `json:"at"`
}

// notifyKey is the store key of the address of one organisation.
func notifyKey(tenant string) string {
	sum := sha256.Sum256([]byte(tenant))
	return "notify/" + hex.EncodeToString(sum[:])
}

// storedEndpoint reads the address the adapter registered for one
// organisation. It reports false for none.
func (s *Service) storedEndpoint(ctx context.Context, tenant string) (notifyRecord, bool, error) {
	raw, err := s.store.Get(ctx, notifyKey(tenant))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return notifyRecord{}, false, nil
	case err != nil:
		return notifyRecord{}, false, connect.NewError(connect.CodeInternal, fmt.Errorf("read the notification address: %w", err))
	}
	var rec notifyRecord
	if json.Unmarshal(raw, &rec) != nil {
		return notifyRecord{}, false, connect.NewError(connect.CodeInternal, errors.New("the record of the notification address is damaged"))
	}
	return rec, true, nil
}

// endpointOf returns the proto message of a record.
func endpointOf(rec notifyRecord, found bool) *backendv1.NotificationEndpoint {
	out := &backendv1.NotificationEndpoint{KeptByAdapter: true, Fixed: true}
	if found {
		out.Url, out.UpdatedAt = rec.URL, timestamppb.New(rec.At)
	}
	return out
}

// GetNotificationEndpoint returns the address the adapter registered for
// one organisation. The platform reads it back through no call.
func (s *Service) GetNotificationEndpoint(
	ctx context.Context, req *connect.Request[backendv1.GetNotificationEndpointRequest],
) (*connect.Response[backendv1.GetNotificationEndpointResponse], error) {
	tenant, err := tenantID(req.Msg.GetTenantId())
	if err != nil {
		return nil, err
	}
	rec, found, err := s.storedEndpoint(ctx, tenant)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&backendv1.GetNotificationEndpointResponse{Endpoint: endpointOf(rec, found)}), nil
}

// SetNotificationEndpoint registers the address of one organisation. The
// platform keeps one address per organisation and takes no change, so a
// second registration is refused before it reaches the platform.
func (s *Service) SetNotificationEndpoint(
	ctx context.Context, req *connect.Request[backendv1.SetNotificationEndpointRequest],
) (*connect.Response[backendv1.SetNotificationEndpointResponse], error) {
	tenant, err := tenantID(req.Msg.GetTenantId())
	if err != nil {
		return nil, err
	}
	address := strings.TrimSpace(req.Msg.GetUrl())
	if uerr := httpsURL(address); uerr != nil {
		return nil, uerr
	}
	_, found, err := s.storedEndpoint(ctx, tenant)
	if err != nil {
		return nil, err
	}
	if found {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New(
			"the platform keeps the first notification address of an organisation and takes no change"))
	}
	at, err := s.client.RegisterNotificationEndpoint(ctx, tenant, address)
	if err != nil {
		return nil, failed("register the notification address of the organisation", err)
	}
	if at.IsZero() {
		at = s.now().UTC()
	}
	rec := notifyRecord{URL: address, At: at}
	if err := s.store.Put(ctx, notifyKey(tenant), anyval.Must(json.Marshal(rec))); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("keep the notification address: %w", err))
	}
	return connect.NewResponse(&backendv1.SetNotificationEndpointResponse{Endpoint: endpointOf(rec, true)}), nil
}

// tenantID checks the tenant id of a call.
func tenantID(id string) (string, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", connect.NewError(connect.CodeInvalidArgument, errors.New("the call names no tenant"))
	}
	return id, nil
}

// httpsURL checks an absolute https URL.
func httpsURL(address string) error {
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("the address must be an https URL"))
	}
	return nil
}
