// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"connectrpc.com/connect"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/records"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/stacks"
)

// webhooks is the feature a stack lists when it calls a webhook per
// tenant.
const webhooks = backendv1.Feature_FEATURE_WEBHOOKS

// ListStackWebhooks implements AdminServiceHandler. It reads the webhook
// of every stack tenant on a stack that lists webhooks (ADR-040
// decision 2). A stack tenant that the adapter cannot read carries the
// reason in its entry.
func (s *Service) ListStackWebhooks(ctx context.Context, req *connect.Request[adminv1.ListStackWebhooksRequest]) (*connect.Response[adminv1.ListStackWebhooksResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	res, err := s.listStackWebhooks(ctx)
	if serr := s.write(ctx, id.Actor, "admin.ListStackWebhooks", "", err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(res), nil
}

// listStackWebhooks does the work of ListStackWebhooks.
func (s *Service) listStackWebhooks(ctx context.Context) (*adminv1.ListStackWebhooksResponse, error) {
	all, err := s.d.Records.ListTenants(ctx)
	if err != nil {
		return nil, err
	}
	offered := map[configv1.Dpg]stacks.Stack{}
	for _, st := range s.d.Stacks.List(ctx) {
		if st.Has(webhooks) {
			offered[st.Dpg] = st
		}
	}
	res := &adminv1.ListStackWebhooksResponse{}
	for _, t := range all {
		for _, b := range t.Bindings {
			st, ok := offered[dpgValue(b.Stack)]
			if !ok {
				continue
			}
			entry := &adminv1.StackWebhook{TenantId: t.ID, TenantName: t.DisplayName, Stack: st.Dpg, StackName: st.Name}
			got, gerr := s.d.Stacks.Notifications(st).GetWebhook(ctx, connect.NewRequest(&backendv1.GetWebhookRequest{TenantId: b.TenantID}))
			if gerr != nil {
				entry.Error = gerr.Error()
			} else {
				entry.Webhook = got.Msg.GetWebhook()
			}
			res.Webhooks = append(res.Webhooks, entry)
		}
	}
	return res, nil
}

// SetStackWebhook implements AdminServiceHandler. An empty URL clears
// the webhook. A URL must use https.
func (s *Service) SetStackWebhook(ctx context.Context, req *connect.Request[adminv1.SetStackWebhookRequest]) (*connect.Response[adminv1.SetStackWebhookResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	res, err := s.setStackWebhook(ctx, req.Msg)
	if serr := s.write(ctx, id.Actor, "admin.SetStackWebhook", req.Msg.GetTenantId(), err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(&adminv1.SetStackWebhookResponse{Webhook: res}), nil
}

// setStackWebhook does the work of SetStackWebhook.
func (s *Service) setStackWebhook(ctx context.Context, m *adminv1.SetStackWebhookRequest) (*adminv1.StackWebhook, error) {
	hook := strings.TrimSpace(m.GetUrl())
	if hook != "" {
		u, err := url.Parse(hook)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, fmt.Errorf("%w: the webhook must be an https URL", records.ErrInvalid)
		}
	}
	tenant, err := s.d.Records.GetTenant(ctx, m.GetTenantId())
	if err != nil {
		return nil, err
	}
	b, ok := tenant.Binding(m.GetStack().String())
	if !ok {
		return nil, fmt.Errorf("%w: the tenant has no binding on %s", records.ErrNotFound, m.GetStack())
	}
	st, err := s.d.Stacks.Find(ctx, m.GetStack(), webhooks)
	if err != nil {
		return nil, err
	}
	res, err := s.d.Stacks.Notifications(st).SetWebhook(ctx, connect.NewRequest(&backendv1.SetWebhookRequest{TenantId: b.TenantID, Url: hook}))
	if err != nil {
		return nil, stackError(st, "set the webhook", err)
	}
	return &adminv1.StackWebhook{
		TenantId: tenant.ID, TenantName: tenant.DisplayName, Stack: st.Dpg, StackName: st.Name, Webhook: res.Msg.GetWebhook(),
	}, nil
}
