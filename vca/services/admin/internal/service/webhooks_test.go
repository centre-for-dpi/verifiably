// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

func (f *fakeAdapter) GetWebhook(_ context.Context, req *connect.Request[backendv1.GetWebhookRequest]) (*connect.Response[backendv1.GetWebhookResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hookErr != nil {
		return nil, f.hookErr
	}
	return connect.NewResponse(&backendv1.GetWebhookResponse{Webhook: &backendv1.Webhook{Url: f.hooks[req.Msg.GetTenantId()]}}), nil
}

func (f *fakeAdapter) SetWebhook(_ context.Context, req *connect.Request[backendv1.SetWebhookRequest]) (*connect.Response[backendv1.SetWebhookResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hookErr != nil {
		return nil, f.hookErr
	}
	f.hooks[req.Msg.GetTenantId()] = req.Msg.GetUrl()
	f.secrets[req.Msg.GetTenantId()] = req.Msg.GetSigningSecret()
	return connect.NewResponse(&backendv1.SetWebhookResponse{Webhook: &backendv1.Webhook{
		Url: req.Msg.GetUrl(), Signed: req.Msg.GetSigningSecret() != "", Fixed: true,
	}}), nil
}

func (f *fakeAdapter) GetNotificationEndpoint(_ context.Context, req *connect.Request[backendv1.GetNotificationEndpointRequest]) (*connect.Response[backendv1.GetNotificationEndpointResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.notifyErr != nil {
		return nil, f.notifyErr
	}
	return connect.NewResponse(&backendv1.GetNotificationEndpointResponse{Endpoint: &backendv1.NotificationEndpoint{
		Url: f.notify[req.Msg.GetTenantId()], KeptByAdapter: true, Fixed: true,
	}}), nil
}

func (f *fakeAdapter) SetNotificationEndpoint(_ context.Context, req *connect.Request[backendv1.SetNotificationEndpointRequest]) (*connect.Response[backendv1.SetNotificationEndpointResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.notifyErr != nil {
		return nil, f.notifyErr
	}
	f.notify[req.Msg.GetTenantId()] = req.Msg.GetUrl()
	return connect.NewResponse(&backendv1.SetNotificationEndpointResponse{Endpoint: &backendv1.NotificationEndpoint{
		Url: req.Msg.GetUrl(), KeptByAdapter: true, Fixed: true,
	}}), nil
}

// TestStackWebhookPassesTheSigningSecret is P6-C8: the secret of a set
// reaches the stack, the entry says the webhook is signed, and the audit
// record holds no secret.
func TestStackWebhookPassesTheSigningSecret(t *testing.T) {
	h := newHarness(t)
	fake, _ := withStacks(t, h, backendv1.Feature_FEATURE_WEBHOOKS)
	ctx := context.Background()
	if _, err := h.svc.BindTenant(ctx, request(h, &adminv1.BindTenantRequest{Id: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL})); err != nil {
		t.Fatal(err)
	}
	secret := "[sixteen or more characters]"
	set, err := h.svc.SetStackWebhook(ctx, request(h, &adminv1.SetStackWebhookRequest{
		TenantId: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL, Url: "https://hooks.health.example/vca", SigningSecret: secret,
	}))
	if err != nil || !set.Msg.GetWebhook().GetWebhook().GetSigned() || fake.secrets["org-1"] != secret {
		t.Fatalf("SetStackWebhook = %+v, %v, stack got %q", set, err, fake.secrets["org-1"])
	}
	for _, rec := range auditActions(t, h, "admin.SetStackWebhook") {
		if strings.Contains(rec.Target+rec.Detail, secret) {
			t.Errorf("the audit record holds the secret: %+v", rec)
		}
	}
}

// TestStackNotificationEndpointRPCs is P6-C8 (ADR-067): on a stack that
// lists holder notifications, the webhook entry of a tenant carries its
// notification address, and the admin registers one. A stack without
// the feature takes none.
func TestStackNotificationEndpointRPCs(t *testing.T) {
	h := newHarness(t)
	fake, _ := withStacks(t, h, backendv1.Feature_FEATURE_WEBHOOKS, backendv1.Feature_FEATURE_HOLDER_NOTIFICATIONS)
	ctx := context.Background()
	if _, err := h.svc.BindTenant(ctx, request(h, &adminv1.BindTenantRequest{Id: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL})); err != nil {
		t.Fatal(err)
	}
	set, err := h.svc.SetStackNotificationEndpoint(ctx, request(h, &adminv1.SetStackNotificationEndpointRequest{
		TenantId: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL, Url: " https://push.health.example/credebl ",
	}))
	if err != nil || set.Msg.GetWebhook().GetNotification().GetUrl() != "https://push.health.example/credebl" || fake.notify["org-1"] != "https://push.health.example/credebl" {
		t.Fatalf("SetStackNotificationEndpoint = %+v, %v", set, err)
	}
	list, err := h.svc.ListStackWebhooks(ctx, request(h, &adminv1.ListStackWebhooksRequest{}))
	if err != nil || len(list.Msg.GetWebhooks()) != 1 || list.Msg.GetWebhooks()[0].GetNotification().GetUrl() != "https://push.health.example/credebl" {
		t.Fatalf("ListStackWebhooks = %+v, %v", list, err)
	}
	if recs := auditActions(t, h, "admin.SetStackNotificationEndpoint"); len(recs) != 1 || !recs[0].OK || recs[0].Target != h.tenantID {
		t.Errorf("audit = %+v", recs)
	}
	fake.notifyErr = connect.NewError(connect.CodeUnavailable, errors.New("the notification service is down"))
	list, err = h.svc.ListStackWebhooks(ctx, request(h, &adminv1.ListStackWebhooksRequest{}))
	if err != nil || !strings.Contains(list.Msg.GetWebhooks()[0].GetNotificationError(), "down") {
		t.Errorf("a failed read gave %+v, %v", list, err)
	}
	_, err = h.svc.SetStackNotificationEndpoint(ctx, request(h, &adminv1.SetStackNotificationEndpointRequest{
		TenantId: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL, Url: "https://push.health.example/credebl",
	}))
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Errorf("a failed set gave %v", err)
	}
	for _, m := range []*adminv1.SetStackNotificationEndpointRequest{
		{TenantId: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL, Url: "http://push.health.example"},
		{TenantId: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL},
	} {
		if _, err := h.svc.SetStackNotificationEndpoint(ctx, request(h, m)); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%+v gave %v", m, err)
		}
	}
	if _, err := h.svc.SetStackNotificationEndpoint(ctx, request(h, &adminv1.SetStackNotificationEndpointRequest{
		TenantId: h.tenantID, Stack: configv1.Dpg_DPG_WALTID, Url: "https://push.health.example",
	})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("a stack with no binding gave %v", err)
	}
	if _, err := h.svc.SetStackNotificationEndpoint(ctx, connect.NewRequest(&adminv1.SetStackNotificationEndpointRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("an anonymous caller gave %v", err)
	}
	plain := newHarness(t)
	_, _ = withStacks(t, plain, backendv1.Feature_FEATURE_WEBHOOKS)
	if _, err := plain.svc.BindTenant(ctx, request(plain, &adminv1.BindTenantRequest{Id: plain.tenantID, Stack: configv1.Dpg_DPG_CREDEBL})); err != nil {
		t.Fatal(err)
	}
	if _, err := plain.svc.SetStackNotificationEndpoint(ctx, request(plain, &adminv1.SetStackNotificationEndpointRequest{
		TenantId: plain.tenantID, Stack: configv1.Dpg_DPG_CREDEBL, Url: "https://push.health.example",
	})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("a stack without the feature gave %v", err)
	}
	if list, err := plain.svc.ListStackWebhooks(ctx, request(plain, &adminv1.ListStackWebhooksRequest{})); err != nil || list.Msg.GetWebhooks()[0].GetNotification() != nil {
		t.Errorf("a stack without the feature listed %+v, %v", list, err)
	}
}

// TestStackWebhookRPCs is ADR-040 decision 2: the webhook of a stack
// tenant is read, set, and cleared through a stack that lists webhooks.
func TestStackWebhookRPCs(t *testing.T) {
	h := newHarness(t)
	fake, _ := withStacks(t, h, backendv1.Feature_FEATURE_WEBHOOKS)
	ctx := context.Background()
	if _, err := h.svc.BindTenant(ctx, request(h, &adminv1.BindTenantRequest{Id: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL})); err != nil {
		t.Fatal(err)
	}
	list, err := h.svc.ListStackWebhooks(ctx, request(h, &adminv1.ListStackWebhooksRequest{}))
	if err != nil || len(list.Msg.GetWebhooks()) != 1 {
		t.Fatalf("ListStackWebhooks = %+v, %v", list, err)
	}
	if w := list.Msg.GetWebhooks()[0]; w.GetTenantName() != "Admin tenant" || w.GetStackName() != "Tenancy stack" || w.GetWebhook().GetUrl() != "" {
		t.Fatalf("webhook = %+v", w)
	}
	set, err := h.svc.SetStackWebhook(ctx, request(h, &adminv1.SetStackWebhookRequest{
		TenantId: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL, Url: " https://hooks.health.example/vca ",
	}))
	if err != nil || set.Msg.GetWebhook().GetWebhook().GetUrl() != "https://hooks.health.example/vca" {
		t.Fatalf("SetStackWebhook = %+v, %v", set, err)
	}
	if fake.hooks["org-1"] != "https://hooks.health.example/vca" {
		t.Fatalf("the stack holds %q", fake.hooks["org-1"])
	}
	if _, cerr := h.svc.SetStackWebhook(ctx, request(h, &adminv1.SetStackWebhookRequest{
		TenantId: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL,
	})); cerr != nil || fake.hooks["org-1"] != "" {
		t.Fatalf("a clear gave %v, %q", cerr, fake.hooks["org-1"])
	}
	if recs := auditActions(t, h, "admin.SetStackWebhook"); len(recs) != 2 || !recs[0].OK || recs[0].Target != h.tenantID {
		t.Errorf("audit = %+v", recs)
	}
	fake.hookErr = connect.NewError(connect.CodeUnavailable, errors.New("the platform is down"))
	list, err = h.svc.ListStackWebhooks(ctx, request(h, &adminv1.ListStackWebhooksRequest{}))
	if err != nil || !strings.Contains(list.Msg.GetWebhooks()[0].GetError(), "down") {
		t.Errorf("a failed read gave %+v, %v", list, err)
	}
	if _, err := h.svc.SetStackWebhook(ctx, request(h, &adminv1.SetStackWebhookRequest{
		TenantId: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL, Url: "https://hooks.health.example/vca",
	})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Errorf("a failed set gave %v", err)
	}
}

func TestStackWebhookRefusals(t *testing.T) {
	h := newHarness(t)
	_, _ = withStacks(t, h)
	ctx := context.Background()
	if _, err := h.svc.BindTenant(ctx, request(h, &adminv1.BindTenantRequest{Id: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL})); err != nil {
		t.Fatal(err)
	}
	// The stack lists no webhooks: no entry, and a set fails.
	list, err := h.svc.ListStackWebhooks(ctx, request(h, &adminv1.ListStackWebhooksRequest{}))
	if err != nil || len(list.Msg.GetWebhooks()) != 0 {
		t.Errorf("a stack without webhooks listed %+v, %v", list, err)
	}
	cases := []struct {
		m    *adminv1.SetStackWebhookRequest
		code connect.Code
	}{
		{&adminv1.SetStackWebhookRequest{TenantId: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL, Url: "https://hooks.example/vca"}, connect.CodeFailedPrecondition},
		{&adminv1.SetStackWebhookRequest{TenantId: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL, Url: "http://hooks.example/vca"}, connect.CodeInvalidArgument},
		{&adminv1.SetStackWebhookRequest{TenantId: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL, Url: "hooks.example"}, connect.CodeInvalidArgument},
		{&adminv1.SetStackWebhookRequest{TenantId: h.tenantID, Stack: configv1.Dpg_DPG_WALTID, Url: "https://hooks.example/vca"}, connect.CodeNotFound},
	}
	for _, c := range cases {
		if _, err := h.svc.SetStackWebhook(ctx, request(h, c.m)); connect.CodeOf(err) != c.code {
			t.Errorf("%+v gave %v, want %v", c.m, err, c.code)
		}
	}
	for _, call := range []func() error{
		func() error {
			_, err := h.svc.ListStackWebhooks(ctx, connect.NewRequest(&adminv1.ListStackWebhooksRequest{}))
			return err
		},
		func() error {
			_, err := h.svc.SetStackWebhook(ctx, connect.NewRequest(&adminv1.SetStackWebhookRequest{}))
			return err
		},
	} {
		if connect.CodeOf(call()) != connect.CodeUnauthenticated {
			t.Error("an anonymous caller passed")
		}
	}
}
