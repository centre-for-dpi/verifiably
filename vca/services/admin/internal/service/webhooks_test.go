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
	return connect.NewResponse(&backendv1.SetWebhookResponse{Webhook: &backendv1.Webhook{Url: req.Msg.GetUrl()}}), nil
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
