// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

func (f *fakeAdapter) ListClientCredentials(_ context.Context, req *connect.Request[backendv1.ListClientCredentialsRequest]) (*connect.Response[backendv1.ListClientCredentialsResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.credErr != nil {
		return nil, f.credErr
	}
	return connect.NewResponse(&backendv1.ListClientCredentialsResponse{Credentials: f.creds[req.Msg.GetTenantId()]}), nil
}

func (f *fakeAdapter) CreateClientCredential(_ context.Context, req *connect.Request[backendv1.CreateClientCredentialRequest]) (*connect.Response[backendv1.CreateClientCredentialResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.credErr != nil {
		return nil, f.credErr
	}
	f.n++
	c := &backendv1.ClientCredential{
		Id: fmt.Sprintf("cred-%d", f.n), ClientId: fmt.Sprintf("client-%d", f.n), Name: req.Msg.GetName(), CreatedAt: timestamppb.Now(),
	}
	f.creds[req.Msg.GetTenantId()] = append(f.creds[req.Msg.GetTenantId()], c)
	return connect.NewResponse(&backendv1.CreateClientCredentialResponse{Credential: c, ClientSecret: "s3cr3t-value-" + c.GetId()}), nil
}

func (f *fakeAdapter) DeleteClientCredential(_ context.Context, req *connect.Request[backendv1.DeleteClientCredentialRequest]) (*connect.Response[backendv1.DeleteClientCredentialResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	list := f.creds[req.Msg.GetTenantId()]
	for i, c := range list {
		if c.GetId() == req.Msg.GetId() {
			f.creds[req.Msg.GetTenantId()] = append(list[:i], list[i+1:]...)
			return connect.NewResponse(&backendv1.DeleteClientCredentialResponse{}), nil
		}
	}
	return nil, connect.NewError(connect.CodeNotFound, errors.New("no credential"))
}

// TestStackCredentialRPCs is ADR-038 decision 2: a client credential of
// a stack tenant is created, listed without its secret, and deleted.
// The secret shows once and never reaches the audit log.
func TestStackCredentialRPCs(t *testing.T) {
	h := newHarness(t)
	_, _ = withStacks(t, h, backendv1.Feature_FEATURE_TENANT_CLIENT_CREDENTIALS)
	ctx := context.Background()
	if _, err := h.svc.BindTenant(ctx, request(h, &adminv1.BindTenantRequest{Id: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL})); err != nil {
		t.Fatal(err)
	}
	created, err := h.svc.CreateStackCredential(ctx, request(h, &adminv1.CreateStackCredentialRequest{
		TenantId: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL, DisplayName: "Payroll sync",
	}))
	if err != nil {
		t.Fatalf("CreateStackCredential: %v", err)
	}
	secret := created.Msg.GetClientSecret()
	c := created.Msg.GetCredential()
	if secret == "" || c.GetTenantId() != h.tenantID || c.GetStackName() != "Tenancy stack" ||
		c.GetCredential().GetClientId() == "" || c.GetCredential().GetName() != "Payroll sync" {
		t.Fatalf("created = %+v", created.Msg)
	}
	list, err := h.svc.ListStackCredentials(ctx, request(h, &adminv1.ListStackCredentialsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Msg.GetCredentials()) != 1 || strings.Contains(list.Msg.String(), secret) {
		t.Fatalf("list = %+v", list.Msg)
	}
	filtered, err := h.svc.ListStackCredentials(ctx, request(h, &adminv1.ListStackCredentialsRequest{TenantId: "other"}))
	if err != nil || len(filtered.Msg.GetCredentials()) != 0 {
		t.Fatalf("a tenant filter gave %+v, %v", filtered, err)
	}
	if _, derr := h.svc.DeleteStackCredential(ctx, request(h, &adminv1.DeleteStackCredentialRequest{
		TenantId: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL, Id: c.GetCredential().GetId(),
	})); derr != nil {
		t.Fatalf("DeleteStackCredential: %v", derr)
	}
	list, err = h.svc.ListStackCredentials(ctx, request(h, &adminv1.ListStackCredentialsRequest{}))
	if err != nil || len(list.Msg.GetCredentials()) != 0 {
		t.Fatalf("after the delete: %+v, %v", list, err)
	}
	for _, action := range []string{"admin.CreateStackCredential", "admin.DeleteStackCredential"} {
		recs := auditActions(t, h, action)
		if len(recs) != 1 || !recs[0].OK || recs[0].Target != c.GetCredential().GetId() {
			t.Errorf("%s audit = %+v", action, recs)
		}
		if strings.Contains(fmt.Sprint(recs), secret) {
			t.Errorf("%s audit holds the secret", action)
		}
	}
}

func TestStackCredentialsNeedTheFeatureAndABinding(t *testing.T) {
	h := newHarness(t)
	fake, _ := withStacks(t, h)
	ctx := context.Background()
	if _, err := h.svc.BindTenant(ctx, request(h, &adminv1.BindTenantRequest{Id: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL})); err != nil {
		t.Fatal(err)
	}
	fake.creds["org-1"] = []*backendv1.ClientCredential{{Id: "cred-9", ClientId: "client-9"}}
	_, err := h.svc.CreateStackCredential(ctx, request(h, &adminv1.CreateStackCredentialRequest{
		TenantId: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL, DisplayName: "x",
	}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("a stack without the feature gave %v", err)
	}
	list, err := h.svc.ListStackCredentials(ctx, request(h, &adminv1.ListStackCredentialsRequest{}))
	if err != nil || len(list.Msg.GetCredentials()) != 0 {
		t.Errorf("a stack without the feature listed %+v, %v", list, err)
	}
	if _, err := h.svc.DeleteStackCredential(ctx, request(h, &adminv1.DeleteStackCredentialRequest{
		TenantId: h.tenantID, Stack: configv1.Dpg_DPG_WALTID, Id: "cred-9",
	})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("a stack without a binding gave %v", err)
	}
}

func TestStackCredentialErrors(t *testing.T) {
	h := newHarness(t)
	fake, _ := withStacks(t, h, backendv1.Feature_FEATURE_TENANT_CLIENT_CREDENTIALS)
	ctx := context.Background()
	if _, err := h.svc.BindTenant(ctx, request(h, &adminv1.BindTenantRequest{Id: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL})); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.CreateStackCredential(ctx, request(h, &adminv1.CreateStackCredentialRequest{
		TenantId: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL, DisplayName: " ",
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("an empty name gave %v", err)
	}
	if _, err := h.svc.CreateStackCredential(ctx, request(h, &adminv1.CreateStackCredentialRequest{
		TenantId: "missing", Stack: configv1.Dpg_DPG_CREDEBL, DisplayName: "x",
	})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("an unknown tenant gave %v", err)
	}
	if _, err := h.svc.DeleteStackCredential(ctx, request(h, &adminv1.DeleteStackCredentialRequest{
		TenantId: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL, Id: "cred-404",
	})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("an unknown credential gave %v", err)
	}
	fake.credErr = connect.NewError(connect.CodeUnavailable, errors.New("the platform is down"))
	list, err := h.svc.ListStackCredentials(ctx, request(h, &adminv1.ListStackCredentialsRequest{}))
	if err != nil || len(list.Msg.GetErrors()) != 1 || !strings.Contains(list.Msg.GetErrors()[0], "Tenancy stack") {
		t.Errorf("a stack that fails gave %+v, %v", list, err)
	}
	if _, err := h.svc.CreateStackCredential(ctx, request(h, &adminv1.CreateStackCredentialRequest{
		TenantId: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL, DisplayName: "x",
	})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Errorf("a stack that fails gave %v", err)
	}
	for _, call := range []func() error{
		func() error {
			_, err := h.svc.ListStackCredentials(ctx, connect.NewRequest(&adminv1.ListStackCredentialsRequest{}))
			return err
		},
		func() error {
			_, err := h.svc.CreateStackCredential(ctx, connect.NewRequest(&adminv1.CreateStackCredentialRequest{}))
			return err
		},
		func() error {
			_, err := h.svc.DeleteStackCredential(ctx, connect.NewRequest(&adminv1.DeleteStackCredentialRequest{}))
			return err
		},
	} {
		if connect.CodeOf(call()) != connect.CodeUnauthenticated {
			t.Error("an anonymous caller passed")
		}
	}
}
