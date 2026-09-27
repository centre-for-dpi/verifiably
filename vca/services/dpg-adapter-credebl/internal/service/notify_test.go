// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// P6-C8: the webhook of an organisation, the address of the
// notification service, and the client credentials of an organisation
// (ADR-067).

// tenantOrg is an organisation of the recorded answers other than the
// organisation of the adapter.
const tenantOrg = "org-2"

// signingSecret is a signing secret of 16 characters or more.
const signingSecret = "[sixteen or more characters]" //nolint:gosec // G101: a placeholder of the tests, not a credential.

// TestSetWebhook is P6-C8: the webhook of an organisation reads as none
// first. A set registers the address and the signing secret through the
// webhook controller of the platform. The platform keeps a webhook once
// set, so the answer says so, and a clear is refused with the reason.
// The secret never comes back.
func TestSetWebhook(t *testing.T) {
	svc, f := newService(t, nil)
	ctx := context.Background()
	got, err := svc.GetWebhook(ctx, connect.NewRequest(&backendv1.GetWebhookRequest{TenantId: tenantOrg}))
	if err != nil {
		t.Fatal(err)
	}
	if hook := got.Msg.GetWebhook(); hook.GetUrl() != "" || hook.GetSigned() || !hook.GetFixed() {
		t.Fatalf("no webhook = %+v", hook)
	}
	if q := f.Query("/v1/webhooks/orgs/webhookurl"); q != "orgId="+tenantOrg {
		t.Errorf("query = %q", q)
	}
	set, err := svc.SetWebhook(ctx, connect.NewRequest(&backendv1.SetWebhookRequest{
		TenantId: tenantOrg, Url: "https://hooks.example.org/vca", SigningSecret: signingSecret,
	}))
	if err != nil {
		t.Fatalf("SetWebhook: %v", err)
	}
	if hook := set.Msg.GetWebhook(); hook.GetUrl() != "https://hooks.example.org/vca" || !hook.GetSigned() || !hook.GetFixed() {
		t.Fatalf("set = %+v", hook)
	}
	var body struct {
		URL    string `json:"webhookUrl"`
		Secret string `json:"webhookSecret"`
	}
	if rerr := f.RequestJSON("/v1/webhooks/orgs/"+tenantOrg+"/register", &body); rerr != nil || body.URL != "https://hooks.example.org/vca" || body.Secret != signingSecret {
		t.Fatalf("register body = %+v, %v", body, rerr)
	}
	raw, err := protojson.Marshal(set.Msg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret") || strings.Contains(string(raw), signingSecret) {
		t.Errorf("the answer carries the secret: %s", raw)
	}
	got, err = svc.GetWebhook(ctx, connect.NewRequest(&backendv1.GetWebhookRequest{TenantId: tenantOrg}))
	if err != nil || got.Msg.GetWebhook().GetUrl() != "https://hooks.example.org/vca" || !got.Msg.GetWebhook().GetSigned() {
		t.Fatalf("after the set = %+v, %v", got, err)
	}
	// A set with no secret keeps the secret of the platform.
	if _, err = svc.SetWebhook(ctx, connect.NewRequest(&backendv1.SetWebhookRequest{TenantId: tenantOrg, Url: "https://hooks.example.org/vca"})); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(f.Request("/v1/webhooks/orgs/"+tenantOrg+"/register")), "webhookSecret") {
		t.Error("a set with no secret sent one")
	}
	_, err = svc.SetWebhook(ctx, connect.NewRequest(&backendv1.SetWebhookRequest{TenantId: tenantOrg}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "keeps") {
		t.Errorf("a clear: %v", err)
	}
	for name, req := range map[string]*backendv1.SetWebhookRequest{
		"no tenant":    {Url: "https://hooks.example.org/vca"},
		"plain http":   {TenantId: tenantOrg, Url: "http://hooks.example.org/vca"},
		"short secret": {TenantId: tenantOrg, Url: "https://hooks.example.org/vca", SigningSecret: "short"},
	} {
		_, err = svc.SetWebhook(ctx, connect.NewRequest(req))
		wantCode(t, err, connect.CodeInvalidArgument)
		_ = name
	}
	_, err = svc.GetWebhook(ctx, connect.NewRequest(&backendv1.GetWebhookRequest{}))
	wantCode(t, err, connect.CodeInvalidArgument)
	f.SetStatus("/v1/webhooks/orgs/webhookurl", 404)
	if got, err = svc.GetWebhook(ctx, connect.NewRequest(&backendv1.GetWebhookRequest{TenantId: tenantOrg})); err != nil || got.Msg.GetWebhook().GetUrl() != "" {
		t.Errorf("an organisation with no agent row = %+v, %v", got, err)
	}
	f.SetStatus("/v1/webhooks/orgs/webhookurl", 500)
	_, err = svc.GetWebhook(ctx, connect.NewRequest(&backendv1.GetWebhookRequest{TenantId: tenantOrg}))
	wantCode(t, err, connect.CodeUnavailable)
	f.SetStatus("/v1/webhooks/orgs/"+tenantOrg+"/register", 500)
	_, err = svc.SetWebhook(ctx, connect.NewRequest(&backendv1.SetWebhookRequest{TenantId: tenantOrg, Url: "https://hooks.example.org/vca"}))
	wantCode(t, err, connect.CodeUnavailable)
}

// TestNotificationEndpoint is P6-C8: the notification service of the
// platform takes one address per organisation and reports none, so the
// adapter keeps the address it registered and says so. A second
// registration is refused before it reaches the platform.
func TestNotificationEndpoint(t *testing.T) {
	kv := store.Memory()
	svc, f := newService(t, func(o *service.Options) { o.Store = kv })
	ctx := context.Background()
	got, err := svc.GetNotificationEndpoint(ctx, connect.NewRequest(&backendv1.GetNotificationEndpointRequest{TenantId: tenantOrg}))
	if err != nil || got.Msg.GetEndpoint().GetUrl() != "" || !got.Msg.GetEndpoint().GetKeptByAdapter() {
		t.Fatalf("none = %+v, %v", got, err)
	}
	set, err := svc.SetNotificationEndpoint(ctx, connect.NewRequest(&backendv1.SetNotificationEndpointRequest{
		TenantId: tenantOrg, Url: "https://push.example.org/credebl",
	}))
	if err != nil {
		t.Fatalf("SetNotificationEndpoint: %v", err)
	}
	if e := set.Msg.GetEndpoint(); e.GetUrl() != "https://push.example.org/credebl" || e.GetUpdatedAt() == nil || !e.GetKeptByAdapter() {
		t.Fatalf("set = %+v", e)
	}
	var body struct {
		OrgID string `json:"orgId"`
		URL   string `json:"notificationWebhook"`
	}
	if rerr := f.RequestJSON("/v1/notification/register/webhook-endpoint", &body); rerr != nil || body.OrgID != tenantOrg || body.URL != "https://push.example.org/credebl" {
		t.Fatalf("body = %+v, %v", body, rerr)
	}
	got, err = svc.GetNotificationEndpoint(ctx, connect.NewRequest(&backendv1.GetNotificationEndpointRequest{TenantId: tenantOrg}))
	if err != nil || got.Msg.GetEndpoint().GetUrl() != "https://push.example.org/credebl" {
		t.Fatalf("after the set = %+v, %v", got, err)
	}
	calls := len(f.Calls())
	_, err = svc.SetNotificationEndpoint(ctx, connect.NewRequest(&backendv1.SetNotificationEndpointRequest{TenantId: tenantOrg, Url: "https://push.example.org/other"}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || len(f.Calls()) != calls {
		t.Errorf("a second address: %v, calls %d -> %d", err, calls, len(f.Calls()))
	}
	for _, req := range []*backendv1.SetNotificationEndpointRequest{
		{Url: "https://push.example.org/credebl"}, {TenantId: "org-3", Url: "http://push.example.org"}, {TenantId: "org-3"},
	} {
		_, err = svc.SetNotificationEndpoint(ctx, connect.NewRequest(req))
		wantCode(t, err, connect.CodeInvalidArgument)
	}
	_, err = svc.GetNotificationEndpoint(ctx, connect.NewRequest(&backendv1.GetNotificationEndpointRequest{}))
	wantCode(t, err, connect.CodeInvalidArgument)
	f.SetStatus("/v1/notification/register/webhook-endpoint", 500)
	_, err = svc.SetNotificationEndpoint(ctx, connect.NewRequest(&backendv1.SetNotificationEndpointRequest{TenantId: "org-3", Url: "https://push.example.org/credebl"}))
	wantCode(t, err, connect.CodeUnavailable)
	broken, _ := newService(t, func(o *service.Options) { o.Store = failingStore{store.Memory()} })
	_, err = broken.GetNotificationEndpoint(ctx, connect.NewRequest(&backendv1.GetNotificationEndpointRequest{TenantId: tenantOrg}))
	wantCode(t, err, connect.CodeInternal)
	_, err = broken.SetNotificationEndpoint(ctx, connect.NewRequest(&backendv1.SetNotificationEndpointRequest{TenantId: tenantOrg, Url: "https://push.example.org/credebl"}))
	wantCode(t, err, connect.CodeInternal)
}

// TestClientCredentialCreatedOnce is P6-C8 (ADR-038 decision 2): an
// organisation holds one client credential. A create returns the secret
// once. A list names the client and never the secret, not even masked.
// A second create is refused, because the platform would replace the
// secret. A delete removes the credential of that client only.
func TestClientCredentialCreatedOnce(t *testing.T) {
	kv := store.Memory()
	svc, f := newService(t, func(o *service.Options) { o.Store = kv })
	ctx := context.Background()
	list, err := svc.ListClientCredentials(ctx, connect.NewRequest(&backendv1.ListClientCredentialsRequest{TenantId: tenantOrg}))
	if err != nil || len(list.Msg.GetCredentials()) != 0 {
		t.Fatalf("none = %+v, %v", list, err)
	}
	created, err := svc.CreateClientCredential(ctx, connect.NewRequest(&backendv1.CreateClientCredentialRequest{TenantId: tenantOrg, Name: "Farm registry"}))
	if err != nil {
		t.Fatalf("CreateClientCredential: %v", err)
	}
	c := created.Msg.GetCredential()
	if created.Msg.GetClientSecret() != "[client secret]" || c.GetClientId() != "0b5c7f3e-2a91-4d6b-8e4f-1c2d3e4f5a6b" || c.GetId() != c.GetClientId() || c.GetName() == "" {
		t.Fatalf("created = %+v", created.Msg)
	}
	list, err = svc.ListClientCredentials(ctx, connect.NewRequest(&backendv1.ListClientCredentialsRequest{TenantId: tenantOrg}))
	if err != nil || len(list.Msg.GetCredentials()) != 1 || list.Msg.GetCredentials()[0].GetClientId() != c.GetClientId() {
		t.Fatalf("list = %+v, %v", list, err)
	}
	raw, err := json.Marshal(list.Msg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "*") || strings.Contains(string(raw), "last five") {
		t.Errorf("the list carries the masked secret: %s", raw)
	}
	keys, err := kv.List(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		value, gerr := kv.Get(ctx, k)
		if gerr == nil && strings.Contains(string(value), "[client secret]") {
			t.Errorf("the store keeps the secret under %s", k)
		}
	}
	_, err = svc.CreateClientCredential(ctx, connect.NewRequest(&backendv1.CreateClientCredentialRequest{TenantId: tenantOrg, Name: "again"}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "one client credential") {
		t.Errorf("a second create: %v", err)
	}
	if n := countOf(f.Calls(), "POST /v1/orgs/"+tenantOrg+"/client_credentials"); n != 1 {
		t.Errorf("the platform got %d creates", n)
	}
	_, err = svc.DeleteClientCredential(ctx, connect.NewRequest(&backendv1.DeleteClientCredentialRequest{TenantId: tenantOrg, Id: "another"}))
	wantCode(t, err, connect.CodeNotFound)
	if _, err = svc.DeleteClientCredential(ctx, connect.NewRequest(&backendv1.DeleteClientCredentialRequest{TenantId: tenantOrg, Id: c.GetId()})); err != nil {
		t.Fatalf("DeleteClientCredential: %v", err)
	}
	list, err = svc.ListClientCredentials(ctx, connect.NewRequest(&backendv1.ListClientCredentialsRequest{TenantId: tenantOrg}))
	if err != nil || len(list.Msg.GetCredentials()) != 0 {
		t.Errorf("after the delete = %+v, %v", list, err)
	}
	for _, call := range []func() error{
		func() error {
			_, e := svc.ListClientCredentials(ctx, connect.NewRequest(&backendv1.ListClientCredentialsRequest{}))
			return e
		},
		func() error {
			_, e := svc.CreateClientCredential(ctx, connect.NewRequest(&backendv1.CreateClientCredentialRequest{}))
			return e
		},
		func() error {
			_, e := svc.DeleteClientCredential(ctx, connect.NewRequest(&backendv1.DeleteClientCredentialRequest{TenantId: tenantOrg}))
			return e
		},
	} {
		wantCode(t, call(), connect.CodeInvalidArgument)
	}
	f.SetStatus("/v1/orgs/"+tenantOrg+"/client_credentials", 500)
	_, err = svc.ListClientCredentials(ctx, connect.NewRequest(&backendv1.ListClientCredentialsRequest{TenantId: tenantOrg}))
	wantCode(t, err, connect.CodeUnavailable)
	f.SetStatus("/v1/orgs/"+tenantOrg+"/client_credentials", 500)
	_, err = svc.CreateClientCredential(ctx, connect.NewRequest(&backendv1.CreateClientCredentialRequest{TenantId: tenantOrg}))
	wantCode(t, err, connect.CodeUnavailable)
}

// countOf returns the number of calls to the method and path.
func countOf(calls []string, key string) int {
	n := 0
	for _, c := range calls {
		if c == key {
			n++
		}
	}
	return n
}

// TestFeaturesListed is P6-C8: the capability answer lists the webhooks,
// the client credentials of a tenant, and the holder notifications, so
// the admin pages show them for this stack.
func TestFeaturesListed(t *testing.T) {
	svc, _ := newService(t, nil)
	caps, err := svc.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []backendv1.Feature{
		backendv1.Feature_FEATURE_WEBHOOKS, backendv1.Feature_FEATURE_TENANT_CLIENT_CREDENTIALS, backendv1.Feature_FEATURE_HOLDER_NOTIFICATIONS,
	} {
		if !slices.Contains(caps.Msg.GetFeatures(), want) {
			t.Errorf("the answer lists no %v: %v", want, caps.Msg.GetFeatures())
		}
	}
}
