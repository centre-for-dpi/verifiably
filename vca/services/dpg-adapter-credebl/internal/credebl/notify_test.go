// SPDX-License-Identifier: Apache-2.0

package credebl

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// P6-C8: the webhook, notification and client credential calls of the
// api gateway.

// doc reads one answer of testdata/doc as text.
func doc(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "doc", name)) // #nosec G304 -- a fixed test path
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestNotifyCalls: the webhook of an organisation reads with its
// signing state, a registration sends the address and the secret, the
// notification address returns the time of its row, and the client
// credential reads, creates and deletes. A not found reads as none.
func TestNotifyCalls(t *testing.T) {
	p := newProofServer(t)
	c, ctx := p.client(), context.Background()
	p.answers["GET /v1/webhooks/orgs/webhookurl"] = doc(t, "webhook-url.json")
	p.answers["POST /v1/webhooks/orgs/org-2/register"] = doc(t, "webhook-registered.json")
	p.answers["POST /v1/notification/register/webhook-endpoint"] = doc(t, "notification-endpoint-registered.json")
	p.answers["GET /v1/orgs/org-2/client_credentials"] = doc(t, "client-credentials.json")
	p.answers["POST /v1/orgs/org-2/client_credentials"] = doc(t, "client-credentials-created.json")
	p.answers["DELETE /v1/orgs/org-2/client_credentials"] = doc(t, "client-credentials-deleted.json")
	hook, err := c.OrgWebhook(ctx, "org-2")
	if err != nil || hook.URL != "https://hooks.example.org/vca" || !hook.Signed() || p.queries["GET /v1/webhooks/orgs/webhookurl"] != "orgId=org-2" {
		t.Fatalf("webhook = %+v, %v", hook, err)
	}
	if hook, err = c.SetOrgWebhook(ctx, "org-2", "https://hooks.example.org/vca", ""); err != nil || !hook.Signed() {
		t.Fatalf("set = %+v, %v", hook, err)
	}
	if body := string(p.bodies["POST /v1/webhooks/orgs/org-2/register"]); body != `{"webhookUrl":"https://hooks.example.org/vca"}` {
		t.Errorf("register body = %s", body)
	}
	at, err := c.RegisterNotificationEndpoint(ctx, "org-2", "https://push.example.org/credebl")
	if err != nil || at.IsZero() {
		t.Fatalf("notification = %v, %v", at, err)
	}
	cred, found, err := c.OrgClientCredential(ctx, "org-2")
	if err != nil || !found || cred.ClientID == "" {
		t.Fatalf("credential = %+v, %v, %v", cred, found, err)
	}
	id, secret, err := c.CreateOrgClientCredential(ctx, "org-2")
	if err != nil || id == "" || secret != "[client secret]" {
		t.Fatalf("create = %s, %s, %v", id, secret, err)
	}
	if derr := c.DeleteOrgClientCredential(ctx, "org-2"); derr != nil {
		t.Fatal(derr)
	}
	p.answers["POST /v1/orgs/org-2/client_credentials"] = `{"data":{"clientId":"x"}}`
	if _, _, cerr := c.CreateOrgClientCredential(ctx, "org-2"); cerr == nil {
		t.Error("an answer with no secret passed")
	}
	for _, key := range []string{"GET /v1/webhooks/orgs/webhookurl", "GET /v1/orgs/org-2/client_credentials"} {
		p.status[key] = http.StatusNotFound
	}
	if hook, err = c.OrgWebhook(ctx, "org-2"); err != nil || hook.URL != "" || hook.Signed() {
		t.Errorf("no agent row = %+v, %v", hook, err)
	}
	if _, found, err = c.OrgClientCredential(ctx, "org-2"); err != nil || found {
		t.Errorf("no credential = %v, %v", found, err)
	}
	for _, key := range []string{"GET /v1/webhooks/orgs/webhookurl", "GET /v1/orgs/org-2/client_credentials",
		"POST /v1/webhooks/orgs/org-2/register", "POST /v1/notification/register/webhook-endpoint", "POST /v1/orgs/org-2/client_credentials"} {
		p.status[key] = http.StatusBadGateway
	}
	_, e1 := c.OrgWebhook(ctx, "org-2")
	_, _, e2 := c.OrgClientCredential(ctx, "org-2")
	_, e3 := c.SetOrgWebhook(ctx, "org-2", "https://x.example", "")
	_, e4 := c.RegisterNotificationEndpoint(ctx, "org-2", "https://x.example")
	_, _, e5 := c.CreateOrgClientCredential(ctx, "org-2")
	for i, err := range []error{e1, e2, e3, e4, e5} {
		if err == nil {
			t.Errorf("call %d passed a failed platform", i+1)
		}
	}
}

// TestNotifyCallsNeedAPlatform: a client with no platform refuses every
// call.
func TestNotifyCallsNeedAPlatform(t *testing.T) {
	var c *Client
	ctx := context.Background()
	_, e1 := c.OrgWebhook(ctx, "o")
	_, e2 := c.SetOrgWebhook(ctx, "o", "u", "")
	_, e3 := c.RegisterNotificationEndpoint(ctx, "o", "u")
	_, _, e4 := c.OrgClientCredential(ctx, "o")
	_, _, e5 := c.CreateOrgClientCredential(ctx, "o")
	e6 := c.DeleteOrgClientCredential(ctx, "o")
	for i, err := range []error{e1, e2, e3, e4, e5, e6} {
		if !errors.Is(err, ErrNoPlatform) {
			t.Errorf("call %d: %v", i+1, err)
		}
	}
}
