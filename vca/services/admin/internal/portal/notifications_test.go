// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
)

// webhookHarness is a signed in harness whose tenancy stack lists the
// features, with one tenant bound on it.
func webhookHarness(t *testing.T, features ...backendv1.Feature) (*harness, *fakeStack, string) {
	t.Helper()
	return credentialHarness(t, features...)
}

// TestNotificationsPageNeverSaysSoon is ADR-040 decision 1: the page
// names what is not built in plain words and never promises a date.
func TestNotificationsPageNeverSaysSoon(t *testing.T) {
	with, _, _ := webhookHarness(t, backendv1.Feature_FEATURE_WEBHOOKS)
	bare := newHarness(t, true)
	bare.signIn(t)
	for name, h := range map[string]*harness{"webhooks": with, "bare": bare} {
		body := strings.ToLower(h.page(t, "/admin/notifications"))
		for _, word := range []string{"soon", "coming"} {
			if strings.Contains(body, word) {
				t.Errorf("%s: the page says %q", name, word)
			}
		}
	}
}

// TestVcaDeliveryRowsSayNotBuilt lists the VCA delivery channels, each
// marked "Not built in this release".
func TestVcaDeliveryRowsSayNotBuilt(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	page := h.page(t, "/admin/notifications")
	notBuilt := strings.TrimSuffix(msg.T("admin.notifications.not_built"), ".")
	if notBuilt != "Not built in this release" {
		t.Fatalf("the label reads %q", notBuilt)
	}
	for _, channel := range []string{"email", "sms"} {
		label := msg.T("admin.notifications.channel." + channel + ".label")
		i := strings.Index(page, label)
		if i < 0 {
			t.Errorf("the page misses the channel %q", label)
			continue
		}
		row := page[i:]
		row = row[:strings.Index(row, "</tr>")]
		if !strings.Contains(row, notBuilt) {
			t.Errorf("the row of %q does not say %q", label, notBuilt)
		}
	}
	if !strings.Contains(page, `<a href="/admin/notifications" aria-current="page"`) {
		t.Error("the side navigation does not mark the page")
	}
}

// TestWebhookFormOnlyWithFeature is ADR-040 decision 2: the live DPG
// webhook form shows only where a live adapter lists webhooks, and it
// sets the webhook of the stack tenant.
func TestWebhookFormOnlyWithFeature(t *testing.T) {
	h, tenancy, tenant := webhookHarness(t, backendv1.Feature_FEATURE_WEBHOOKS)
	page := h.page(t, "/admin/notifications")
	for _, want := range []string{msg.T("admin.notifications.webhooks.label"), `name="url"`, "Ministry of Health", "Tenancy stack"} {
		if !strings.Contains(page, want) {
			t.Errorf("the page misses %q", want)
		}
	}
	if !strings.Contains(page, `value="`+tenant+`|DPG_CREDEBL"`) {
		t.Error("the form does not offer the stack tenant")
	}
	status, _ := h.post(t, "/admin/notifications/webhook", url.Values{
		"target": {tenant + "|DPG_CREDEBL"}, "url": {"https://hooks.health.example/vca"},
	})
	if status != http.StatusSeeOther {
		t.Fatalf("set = %d", status)
	}
	if tenancy.hooks["org-1"] != "https://hooks.health.example/vca" {
		t.Fatalf("the stack holds %q", tenancy.hooks["org-1"])
	}
	saved := h.page(t, "/admin/notifications?notice=webhook-saved")
	for _, want := range []string{"https://hooks.health.example/vca", msg.T("admin.notifications.webhook.clear.label")} {
		if !strings.Contains(saved, want) {
			t.Errorf("the saved page misses %q", want)
		}
	}
	if status, _ := h.post(t, "/admin/notifications/webhook", url.Values{"target": {tenant + "|DPG_CREDEBL"}}); status != http.StatusSeeOther || tenancy.hooks["org-1"] != "" {
		t.Errorf("a clear gave %d, %q", status, tenancy.hooks["org-1"])
	}
	for _, bad := range []url.Values{
		{"target": {tenant + "|DPG_CREDEBL"}, "url": {"http://plain.example"}},
		{"target": {tenant + "|NOPE"}},
		{"target": {"no-separator"}},
	} {
		if status, _ := h.post(t, "/admin/notifications/webhook", bad); status != http.StatusBadRequest {
			t.Errorf("%v gave %d", bad, status)
		}
	}
	without, _, _ := webhookHarness(t)
	bare := newHarness(t, true)
	bare.signIn(t)
	for name, hh := range map[string]*harness{"tenancy only": without, "bare": bare} {
		page := hh.page(t, "/admin/notifications")
		for _, gone := range []string{msg.T("admin.notifications.webhooks.label"), `name="url"`} {
			if strings.Contains(page, gone) {
				t.Errorf("%s: the page shows %q", name, gone)
			}
		}
	}
}

// TestWebhookSectionWithoutABindingPointsAtTenants shows the empty state
// when no tenant sits on a stack with webhooks.
func TestWebhookSectionWithoutABindingPointsAtTenants(t *testing.T) {
	tenancy := newFakeStack("Tenancy stack", backendv1.Feature_FEATURE_MULTI_TENANCY, backendv1.Feature_FEATURE_WEBHOOKS)
	h := newHarnessWith(t, true, stackPeers(tenancy, nil))
	h.signIn(t)
	page := h.page(t, "/admin/notifications")
	if !strings.Contains(page, msg.T("admin.notifications.webhooks.empty.title")) || strings.Contains(page, `name="url"`) {
		t.Error("the page offers a webhook form without a bound tenant")
	}
}
