// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"strings"
	"testing"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1/datasourcev1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1/issuancev1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1/issuedv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1/schemav1connect"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/internal/rolenav"
	"github.com/centre-for-dpi/vc-adapters/services/internal/helptext"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// featureSets are the answers of the adapter the notification tests
// run: none, each stack feature alone, and both.
var featureSets = [][]backendv1.Feature{
	nil,
	{backendv1.Feature_FEATURE_WEBHOOKS},
	{backendv1.Feature_FEATURE_SESSION_CALLBACKS},
	{backendv1.Feature_FEATURE_WEBHOOKS, backendv1.Feature_FEATURE_SESSION_CALLBACKS},
}

// TestIssuerNotificationsNeverSaysSoon is ADR-040 decision 1 on every
// answer of the adapter: the VCA delivery rows say "Not built in this
// release", and no word promises a date.
func TestIssuerNotificationsNeverSaysSoon(t *testing.T) {
	for _, features := range featureSets {
		h := newHarness(t, features...)
		doc := body(t, h.get(t, "/notifications/"))
		a11ytest.AssertPage(t, doc)
		lower := strings.ToLower(doc)
		for _, word := range []string{"soon", "coming", "not deployed"} {
			if strings.Contains(lower, word) {
				t.Errorf("%v: the page says %q", features, word)
			}
		}
		if strings.Count(doc, strings.TrimSuffix(msg.T("admin.notifications.not_built"), ".")) != 3 {
			t.Errorf("%v: the three VCA rows do not say they are not built", features)
		}
	}
}

// TestIssuerNotificationsStackCardsFollowFeatures is ADR-040 decision 2:
// the webhook card shows only when the adapter lists FEATURE_WEBHOOKS,
// and the session callbacks only when it lists
// FEATURE_SESSION_CALLBACKS. Each names the stack.
func TestIssuerNotificationsStackCardsFollowFeatures(t *testing.T) {
	for _, features := range featureSets {
		h := newHarness(t, features...)
		doc := body(t, h.get(t, "/notifications/"))
		hooks, callbacks := false, false
		for _, f := range features {
			hooks = hooks || f == backendv1.Feature_FEATURE_WEBHOOKS
			callbacks = callbacks || f == backendv1.Feature_FEATURE_SESSION_CALLBACKS
		}
		if got := strings.Contains(doc, `id="stack-webhooks"`); got != hooks {
			t.Errorf("%v: webhook card %v, want %v", features, got, hooks)
		}
		if got := strings.Contains(doc, `id="session-callbacks"`); got != callbacks {
			t.Errorf("%v: callbacks card %v, want %v", features, got, callbacks)
		}
		if callbacks && !strings.Contains(doc, msg.T("issuer.notifications.callbacks.text", waltidName)) {
			t.Errorf("%v: the callbacks card does not name the stack", features)
		}
	}
}

// TestIssuerHelpListsTheRPCs lists what each issuer page does with a
// link to its document, and every RPC of the issuer services with the
// help text of its proto file (ADR-009 decision 3).
func TestIssuerHelpListsTheRPCs(t *testing.T) {
	h := newHarness(t)
	doc := body(t, h.get(t, "/help/"))
	a11ytest.AssertPage(t, doc)
	for _, path := range rolenav.Paths(commonv1.Role_ROLE_ISSUER) {
		if !strings.Contains(doc, `<a href="`+path+`">`) {
			t.Errorf("help does not link the page %s", path)
		}
	}
	for _, want := range []string{
		msg.T("issuer.help.page.issued"), msg.T("issuer.help.page.sources"), msg.T("issuer.help.pages.label"),
		`href="https://github.com/centre-for-dpi/verifiably/tree/main/vca/docs/issued-credentials.md"`,
		`href="https://github.com/centre-for-dpi/verifiably/tree/main/vca/docs/data-source.md"`,
		"IssueBatch", "Publish", "Revoke", "PreviewRows", "VerifyChain",
		msg.T("issuer.help.caption.label", msg.T("issuer.nav.sources.label"), "10"),
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("help lacks %q", want)
		}
	}
	// Every issuer RPC carries its help sentence, so no row is blank.
	for _, name := range []string{
		schemav1connect.SchemaServiceName, issuancev1connect.IssuanceServiceName,
		datasourcev1connect.DataSourceServiceName, issuedv1connect.IssuedServiceName,
	} {
		for _, e := range helptext.Service(name) {
			if e.Description == "" || !strings.Contains(doc, e.Description) {
				t.Errorf("%s has no help sentence on the page", e.Procedure)
			}
		}
	}
	h.opts.DocsURL = "https://docs.example.org/vca/"
	h.build(t)
	doc = body(t, h.get(t, "/help/"))
	if !strings.Contains(doc, `href="https://docs.example.org/vca/issuance.md"`) {
		t.Error("help ignores the docs URL of the deployment")
	}
}
