// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// stepStates returns the state word of each step card, in order.
func stepStates(t *testing.T, doc string) []string {
	t.Helper()
	var out []string
	for _, m := range regexp.MustCompile(`<li class="step[^"]*"[\s\S]*?<span class="step-state[^"]*">([^<]+)</span>`).FindAllStringSubmatch(doc, -1) {
		out = append(out, m[1])
	}
	if len(out) != 4 {
		t.Fatalf("got %d step states %v\n%s", len(out), out, doc)
	}
	return out
}

func TestOverviewStepsLockInOrder(t *testing.T) {
	h := newHarness(t, allIdentity...)
	cases := []struct {
		name  string
		setup func()
		want  string
	}{
		{"nothing", func() {}, "Current Locked Locked Locked"},
		// A schema without an identity stays locked: the steps unlock in order.
		{"schema only", func() { h.schemas.published = []*schemav1.Schema{{Id: "farmer", Version: 1}} }, "Current Locked Locked Locked"},
		{"identity", func() {
			h.schemas.published = nil
			h.identity.identity = &backendv1.IssuerIdentity{Identifiers: []string{didKey}}
		}, "Done Current Locked Locked"},
		{"schema", func() { h.schemas.published = []*schemav1.Schema{{Id: "farmer", Version: 1}} }, "Done Done Current Locked"},
		{"issued", func() { h.issued.total = 1 }, "Done Done Done Current"},
	}
	for _, c := range cases {
		c.setup()
		doc := body(t, h.get(t, "/issuer/"))
		a11ytest.AssertPage(t, doc)
		if got := strings.Join(stepStates(t, doc), " "); got != c.want {
			t.Errorf("%s: steps %q, want %q", c.name, got, c.want)
		}
	}
	// A stack that keeps its own identity counts as registered.
	h.identity.identity, h.issued.total = nil, 0
	h.identity.err = connect.NewError(connect.CodeUnimplemented, errors.New("the stack keeps it"))
	if got := strings.Join(stepStates(t, body(t, h.get(t, "/issuer/"))), " "); got != "Done Done Current Locked" {
		t.Errorf("stack identity: steps %q", got)
	}
}

func TestOverviewCountsFromRPCs(t *testing.T) {
	h := newHarness(t, allIdentity...)
	h.identity.identity = &backendv1.IssuerIdentity{Identifiers: []string{"did:web:issuer-waltid.labs.example"}}
	h.trust.entries = map[string]*trustv1.TrustEntry{"did:web:issuer-waltid.labs.example": {Status: trustv1.Status_STATUS_PENDING}}
	h.schemas.published = []*schemav1.Schema{{Id: "a"}, {Id: "b"}, {Id: "c"}}
	h.issued.total = 128
	doc := body(t, h.get(t, "/issuer/"))
	for _, want := range []string{"3 published", "128 issued", "did:web:issuer-waltid.labs.example", "In trust registry", "Manage schemas"} {
		if !strings.Contains(doc, want) {
			t.Errorf("the overview lacks %q", want)
		}
	}
	h.trust.entries["did:web:issuer-waltid.labs.example"].Status = trustv1.Status_STATUS_ACTIVE
	if doc := body(t, h.get(t, "/issuer/")); !strings.Contains(doc, "On trust list") {
		t.Error("an approved entry is not named")
	}
}

func TestOverviewEmptyStateLinksToIssue(t *testing.T) {
	h := newHarness(t, allIdentity...)
	doc := body(t, h.get(t, "/issuer/"))
	if !strings.Contains(doc, "Nothing yet") || !strings.Contains(doc, `href="/issue/"`) || !strings.Contains(doc, "Issue the first one") {
		t.Errorf("the empty issued card does not lead to the issue page\n%s", doc)
	}
	if !strings.Contains(doc, "Not registered") || !strings.Contains(doc, `href="/identity/"`) {
		t.Error("the identity card does not lead to the identity page")
	}
	if !strings.Contains(doc, "No activity yet.") {
		t.Error("the empty activity is not named")
	}
}

func TestOverviewShowsRecentActivity(t *testing.T) {
	h := newHarness(t, allIdentity...)
	ctx := context.Background()
	for _, e := range []auditlog.Entry{
		{Actor: "kc|wanjiru", Action: "issuance.ProvisionIdentity", Target: "did:web:issuer-waltid.labs.example", OK: true},
		{Actor: "kc|wanjiru", Action: "issuance.RequestTrustEntry", Target: "did:web:issuer-waltid.labs.example", OK: true},
		{Actor: "kc|wanjiru", Action: "issuance.Issue", Target: "offer-7f3a", OK: false, Detail: "The service answered with the code unavailable."},
		{Actor: "kc|wanjiru", Action: "issuance.Other", Target: "x", OK: true},
	} {
		if _, err := h.audit.Append(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	doc := body(t, h.get(t, "/issuer/"))
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{"Recent activity", "Identity registered", "Trust entry requested", "Credential issued",
		"issuance.Other", "The service answered with the code unavailable.", "Failed", "2026-09-25 09:30 UTC"} {
		if !strings.Contains(doc, want) {
			t.Errorf("the activity lacks %q", want)
		}
	}
}
