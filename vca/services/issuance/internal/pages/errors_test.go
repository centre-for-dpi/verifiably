// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/pages"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

func TestNewNeedsItsParts(t *testing.T) {
	kit, err := components.New()
	if err != nil {
		t.Fatal(err)
	}
	shell := staffshell.New(staffshell.Options{})
	for name, opts := range map[string]pages.Options{
		"kit":        {Shell: shell, Capability: &fakeCapability{}},
		"shell":      {Kit: kit, Capability: &fakeCapability{}},
		"capability": {Kit: kit, Shell: shell},
	} {
		if _, err := pages.New(opts); err == nil {
			t.Errorf("New without a %s passed", name)
		}
	}
	if len(pages.Prefixes()) != 5 {
		t.Fatalf("prefixes = %v", pages.Prefixes())
	}
}

// failingCapability answers every call with an outage.
type failingCapability struct{}

func (failingCapability) GetCapabilities(context.Context, *connect.Request[backendv1.GetCapabilitiesRequest]) (*connect.Response[backendv1.GetCapabilitiesResponse], error) {
	return nil, connect.NewError(connect.CodeUnavailable, errors.New("down"))
}

// TestPagesDrawWithoutTheProbe covers a pair with no peer list: the
// pages ask the adapter itself, and a failed answer names no stack.
func TestPagesDrawWithoutTheProbe(t *testing.T) {
	h := newHarness(t)
	h.snap = topology.Snapshot{}
	doc := body(t, h.get(t, "/issuer/"))
	if !strings.Contains(doc, "Your issuer on First stack.") {
		t.Error("the overview did not ask the adapter")
	}
	h.opts.Capability = failingCapability{}
	h.build(t)
	doc = body(t, h.get(t, "/issuer/"))
	if !strings.Contains(doc, "Your issuer on this stack.") {
		t.Error("the overview named a stack it does not know")
	}
}

func TestOverviewCountsAndOutages(t *testing.T) {
	h := newHarness(t)
	h.schemas.published = nil
	h.issued.total = 12
	doc := body(t, h.get(t, "/issuer/"))
	if !strings.Contains(doc, "None published") || !strings.Contains(doc, "12 issued") {
		t.Error("the counts are wrong")
	}
	h.schemas.err = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	h.issued.err = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	doc = body(t, h.get(t, "/issuer/"))
	if strings.Count(doc, "Unknown now") != 2 {
		t.Error("an outage must show as unknown")
	}
	// The issue page names an outage of the registry as no schema, and
	// fails on any other error.
	body(t, h.get(t, "/issue/"))
	h.schemas.err = connect.NewError(connect.CodeInternal, errors.New("broken"))
	if rec := h.get(t, "/issue/"); rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", rec.Code)
	}
	h.schemas.err = connect.NewError(connect.CodeInvalidArgument, errors.New("bad"))
	if rec := h.get(t, "/issue/"); rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
	h.schemas.err = connect.NewError(connect.CodeNotFound, errors.New("gone"))
	if rec := h.get(t, "/issue/"); rec.Code != http.StatusNotFound {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestNotificationsNameTheStackWebhooks(t *testing.T) {
	h := newHarness(t, backendv1.Feature_FEATURE_WEBHOOKS)
	doc := body(t, h.get(t, "/notifications/"))
	if !strings.Contains(doc, "First stack calls a webhook on its events.") {
		t.Error("the stack webhook card is missing")
	}
}
