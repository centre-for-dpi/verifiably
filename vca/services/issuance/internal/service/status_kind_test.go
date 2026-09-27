// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"testing"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	statusv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/service"
)

// An SD-JWT VC carries an entry of an IETF Token Status List, which the
// status-token service keeps. A W3C credential carries an entry of a
// Bitstring Status List, which the status-bitstring service keeps. The
// bitstring service refuses a token list, so each kind goes to its own
// service.

// tokenLists is the status-token service of the tests.
func tokenLists() *fakeStatus {
	return &fakeStatus{answer: &statusv1.AllocateIndexResponse{
		ListId: "token-1", Index: 7, Url: "https://issuer.example.org/status-token/status/token-1",
	}}
}

// TestSdJwtStatusComesFromTheTokenService: the entry of an SD-JWT VC
// comes from the token service, and the bitstring service hears nothing.
func TestSdJwtStatusComesFromTheTokenService(t *testing.T) {
	token := tokenLists()
	h := newHarness(t, func(o *service.Options, _ *harness) { o.StatusToken = token })
	h.issue(t, backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, nil)
	if len(token.requests) != 1 || token.requests[0].GetKind() != statusv1.Kind_KIND_TOKEN {
		t.Fatalf("token service requests = %v", token.requests)
	}
	if len(h.status.requests) != 0 {
		t.Errorf("the bitstring service got %v", h.status.requests)
	}
	got := h.adapter.lastSpec().GetStatus()
	if got.GetKind() != backendv1.StatusListBinding_KIND_TOKEN || got.GetListId() != "token-1" || got.GetIndex() != 7 {
		t.Errorf("status = %v", got)
	}
}

// TestW3CStatusComesFromTheBitstringService: the entry of a W3C
// credential comes from the bitstring service.
func TestW3CStatusComesFromTheBitstringService(t *testing.T) {
	token := tokenLists()
	h := newHarness(t, func(o *service.Options, _ *harness) { o.StatusToken = token })
	h.schemas.schema.Formats = []commonv1.Format{commonv1.Format_FORMAT_LDP_VC}
	h.issue(t, backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, nil)
	if len(h.status.requests) != 1 || h.status.requests[0].GetKind() != statusv1.Kind_KIND_BITSTRING {
		t.Fatalf("bitstring service requests = %v", h.status.requests)
	}
	if len(token.requests) != 0 {
		t.Errorf("the token service got %v", token.requests)
	}
}

// TestSdJwtWithoutTokenServiceIsNotRevocable: with no token service the
// SD-JWT VC carries no status entry, as with no status service at all.
// The bitstring service never gets a token list request.
func TestSdJwtWithoutTokenServiceIsNotRevocable(t *testing.T) {
	h := newHarness(t, func(o *service.Options, _ *harness) { o.StatusToken = nil })
	h.issue(t, backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, nil)
	if len(h.status.requests) != 0 {
		t.Errorf("the bitstring service got %v", h.status.requests)
	}
	if got := h.adapter.lastSpec().GetStatus(); got != nil {
		t.Errorf("status = %v, want none", got)
	}
}
