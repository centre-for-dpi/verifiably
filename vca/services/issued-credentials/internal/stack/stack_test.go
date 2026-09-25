// SPDX-License-Identifier: Apache-2.0

package stack_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/stack"
)

// fakeAdapter answers as the capability and issuer services of an
// adapter.
type fakeAdapter struct {
	backendv1connect.UnimplementedIssuerBackendServiceHandler
	answer   *backendv1.GetCapabilitiesResponse
	capsErr  error
	capCalls int
	revoked  []*backendv1.RevokeRequest
	state    backendv1.GetIssuanceStatusResponse_State
	stateErr error
	asked    []string
}

func (f *fakeAdapter) GetCapabilities(context.Context, *connect.Request[backendv1.GetCapabilitiesRequest]) (*connect.Response[backendv1.GetCapabilitiesResponse], error) {
	f.capCalls++
	if f.capsErr != nil {
		return nil, f.capsErr
	}
	return connect.NewResponse(f.answer), nil
}

func (f *fakeAdapter) Revoke(_ context.Context, req *connect.Request[backendv1.RevokeRequest]) (*connect.Response[backendv1.RevokeResponse], error) {
	f.revoked = append(f.revoked, req.Msg)
	return connect.NewResponse(&backendv1.RevokeResponse{}), nil
}

func (f *fakeAdapter) GetIssuanceStatus(_ context.Context, req *connect.Request[backendv1.GetIssuanceStatusRequest]) (*connect.Response[backendv1.GetIssuanceStatusResponse], error) {
	f.asked = append(f.asked, req.Msg.GetOfferId())
	if f.stateErr != nil {
		return nil, f.stateErr
	}
	return connect.NewResponse(&backendv1.GetIssuanceStatusResponse{State: f.state}), nil
}

func listing(features ...backendv1.Feature) *backendv1.GetCapabilitiesResponse {
	return &backendv1.GetCapabilitiesResponse{Features: features, DpgInfo: &backendv1.DpgInfo{DisplayName: "Test stack"}}
}

// TestHasReadsTheFeaturesOnceAWhile keeps one capability call for the
// time to live, and reads again after it.
func TestHasReadsTheFeaturesOnceAWhile(t *testing.T) {
	now := time.Date(2026, 9, 25, 9, 0, 0, 0, time.UTC)
	f := &fakeAdapter{answer: listing(backendv1.Feature_FEATURE_REVOCATION)}
	a := stack.New(f, f, time.Minute, func() time.Time { return now })
	ctx := context.Background()
	if !a.Has(ctx, backendv1.Feature_FEATURE_REVOCATION) || a.Has(ctx, backendv1.Feature_FEATURE_ISSUANCE_STATUS) {
		t.Fatal("the features do not follow the answer")
	}
	if a.Name(ctx) != "Test stack" || f.capCalls != 1 {
		t.Fatalf("name %q after %d calls", a.Name(ctx), f.capCalls)
	}
	now = now.Add(2 * time.Minute)
	f.answer = listing()
	if a.Has(ctx, backendv1.Feature_FEATURE_REVOCATION) || f.capCalls != 2 {
		t.Fatalf("the cache did not expire: %d calls", f.capCalls)
	}
}

// TestHasListsNothingWhenTheAdapterIsDown hides every feature of an
// adapter that never answered, and keeps the last answer through a
// short outage.
func TestHasListsNothingWhenTheAdapterIsDown(t *testing.T) {
	now := time.Date(2026, 9, 25, 9, 0, 0, 0, time.UTC)
	f := &fakeAdapter{capsErr: errors.New("down")}
	a := stack.New(f, f, time.Minute, func() time.Time { return now })
	ctx := context.Background()
	if a.Has(ctx, backendv1.Feature_FEATURE_REVOCATION) || a.Name(ctx) != "" {
		t.Fatal("a silent adapter lists a feature")
	}
	f.capsErr, f.answer = nil, listing(backendv1.Feature_FEATURE_REVOCATION)
	if !a.Has(ctx, backendv1.Feature_FEATURE_REVOCATION) {
		t.Fatal("the answer after the outage is missing")
	}
	now = now.Add(2 * time.Minute)
	f.capsErr = errors.New("down again")
	if !a.Has(ctx, backendv1.Feature_FEATURE_REVOCATION) {
		t.Fatal("a short outage dropped the last answer")
	}
	var none *stack.Adapter
	if none.Has(ctx, backendv1.Feature_FEATURE_REVOCATION) || none.Name(ctx) != "" {
		t.Fatal("a nil adapter lists a feature")
	}
}

// TestRevokeSendsTheBindingAndTheReason is the call for a
// stack that revokes itself.
func TestRevokeSendsTheBindingAndTheReason(t *testing.T) {
	f := &fakeAdapter{answer: listing()}
	a := stack.New(f, f, 0, nil)
	binding := &backendv1.StatusListBinding{ListId: "v1", Index: 7}
	if err := a.Revoke(context.Background(), binding, "Lost card"); err != nil {
		t.Fatal(err)
	}
	if len(f.revoked) != 1 || f.revoked[0].GetStatus().GetIndex() != 7 || f.revoked[0].GetReason() != "Lost card" {
		t.Fatalf("revoked = %v", f.revoked)
	}
}

// TestPendingReadsTheClaimState reports an offer that no wallet claimed,
// and says nothing for an offer without an id or for an error.
func TestPendingReadsTheClaimState(t *testing.T) {
	f := &fakeAdapter{answer: listing(), state: backendv1.GetIssuanceStatusResponse_STATE_PENDING}
	a := stack.New(f, f, 0, nil)
	ctx := context.Background()
	if !a.Pending(ctx, "offer-7") || len(f.asked) != 1 || f.asked[0] != "offer-7" {
		t.Fatalf("pending offer: asked %v", f.asked)
	}
	f.state = backendv1.GetIssuanceStatusResponse_STATE_ISSUED
	if a.Pending(ctx, "offer-7") {
		t.Fatal("a claimed offer reads as pending")
	}
	if a.Pending(ctx, "") || len(f.asked) != 2 {
		t.Fatal("an empty offer id reached the adapter")
	}
	f.stateErr = errors.New("down")
	if a.Pending(ctx, "offer-7") {
		t.Fatal("an error reads as pending")
	}
}
