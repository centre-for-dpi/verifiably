// SPDX-License-Identifier: Apache-2.0

// Package stack is the DPG adapter of the pair as the issued
// credentials service sees it: the features it lists now, a revoke in
// the stack, and the claim state of an offer (ADR-034 decision 5). The features
// come from GetCapabilities, read once for a while, so a page asks no
// more than once a minute.
package stack

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/service"
)

// DefaultTTL is how long one capability answer stays fresh.
const DefaultTTL = time.Minute

// Capabilities is the capability service of the adapter. The generated
// Connect client fits it.
type Capabilities interface {
	GetCapabilities(context.Context, *connect.Request[backendv1.GetCapabilitiesRequest]) (
		*connect.Response[backendv1.GetCapabilitiesResponse], error)
}

// Issuer is the part of the issuer backend service that the service
// calls. The generated Connect client fits it.
type Issuer interface {
	Revoke(context.Context, *connect.Request[backendv1.RevokeRequest]) (*connect.Response[backendv1.RevokeResponse], error)
	ListIssuedCredentials(context.Context, *connect.Request[backendv1.ListIssuedCredentialsRequest]) (
		*connect.Response[backendv1.ListIssuedCredentialsResponse], error)
	GetIssuanceStatus(context.Context, *connect.Request[backendv1.GetIssuanceStatusRequest]) (
		*connect.Response[backendv1.GetIssuanceStatusResponse], error)
}

// Adapter calls the DPG adapter of the pair.
type Adapter struct {
	caps   Capabilities
	issuer Issuer
	ttl    time.Duration
	now    func() time.Time

	mu      sync.Mutex
	answer  *backendv1.GetCapabilitiesResponse
	expires time.Time
}

// New returns the adapter. A zero ttl means DefaultTTL, and a nil now
// means time.Now.
func New(caps Capabilities, issuer Issuer, ttl time.Duration, now func() time.Time) *Adapter {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if now == nil {
		now = time.Now
	}
	return &Adapter{caps: caps, issuer: issuer, ttl: ttl, now: now}
}

// capabilities returns the last answer of the adapter, read again when
// it is old. An adapter that never answered gives an empty answer, so
// every feature stays hidden. A short outage keeps the last answer.
func (a *Adapter) capabilities(ctx context.Context) *backendv1.GetCapabilitiesResponse {
	a.mu.Lock()
	answer, fresh := a.answer, a.answer != nil && a.now().Before(a.expires)
	a.mu.Unlock()
	if fresh {
		return answer
	}
	res, err := a.caps.GetCapabilities(ctx, connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		if answer == nil {
			return &backendv1.GetCapabilitiesResponse{}
		}
		return answer
	}
	a.mu.Lock()
	a.answer, a.expires = res.Msg, a.now().Add(a.ttl)
	a.mu.Unlock()
	return res.Msg
}

// Has reports whether the adapter lists a feature now (ADR-034
// decision 5). A nil adapter lists none.
func (a *Adapter) Has(ctx context.Context, feature backendv1.Feature) bool {
	if a == nil {
		return false
	}
	return slices.Contains(a.capabilities(ctx).GetFeatures(), feature)
}

// Name is the name of the stack as its adapter reports it, or "".
func (a *Adapter) Name(ctx context.Context) string {
	if a == nil {
		return ""
	}
	return strings.TrimSpace(a.capabilities(ctx).GetDpgInfo().GetDisplayName())
}

// Change asks the stack to change the status of one credential of its
// ledger.
func (a *Adapter) Change(ctx context.Context, c service.StackChange) error {
	_, err := a.issuer.Revoke(ctx, connect.NewRequest(&backendv1.RevokeRequest{
		Status: c.Binding, Reason: c.Reason, Action: c.Action, CredentialId: c.CredentialID,
	}))
	return err
}

// Ledger returns one page of the ledger of the stack.
func (a *Adapter) Ledger(ctx context.Context, req *backendv1.ListIssuedCredentialsRequest) (*backendv1.ListIssuedCredentialsResponse, error) {
	res, err := a.issuer.ListIssuedCredentials(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, err
	}
	return res.Msg, nil
}

// Pending reports whether the offer with the adapter id exists and no
// wallet claimed it yet. An empty id or an error of the adapter reports
// false, so the page shows the status of the log.
func (a *Adapter) Pending(ctx context.Context, offerID string) bool {
	if offerID == "" {
		return false
	}
	res, err := a.issuer.GetIssuanceStatus(ctx, connect.NewRequest(&backendv1.GetIssuanceStatusRequest{OfferId: offerID}))
	return err == nil && res.Msg.GetState() == backendv1.GetIssuanceStatusResponse_STATE_PENDING
}
