// SPDX-License-Identifier: Apache-2.0

// Package clients holds the interfaces the issuance service needs from
// the other services, and the capability cache of the DPG adapter.
//
// Every interface is small, so a test passes a fake and needs no server.
// The wiring gives each interface a Connect client (ADR-002 decision 5).
package clients

import (
	"context"
	"fmt"
	"sync"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	statusv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1"
)

// Capability reads what a DPG adapter can do.
type Capability interface {
	// GetCapabilities returns the formats, channels, roles, and
	// protocols of the adapter.
	GetCapabilities(context.Context, *connect.Request[backendv1.GetCapabilitiesRequest]) (
		*connect.Response[backendv1.GetCapabilitiesResponse], error)
}

// Issuer drives the issuer side of a DPG adapter.
type Issuer interface {
	// CreateOffer builds an OID4VCI credential offer.
	CreateOffer(context.Context, *connect.Request[backendv1.CreateOfferRequest]) (
		*connect.Response[backendv1.CreateOfferResponse], error)
	// Issue produces one credential without a wallet.
	Issue(context.Context, *connect.Request[backendv1.IssueRequest]) (
		*connect.Response[backendv1.IssueResponse], error)
	// GetIssuanceStatus reads the state of one offer or deferred
	// issuance.
	GetIssuanceStatus(context.Context, *connect.Request[backendv1.GetIssuanceStatusRequest]) (
		*connect.Response[backendv1.GetIssuanceStatusResponse], error)
	// IssueBatch issues many credentials through the bulk import of the
	// DPG, when the adapter lists FEATURE_BULK_NATIVE.
	IssueBatch(context.Context, *connect.Request[backendv1.IssueBatchRequest]) (
		*connect.Response[backendv1.IssueBatchResponse], error)
}

// Schemas reads a published schema.
type Schemas interface {
	// Get returns one schema version.
	Get(context.Context, *connect.Request[schemav1.GetRequest]) (
		*connect.Response[schemav1.GetResponse], error)
}

// Status allocates the status list entry of a credential.
type Status interface {
	// AllocateIndex reserves one index in a status list.
	AllocateIndex(context.Context, *connect.Request[statusv1.AllocateIndexRequest]) (
		*connect.Response[statusv1.AllocateIndexResponse], error)
}

// Recorder writes the record of one issuance to the issued credentials
// service (ADR-017 decision 1).
type Recorder interface {
	// Record stores one issued record and returns its id.
	Record(ctx context.Context, r *issuedv1.IssuedRecord) (string, error)
}

// Rows reads the rows of a data source job.
type Rows interface {
	// Rows returns the rows of one data source job.
	Rows(ctx context.Context, sourceJobID string) ([]map[string]string, error)
}

// Capabilities is the answer of a DPG adapter with the time it arrived.
type Capabilities struct {
	// Formats are the wire formats the adapter can issue.
	Formats []commonv1.Format
	// Channels are the delivery channels the adapter supports.
	Channels []backendv1.Channel
	// Roles are the roles the adapter serves.
	Roles []commonv1.Role
	// Adapter is the name of the adapter.
	Adapter string
	// DpgVersion is the release of the DPG behind the adapter.
	DpgVersion string
	// Features are the optional RPCs the adapter implements.
	Features []backendv1.Feature
}

// Has reports whether the adapter lists a feature.
func (c Capabilities) Has(f backendv1.Feature) bool {
	for _, item := range c.Features {
		if item == f {
			return true
		}
	}
	return false
}

// SupportsFormat reports whether the adapter can issue the format. An
// unspecified format always passes, because the schema then chooses.
func (c Capabilities) SupportsFormat(f commonv1.Format) bool {
	if f == commonv1.Format_FORMAT_UNSPECIFIED {
		return true
	}
	for _, item := range c.Formats {
		if item == f {
			return true
		}
	}
	return false
}

// SupportsChannel reports whether the adapter supports the channel.
func (c Capabilities) SupportsChannel(ch backendv1.Channel) bool {
	for _, item := range c.Channels {
		if item == ch {
			return true
		}
	}
	return false
}

// FirstFormat returns the first format the adapter can issue.
func (c Capabilities) FirstFormat() commonv1.Format {
	if len(c.Formats) == 0 {
		return commonv1.Format_FORMAT_UNSPECIFIED
	}
	return c.Formats[0]
}

// CapabilityCache reads the capabilities of the adapter once and keeps
// them for a while. The UI then offers only what is possible
// (ADR-016 decision 6) without a call per request.
type CapabilityCache struct {
	client Capability
	ttl    time.Duration
	now    func() time.Time

	mu      sync.Mutex
	value   Capabilities
	expires time.Time
	loaded  bool
}

// NewCapabilityCache returns a cache over the adapter client.
func NewCapabilityCache(client Capability, ttl time.Duration, now func() time.Time) *CapabilityCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if now == nil {
		now = time.Now
	}
	return &CapabilityCache{client: client, ttl: ttl, now: now}
}

// Get returns the capabilities of the adapter.
func (c *CapabilityCache) Get(ctx context.Context) (Capabilities, error) {
	c.mu.Lock()
	value, expires, loaded := c.value, c.expires, c.loaded
	c.mu.Unlock()
	if loaded && c.now().Before(expires) {
		return value, nil
	}
	resp, err := c.client.GetCapabilities(ctx,
		connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		if loaded {
			// A short outage of the adapter must not stop an issuance
			// that the last answer allows.
			return value, nil
		}
		return Capabilities{}, fmt.Errorf("clients: read the adapter capabilities: %w", err)
	}
	value = Capabilities{
		Formats:    resp.Msg.GetFormats(),
		Channels:   resp.Msg.GetChannels(),
		Roles:      resp.Msg.GetRoles(),
		Adapter:    resp.Msg.GetAdapter(),
		DpgVersion: resp.Msg.GetDpgVersion(),
		Features:   resp.Msg.GetFeatures(),
	}
	c.mu.Lock()
	c.value, c.expires, c.loaded = value, c.now().Add(c.ttl), true
	c.mu.Unlock()
	return value, nil
}
