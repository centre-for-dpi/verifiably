// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"sync"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	statusv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1"
)

// fakeAdapter answers as a DPG adapter.
type fakeAdapter struct {
	mu sync.Mutex
	// capabilities is the answer of GetCapabilities.
	capabilities *backendv1.GetCapabilitiesResponse
	// capabilityErr fails GetCapabilities.
	capabilityErr error
	// offer is the answer of CreateOffer.
	offer *backendv1.CreateOfferResponse
	// offerErr fails CreateOffer.
	offerErr error
	// credential is the answer of Issue.
	credential *backendv1.IssueResponse
	// issueErr fails Issue.
	issueErr error
	// state is the answer of GetIssuanceStatus.
	state *backendv1.GetIssuanceStatusResponse
	// stateErr fails GetIssuanceStatus.
	stateErr error
	// specs records every spec the service sent.
	specs []*backendv1.IssueSpec
	// channels records every channel the service asked for.
	channels []backendv1.Channel
	// batches records every native batch the service sent.
	batches []*backendv1.IssueBatchRequest
	// batch is the answer of IssueBatch. Nil answers one credential per
	// spec.
	batch *backendv1.IssueBatchResponse
	// batchErr fails IssueBatch.
	batchErr error
}

func (f *fakeAdapter) GetCapabilities(
	context.Context, *connect.Request[backendv1.GetCapabilitiesRequest],
) (*connect.Response[backendv1.GetCapabilitiesResponse], error) {
	if f.capabilityErr != nil {
		return nil, f.capabilityErr
	}
	return connect.NewResponse(f.capabilities), nil
}

func (f *fakeAdapter) CreateOffer(
	_ context.Context, req *connect.Request[backendv1.CreateOfferRequest],
) (*connect.Response[backendv1.CreateOfferResponse], error) {
	f.mu.Lock()
	f.specs = append(f.specs, req.Msg.GetSpec())
	f.channels = append(f.channels, req.Msg.GetChannel())
	f.mu.Unlock()
	if f.offerErr != nil {
		return nil, f.offerErr
	}
	return connect.NewResponse(f.offer), nil
}

func (f *fakeAdapter) Issue(
	_ context.Context, req *connect.Request[backendv1.IssueRequest],
) (*connect.Response[backendv1.IssueResponse], error) {
	f.mu.Lock()
	f.specs = append(f.specs, req.Msg.GetSpec())
	f.mu.Unlock()
	if f.issueErr != nil {
		return nil, f.issueErr
	}
	return connect.NewResponse(f.credential), nil
}

func (f *fakeAdapter) GetIssuanceStatus(
	context.Context, *connect.Request[backendv1.GetIssuanceStatusRequest],
) (*connect.Response[backendv1.GetIssuanceStatusResponse], error) {
	if f.stateErr != nil {
		return nil, f.stateErr
	}
	return connect.NewResponse(f.state), nil
}

func (f *fakeAdapter) IssueBatch(
	_ context.Context, req *connect.Request[backendv1.IssueBatchRequest],
) (*connect.Response[backendv1.IssueBatchResponse], error) {
	f.mu.Lock()
	f.batches = append(f.batches, req.Msg)
	f.mu.Unlock()
	if f.batchErr != nil {
		return nil, f.batchErr
	}
	if f.batch != nil {
		return connect.NewResponse(f.batch), nil
	}
	out := &backendv1.IssueBatchResponse{}
	var position int32
	for range req.Msg.GetSpecs() {
		out.Items = append(out.Items, &backendv1.IssueBatchResponse_Item{Position: position, Credential: f.credential.GetCredential()})
		position++
	}
	return connect.NewResponse(out), nil
}

// lastSpec returns the spec of the last call.
func (f *fakeAdapter) lastSpec() *backendv1.IssueSpec {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.specs) == 0 {
		return nil
	}
	return f.specs[len(f.specs)-1]
}

// fakeSchemas answers as the schema registry.
type fakeSchemas struct {
	schema *schemav1.Schema
	err    error
}

func (f *fakeSchemas) Get(
	context.Context, *connect.Request[schemav1.GetRequest],
) (*connect.Response[schemav1.GetResponse], error) {
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(&schemav1.GetResponse{Schema: f.schema}), nil
}

// fakeStatus answers as the status service.
type fakeStatus struct {
	answer   *statusv1.AllocateIndexResponse
	err      error
	requests []*statusv1.AllocateIndexRequest
}

func (f *fakeStatus) AllocateIndex(
	_ context.Context, req *connect.Request[statusv1.AllocateIndexRequest],
) (*connect.Response[statusv1.AllocateIndexResponse], error) {
	f.requests = append(f.requests, req.Msg)
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(f.answer), nil
}

// fakeRecorder answers as the issued credentials service.
type fakeRecorder struct {
	mu      sync.Mutex
	records []*issuedv1.IssuedRecord
	err     error
}

func (f *fakeRecorder) Record(_ context.Context, r *issuedv1.IssuedRecord) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return "", f.err
	}
	f.records = append(f.records, r)
	return "record-1", nil
}

// last returns the last record the service wrote.
func (f *fakeRecorder) last() *issuedv1.IssuedRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.records) == 0 {
		return nil
	}
	return f.records[len(f.records)-1]
}

// allChannels is the capability answer of an adapter that can do
// everything the issuance service offers.
func allChannels() *backendv1.GetCapabilitiesResponse {
	return &backendv1.GetCapabilitiesResponse{
		Adapter:    "dpg-adapter-test",
		DpgVersion: "1.0",
		Formats: []commonv1.Format{
			commonv1.Format_FORMAT_VC_SD_JWT, commonv1.Format_FORMAT_LDP_VC,
		},
		Channels: []backendv1.Channel{
			backendv1.Channel_CHANNEL_OID4VCI_PREAUTH,
			backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE,
			backendv1.Channel_CHANNEL_PDF,
		},
		Roles: []commonv1.Role{commonv1.Role_ROLE_ISSUER},
	}
}
