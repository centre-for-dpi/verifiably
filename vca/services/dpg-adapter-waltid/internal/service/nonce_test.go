// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/fake"
)

// The nonces the recorded walt.id answers carry.
const (
	verifyNonce  = "0b6c9d3e-41a2-4c7f-9e15-2d8a7f30c6b1"
	crossNonce   = "4c44c117-2d26-4838-b42f-52b0e0faa070"
	dcAPINonce   = "8054f259-7101-4fa5-9336-362999f17ecb"
	callerNonce  = "vca-nonce"
	answeredDcID = "ff4f0c86-56ce-4e4a-a137-dd5569049ff3"
)

// TestCreateRequestReturnsTheNonceOfTheStack returns the nonce walt.id
// put in the request. Neither verifier of 0.18.2 takes a nonce of the
// caller, so the caller must check the answer against this one.
func TestCreateRequestReturnsTheNonceOfTheStack(t *testing.T) {
	ctx := context.Background()
	svc, _ := newService(t, all)
	pe, err := svc.CreateRequest(ctx, connect.NewRequest(&backendv1.CreateRequestRequest{
		PresentationDefinition: sdJwtDefinition, Nonce: callerNonce,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := pe.Msg.GetNonce(); got != verifyNonce {
		t.Errorf("the verifier-api request: nonce %q, want the nonce of the authorize URL %q", got, verifyNonce)
	}
	v2, _ := newService(t, withV2)
	cross, err := v2.CreateRequest(ctx, connect.NewRequest(&backendv1.CreateRequestRequest{Dcql: dcqlQuery, Nonce: callerNonce}))
	if err != nil {
		t.Fatal(err)
	}
	if got := cross.Msg.GetNonce(); got != crossNonce {
		t.Errorf("the verifier 2 request: nonce %q, want %q", got, crossNonce)
	}
	both, err := v2.CreateRequest(ctx, connect.NewRequest(&backendv1.CreateRequestRequest{
		Dcql: dcqlQuery, Nonce: callerNonce, DcApi: true, ExpectedOrigins: []string{"https://verify.example"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := both.Msg.GetNonce(); got != crossNonce {
		t.Errorf("the request with a Digital Credentials API session: nonce %q, want the cross device nonce %q", got, crossNonce)
	}
}

// TestGetResultV2NamesTheNonceOfTheAnsweredSession reads the nonce of
// the verifier 2 session that holds the answer. A request with a Digital
// Credentials API session holds two sessions with two nonces.
func TestGetResultV2NamesTheNonceOfTheAnsweredSession(t *testing.T) {
	svc, f := newService(t, withV2)
	f.SetSession2(fake.Session2Successful)
	resp, err := svc.GetResult(context.Background(), connect.NewRequest(&backendv1.GetResultRequest{
		State: "v2:" + answeredDcID + ",14d60fa2-4e7d-4a34-a291-80da0e053fab",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.Msg.GetNonce(); got != crossNonce {
		t.Errorf("nonce %q, want the nonce of the session authorization request %q", got, crossNonce)
	}
}
