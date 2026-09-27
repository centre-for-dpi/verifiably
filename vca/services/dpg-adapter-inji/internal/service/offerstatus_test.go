// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

// TestCreateOfferNamesTheStatusEntryOfTheRow: the claims row carries the
// entry of the spec, and Certify writes it into the credential. The
// answer names that entry, on both OID4VCI channels.
func TestCreateOfferNamesTheStatusEntryOfTheRow(t *testing.T) {
	svc, _ := newService(t, both)
	for _, channel := range []backendv1.Channel{
		backendv1.Channel_CHANNEL_OID4VCI_PREAUTH,
	} {
		spec := farmerSpec()
		resp, err := svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{Spec: spec, Channel: channel}))
		if err != nil {
			t.Fatalf("%v: CreateOffer: %v", channel, err)
		}
		if !proto.Equal(resp.Msg.GetStatus(), spec.GetStatus()) {
			t.Errorf("%v: status = %v, want the entry of the spec %v", channel, resp.Msg.GetStatus(), spec.GetStatus())
		}
	}
}

// TestCreateOfferWithNoRowNamesNoEntry: an authorization code offer of
// the identity provider stages no row, so its credential carries no
// status entry of VCA.
func TestCreateOfferWithNoRowNamesNoEntry(t *testing.T) {
	svc, _ := newService(t, both)
	resp, err := svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: farmerSpec(), Channel: backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE,
	}))
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	if resp.Msg.GetStatus() != nil {
		t.Fatalf("status = %v, want none", resp.Msg.GetStatus())
	}
}
