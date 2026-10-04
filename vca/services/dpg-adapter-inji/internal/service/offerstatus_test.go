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

// TestIssueNamesTheStatusEntryOfTheRow is ADR-072 decision 1 for Issue:
// the credential that the adapter fetches carries the entry of the
// spec, so the answer names it, as the answer of CreateOffer does.
func TestIssueNamesTheStatusEntryOfTheRow(t *testing.T) {
	svc, _ := newService(t, both)
	spec := farmerSpec()
	resp, err := svc.Issue(context.Background(), connect.NewRequest(&backendv1.IssueRequest{Spec: spec}))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !proto.Equal(resp.Msg.GetStatus(), spec.GetStatus()) {
		t.Fatalf("status = %v, want the entry of the spec %v", resp.Msg.GetStatus(), spec.GetStatus())
	}
	// A spec with no entry gives a credential that carries none.
	bare := farmerSpec()
	bare.Status = nil
	resp, err = svc.Issue(context.Background(), connect.NewRequest(&backendv1.IssueRequest{Spec: bare}))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if resp.Msg.GetStatus() != nil {
		t.Fatalf("status = %v, want none", resp.Msg.GetStatus())
	}
}

// TestIssueBatchNamesTheStatusEntryOfEachRow is the follow-up of
// ADR-076: each item of IssueBatch names the entry its credential
// carries and the id of the credential, as the answer of Issue does. A
// spec with no entry gives an item with none.
func TestIssueBatchNamesTheStatusEntryOfEachRow(t *testing.T) {
	svc, _ := newService(t, both)
	spec, bare := farmerSpec(), farmerSpec()
	bare.Status = nil
	resp, err := svc.IssueBatch(context.Background(), connect.NewRequest(&backendv1.IssueBatchRequest{Specs: []*backendv1.IssueSpec{spec, bare}}))
	if err != nil {
		t.Fatalf("IssueBatch: %v", err)
	}
	items := resp.Msg.GetItems()
	if len(items) != 2 || items[0].GetError() != nil || items[1].GetError() != nil {
		t.Fatalf("items = %v", items)
	}
	if !proto.Equal(items[0].GetStatus(), spec.GetStatus()) {
		t.Errorf("status = %v, want the entry of the spec %v", items[0].GetStatus(), spec.GetStatus())
	}
	if items[0].GetCredentialId() == "" {
		t.Error("the item names no credential id")
	}
	if items[1].GetStatus() != nil {
		t.Errorf("status = %v, want none", items[1].GetStatus())
	}
}
