// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/record"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/service"
)

// addStackList writes the record of an offer whose credential carries an
// entry of the status list of the stack, as the issuance service writes
// it for a stack that keeps its own list.
func (f *fixture) addStackList(t *testing.T, id string) {
	t.Helper()
	_, err := f.svc.AppendRecord(record.Record{
		ID: id, SchemaID: "TradeLicence", SchemaVersion: 1, SubjectRef: f.svc.SubjectRef("T-" + id),
		DPG: "dpg-adapter-credebl", IssuedAt: clock, DPGCredentialID: "5f2c1d7b-6a09-4e83-9c14-2b7d8e0f3a56",
		Binding: record.Binding{
			Kind: record.KindToken, ListID: "6f1e2d3c-4b5a-4968-8778-a1b2c3d4e5f6", Index: 4211,
			PublishURL: "https://status.issuer.example.org/status-lists/6f1e2d3c", DPGList: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

// withBothLists rebuilds the service of f with a client of both status
// list kinds and a stack, so only the routing can refuse a change.
func withBothLists(t *testing.T, f *fixture, stack service.Stack) {
	t.Helper()
	svc, err := service.New(service.Options{
		Store: f.store, Status: f.status, StatusToken: f.status, Stack: stack, Now: func() time.Time { return f.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	f.svc = svc
}

// TestAStackListEntryChangesThroughTheAdapter: the list of the stack
// holds the status, so a revoke goes to the adapter with the id of the
// credential, and no status service of VCA flips a bit.
func TestAStackListEntryChangesThroughTheAdapter(t *testing.T) {
	f := newFixture(t)
	stack := &fakeStack{features: map[backendv1.Feature]bool{backendv1.Feature_FEATURE_REVOCATION: true}}
	withStack(t, f, stack)
	f.addStackList(t, "rec-1")
	if _, err := f.svc.Revoke(context.Background(), staff(&issuedv1.RevokeRequest{
		Id: "rec-1", Status: issuedv1.Status_STATUS_REVOKED, Reason: "Licence withdrawn",
	})); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(stack.changes) != 1 || stack.changes[0].CredentialID != "5f2c1d7b-6a09-4e83-9c14-2b7d8e0f3a56" ||
		!stack.changes[0].Binding.GetDpgList() {
		t.Fatalf("stack changes = %+v, want one revoke of the session", stack.changes)
	}
	if len(f.status.calls) != 0 {
		t.Fatalf("a status service of VCA took %d calls for an entry of the stack", len(f.status.calls))
	}
}

// TestAStackListEntryTheStackCannotChangeIsRefused: a suspension of an
// entry that the list of the stack holds, on a stack that cannot
// suspend, fails. So does any change with no adapter. The status
// services of VCA take no call, and the record keeps its status.
func TestAStackListEntryTheStackCannotChangeIsRefused(t *testing.T) {
	for name, stack := range map[string]service.Stack{
		"no suspension": &fakeStack{features: map[backendv1.Feature]bool{backendv1.Feature_FEATURE_REVOCATION: true}},
		"no adapter":    nil,
	} {
		f := newFixture(t)
		withBothLists(t, f, stack)
		f.addStackList(t, "rec-1")
		_, err := f.svc.Revoke(context.Background(), staff(&issuedv1.RevokeRequest{
			Id: "rec-1", Status: issuedv1.Status_STATUS_SUSPENDED, Reason: "Under review",
		}))
		if connect.CodeOf(err) != connect.CodeFailedPrecondition {
			t.Fatalf("%s: err = %v, want FailedPrecondition", name, err)
		}
		if len(f.status.calls) != 0 {
			t.Fatalf("%s: a status service of VCA flipped a bit no verifier reads", name)
		}
		got, err := f.svc.Get(context.Background(), connect.NewRequest(&issuedv1.GetRequest{Id: "rec-1"}))
		if err != nil || got.Msg.GetRecord().GetStatus() != issuedv1.Status_STATUS_ACTIVE {
			t.Fatalf("%s: record = %v, %v", name, got, err)
		}
	}
}

// TestTheStackListFlagSurvivesTheLog: the record keeps the flag through
// the append RPC and the read, so every later change routes right.
func TestTheStackListFlagSurvivesTheLog(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.Append(context.Background(), connect.NewRequest(&issuedv1.AppendRequest{Record: &issuedv1.IssuedRecord{
		SchemaId: "TradeLicence", SchemaVersion: 1, Hash: "abc", Dpg: "dpg-adapter-credebl",
		Subject:         &commonv1.Subject{Ref: "offer-1"},
		DpgCredentialId: "5f2c1d7b",
		StatusBinding: &backendv1.StatusListBinding{
			Kind: backendv1.StatusListBinding_KIND_TOKEN, ListId: "6f1e", Index: 4211, DpgList: true,
		},
	}}))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	list, err := f.svc.List(context.Background(), connect.NewRequest(&issuedv1.ListRequest{}))
	if err != nil || len(list.Msg.GetRecords()) != 1 {
		t.Fatalf("List: %v, %v", list, err)
	}
	if !list.Msg.GetRecords()[0].GetStatusBinding().GetDpgList() {
		t.Fatalf("binding = %v, want dpg_list kept", list.Msg.GetRecords()[0].GetStatusBinding())
	}
}
