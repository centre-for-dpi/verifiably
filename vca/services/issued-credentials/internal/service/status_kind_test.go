// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/record"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/service"
)

// addToken appends one record whose status entry sits in a Token Status
// List, as the record of an SD-JWT VC does.
func (f *fixture) addToken(t *testing.T, id string, index int64) {
	t.Helper()
	r := record.Record{
		ID: id, SchemaID: "farmer", SchemaVersion: 1, SubjectRef: f.svc.SubjectRef("subject-" + id),
		Format: "dc+sd-jwt", DPG: "waltid", IssuedAt: clock,
		Binding: record.Binding{Kind: record.KindToken, ListID: "t1", Index: index},
	}
	if _, err := f.svc.AppendRecord(r); err != nil {
		t.Fatalf("append %s: %v", id, err)
	}
}

// TestStatusChangeGoesToTheServiceOfTheList: a record of an SD-JWT VC
// points into a Token Status List, which the status-token service
// keeps, so its change goes there. A record with a Bitstring entry goes
// to the bitstring service. Without a token service the change of a
// token entry fails before any call.
func TestStatusChangeGoesToTheServiceOfTheList(t *testing.T) {
	f := newFixture(t)
	token := &fakeStatus{}
	now := func() time.Time { return f.now }
	svc, err := service.New(service.Options{Store: f.store, Status: f.status, StatusToken: token, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	f.svc = svc
	f.add(t, "bits", "farmer", 1, nil)
	f.addToken(t, "tok", 2)
	f.addToken(t, "tok2", 3)
	ctx := context.Background()
	for _, id := range []string{"bits", "tok"} {
		if _, rerr := svc.Revoke(ctx, staff(&issuedv1.RevokeRequest{Id: id, Status: issuedv1.Status_STATUS_REVOKED, Reason: "lost card"})); rerr != nil {
			t.Fatalf("revoke %s: %v", id, rerr)
		}
	}
	if len(f.status.calls) != 1 || f.status.calls[0].GetListId() != "v1" || f.status.calls[0].GetIndex() != 1 {
		t.Errorf("bitstring calls = %v", f.status.calls)
	}
	if len(token.calls) != 1 || token.calls[0].GetListId() != "t1" || token.calls[0].GetIndex() != 2 {
		t.Errorf("token calls = %v", token.calls)
	}

	bare, err := service.New(service.Options{Store: f.store, Status: f.status, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	_, err = bare.Revoke(ctx, staff(&issuedv1.RevokeRequest{Id: "tok2", Status: issuedv1.Status_STATUS_SUSPENDED, Reason: "under review"}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("suspend without a token service: %v", err)
	}
	if len(f.status.calls) != 1 {
		t.Errorf("the bitstring service got a token entry: %v", f.status.calls)
	}
}
