// SPDX-License-Identifier: Apache-2.0

package fake_test

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/fake"
)

func TestRegistry(t *testing.T) {
	r := &fake.Registry{}
	ctx := context.Background()
	if _, err := r.Get(ctx, connect.NewRequest(&schemav1.GetRequest{Id: "s"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("an empty registry must answer not found, got %v", err)
	}
	created, err := r.Create(ctx, connect.NewRequest(&schemav1.CreateRequest{Schema: &schemav1.Schema{Type: "T"}}))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Msg.GetSchema().GetId() != "schema-1" || created.Msg.GetSchema().GetVersion() != 1 {
		t.Errorf("created = %+v", created.Msg.GetSchema())
	}
	if created.Msg.GetSchema().GetState() != schemav1.State_STATE_DRAFT {
		t.Errorf("state = %v", created.Msg.GetSchema().GetState())
	}
	updated, err := r.Update(ctx, connect.NewRequest(&schemav1.UpdateRequest{Schema: &schemav1.Schema{Id: "schema-1", Type: "T"}}))
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Msg.GetSchema().GetVersion() != 2 {
		t.Errorf("version = %d", updated.Msg.GetSchema().GetVersion())
	}
	got, err := r.Get(ctx, connect.NewRequest(&schemav1.GetRequest{Id: "schema-1"}))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Msg.GetSchema().GetId() != "schema-1" {
		t.Errorf("got = %+v", got.Msg.GetSchema())
	}
	if r.Created != 1 || r.Updated != 1 {
		t.Errorf("counts = %d %d", r.Created, r.Updated)
	}
}

func TestRegistryFails(t *testing.T) {
	r := &fake.Registry{Err: errors.New("down")}
	ctx := context.Background()
	if _, err := r.Create(ctx, connect.NewRequest(&schemav1.CreateRequest{})); err == nil {
		t.Error("create must fail")
	}
	if _, err := r.Update(ctx, connect.NewRequest(&schemav1.UpdateRequest{})); err == nil {
		t.Error("update must fail")
	}
	if _, err := r.Get(ctx, connect.NewRequest(&schemav1.GetRequest{})); err == nil {
		t.Error("get must fail")
	}
}

func TestCatalog(t *testing.T) {
	c := &fake.Catalog{Entries: []*backendv1.CredentialConfiguration{{Id: "one"}}}
	resp, err := c.ListCredentialTypes(context.Background(), connect.NewRequest(&backendv1.ListCredentialTypesRequest{}))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(resp.Msg.GetConfigurations()) != 1 || c.Calls != 1 {
		t.Errorf("list = %+v, calls = %d", resp.Msg.GetConfigurations(), c.Calls)
	}
	c.Err = errors.New("down")
	if _, err := c.ListCredentialTypes(context.Background(), connect.NewRequest(&backendv1.ListCredentialTypesRequest{})); err == nil {
		t.Error("list must fail")
	}
}
