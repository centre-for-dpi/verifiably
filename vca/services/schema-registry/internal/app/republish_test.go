// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
)

// flakyBackend refuses the first runs of a registration, as an adapter
// that starts after the registry does.
type flakyBackend struct {
	fakeBackend
	refuse int
}

func (f *flakyBackend) RegisterCredentialConfiguration(ctx context.Context, req *connect.Request[backendv1.RegisterCredentialConfigurationRequest]) (*connect.Response[backendv1.RegisterCredentialConfigurationResponse], error) {
	if f.refuse > 0 {
		f.refuse--
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("the adapter is starting"))
	}
	return f.fakeBackend.RegisterCredentialConfiguration(ctx, req)
}

// TestRepublishWaitsForTheStack is ADR-077: at start the registry
// registers every published version again, and it tries again until the
// adapter answers.
func TestRepublishWaitsForTheStack(t *testing.T) {
	backend := &flakyBackend{}
	a := buildWith(t, settings(t), backend, staff(t))
	ctx := context.Background()
	created, err := a.Service.Create(ctx, connect.NewRequest(&schemav1.CreateRequest{Schema: &schemav1.Schema{
		Type: "Degree", JsonSchema: `{"type":"object","properties":{"name":{"type":"string"}}}`,
		Formats: []commonv1.Format{commonv1.Format_FORMAT_DC_SD_JWT},
	}}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Service.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: created.Msg.GetSchema().GetId()})); err != nil {
		t.Fatal(err)
	}
	backend.ids, backend.refuse = nil, 2
	if err := a.Republish(ctx, time.Millisecond); err != nil {
		t.Fatalf("Republish: %v", err)
	}
	if len(backend.ids) != 1 || backend.refuse != 0 {
		t.Fatalf("registered %v after the refusals, want the one version once", backend.ids)
	}
	// A stack that never answers keeps the registry trying until it stops.
	backend.refuse = 1 << 30
	stopped, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if err := a.Republish(stopped, time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Republish against a silent stack = %v, want the end of the context", err)
	}
}
