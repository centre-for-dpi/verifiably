// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
)

// TestRepublishRegistersEveryPublishedVersionAgain is ADR-077: a stack
// that kept a registration of an earlier release, such as a walt.id
// configuration with the retired vct, gets the registration of the
// registry again when the registry starts. A draft and a retired
// version stay out. A second run makes the same calls, so a run at
// every start changes nothing more.
func TestRepublishRegistersEveryPublishedVersionAgain(t *testing.T) {
	s, fb := newService(t, &fakeBackend{})
	ctx := context.Background()
	degree := create(t, s, "Degree")
	if _, err := s.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: degree.GetId()})); err != nil {
		t.Fatal(err)
	}
	permit := create(t, s, "Permit")
	if _, err := s.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: permit.GetId()})); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Retire(ctx, connect.NewRequest(&schemav1.RetireRequest{Id: permit.GetId()})); err != nil {
		t.Fatal(err)
	}
	create(t, s, "Draft")
	for run := 1; run <= 2; run++ {
		fb.calls = nil
		n, err := s.Republish(ctx)
		if err != nil || n != 1 {
			t.Fatalf("run %d: Republish = %d, %v; want the one published version", run, n, err)
		}
		if len(fb.calls) != 2 {
			t.Fatalf("run %d: %d registrations, want one per format of Degree", run, len(fb.calls))
		}
		for _, c := range fb.calls {
			want := "Degree"
			if c.GetFormat() == commonv1.Format_FORMAT_DC_SD_JWT {
				want = "https://r/.well-known/vct/Degree"
			}
			if c.GetType() != want || c.GetId() == "" {
				t.Errorf("run %d: %v registers %q as %q, want %q", run, c.GetFormat(), c.GetId(), c.GetType(), want)
			}
		}
	}
}

// TestRepublishReportsAStackThatRefuses: a failed registration names its
// version, and the other versions still go.
func TestRepublishReportsAStackThatRefuses(t *testing.T) {
	s, fb := newService(t, &fakeBackend{})
	ctx := context.Background()
	degree := create(t, s, "Degree")
	if _, err := s.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: degree.GetId()})); err != nil {
		t.Fatal(err)
	}
	fb.err = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	if n, err := s.Republish(ctx); n != 0 || err == nil {
		t.Fatalf("Republish = %d, %v; want a failure", n, err)
	}
	none, _ := newService(t, nil)
	if n, err := none.Republish(ctx); n != 0 || err != nil {
		t.Fatalf("a registry with no stack: %d, %v", n, err)
	}
}
