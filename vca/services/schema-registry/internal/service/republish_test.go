// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
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
		out := s.Republish(ctx, nil)
		if out.Done != 1 || len(out.Retry) != 0 || len(out.Failed) != 0 {
			t.Fatalf("run %d: Republish = %+v; want the one published version", run, out)
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
	none, _ := newService(t, nil)
	if out := none.Republish(ctx, nil); out.Done != 0 || len(out.Retry) != 0 || len(out.Failed) != 0 {
		t.Fatalf("a registry with no stack: %+v", out)
	}
}

// pickyBackend refuses the registrations of some types with a code.
type pickyBackend struct {
	fakeBackend
	refuse map[string]error
}

func (f *pickyBackend) RegisterCredentialConfiguration(ctx context.Context, req *connect.Request[backendv1.RegisterCredentialConfigurationRequest]) (*connect.Response[backendv1.RegisterCredentialConfigurationResponse], error) {
	for typ, err := range f.refuse {
		if strings.HasSuffix(req.Msg.GetConfiguration().GetType(), typ) {
			return nil, err
		}
	}
	return f.fakeBackend.RegisterCredentialConfiguration(ctx, req)
}

// publishOn builds a registry over the backend with one published
// version of each type. It returns the keys in order.
func publishOn(t *testing.T, backend backendv1connect.IssuerBackendServiceClient, types ...string) (*Service, []Key) {
	t.Helper()
	s, _ := newService(t, nil)
	s.opts.Backend = backend
	var keys []Key
	for _, typ := range types {
		m := create(t, s, typ)
		if _, err := s.Publish(context.Background(), connect.NewRequest(&schemav1.PublishRequest{Id: m.GetId()})); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, Key{ID: m.GetId(), Version: 1})
	}
	return s, keys
}

// TestRepublishSortsTheRefusals is ADR-077 as amended on 2026-10-04: a
// refusal that time can heal (unavailable, deadline exceeded) goes back
// on the list. Every other code stops the version, and the detail page
// shows the reason. A run with a list registers only those versions.
func TestRepublishSortsTheRefusals(t *testing.T) {
	backend := &pickyBackend{}
	s, keys := publishOn(t, backend, "Degree", "Permit", "Licence", "Card", "Badge")
	backend.refuse = map[string]error{
		"Permit":  connect.NewError(connect.CodeUnavailable, errors.New("the adapter is starting")),
		"Licence": connect.NewError(connect.CodeDeadlineExceeded, errors.New("slow")),
		"Card":    connect.NewError(connect.CodeAlreadyExists, errors.New("the platform holds the name Card")),
		"Badge":   connect.NewError(connect.CodeFailedPrecondition, errors.New("no DID on the ledger")),
	}
	ctx := context.Background()
	out := s.Republish(ctx, nil)
	if out.Done != 1 {
		t.Errorf("done = %d, want Degree only", out.Done)
	}
	if len(out.Retry) != 2 || !slices.Contains(out.Retry, keys[1]) || !slices.Contains(out.Retry, keys[2]) {
		t.Errorf("retry = %v, want Permit and Licence", out.Retry)
	}
	var failed []Key
	for _, f := range out.Failed {
		failed = append(failed, f.Key)
	}
	if len(failed) != 2 || !slices.Contains(failed, keys[3]) || !slices.Contains(failed, keys[4]) {
		t.Fatalf("failed = %v, want Card and Badge", out.Failed)
	}
	if got := s.RegistrationFailure(keys[3].ID, 1); !strings.Contains(got, "the platform holds the name Card") {
		t.Errorf("the failure of Card = %q", got)
	}
	if got := s.RegistrationFailure(keys[1].ID, 1); got != "" {
		t.Errorf("a version that waits shows the failure %q", got)
	}
	backend.calls = nil
	delete(backend.refuse, "Permit")
	out = s.Republish(ctx, out.Retry)
	if out.Done != 1 || len(out.Retry) != 1 || out.Retry[0] != keys[2] {
		t.Errorf("the second run = %+v, want Permit done and Licence again", out)
	}
	for _, c := range backend.calls {
		if !strings.HasSuffix(c.GetType(), "Permit") {
			t.Errorf("the second run registered %q, which went or stopped before", c.GetType())
		}
	}
	// A version that left the published state leaves the list.
	if _, err := s.Retire(ctx, connect.NewRequest(&schemav1.RetireRequest{Id: keys[2].ID})); err != nil {
		t.Fatal(err)
	}
	if out = s.Republish(ctx, []Key{keys[2]}); out.Done != 0 || len(out.Retry) != 0 {
		t.Errorf("a retired version = %+v", out)
	}
}

// TestRetryRegistrationOfTheDetailPage: the action of the detail page
// registers one stopped version again. A success clears the reason. A
// refusal keeps a reason on the page, whatever its code.
func TestRetryRegistrationOfTheDetailPage(t *testing.T) {
	backend := &pickyBackend{}
	s, keys := publishOn(t, backend, "Card")
	backend.refuse = map[string]error{"Card": connect.NewError(connect.CodeAlreadyExists, errors.New("the platform holds the name Card"))}
	ctx := context.Background()
	s.Republish(ctx, nil)
	backend.refuse["Card"] = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	if err := s.RetryRegistration(ctx, keys[0].ID, 1); err == nil {
		t.Fatal("a refused retry gave no error")
	}
	if got := s.RegistrationFailure(keys[0].ID, 1); !strings.Contains(got, "down") {
		t.Errorf("the failure after a refused retry = %q", got)
	}
	delete(backend.refuse, "Card")
	if err := s.RetryRegistration(ctx, keys[0].ID, 1); err != nil {
		t.Fatalf("RetryRegistration: %v", err)
	}
	if got := s.RegistrationFailure(keys[0].ID, 1); got != "" {
		t.Errorf("a registered version still shows %q", got)
	}
	if err := s.RetryRegistration(ctx, keys[0].ID, 9); code(err) != connect.CodeNotFound {
		t.Errorf("a retry of a missing version = %v", err)
	}
	draft := create(t, s, "Draft")
	if err := s.RetryRegistration(ctx, draft.GetId(), 1); code(err) != connect.CodeFailedPrecondition {
		t.Errorf("a retry of a draft = %v", err)
	}
	none, _ := newService(t, nil)
	if err := none.RetryRegistration(ctx, keys[0].ID, 1); code(err) != connect.CodeFailedPrecondition {
		t.Errorf("a retry with no stack = %v", err)
	}
}

// TestPublishStillAnswersUnavailable: the publish action keeps its code
// for a refusal of the stack, so the issuer can try again.
func TestPublishStillAnswersUnavailable(t *testing.T) {
	s, fb := newService(t, &fakeBackend{})
	fb.err = connect.NewError(connect.CodeAlreadyExists, errors.New("taken"))
	m := create(t, s, "Degree")
	if _, err := s.Publish(context.Background(), connect.NewRequest(&schemav1.PublishRequest{Id: m.GetId()})); code(err) != connect.CodeUnavailable {
		t.Fatalf("Publish = %v, want unavailable", err)
	}
}
