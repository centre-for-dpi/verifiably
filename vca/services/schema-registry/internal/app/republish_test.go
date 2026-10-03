// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
)

// flakyBackend refuses the registrations of a type a number of times
// with one code, as an adapter that starts after the registry does, or
// for ever with another, as a stack that holds the name.
type flakyBackend struct {
	fakeBackend
	mu     sync.Mutex
	refuse map[string]int
	codes  map[string]connect.Code
	tries  map[string]int
}

func (f *flakyBackend) RegisterCredentialConfiguration(ctx context.Context, req *connect.Request[backendv1.RegisterCredentialConfigurationRequest]) (*connect.Response[backendv1.RegisterCredentialConfigurationResponse], error) {
	f.mu.Lock()
	typ := req.Msg.GetConfiguration().GetType()
	typ = typ[strings.LastIndex(typ, "/")+1:]
	f.tries[typ]++
	if f.refuse[typ] > 0 {
		f.refuse[typ]--
		code := f.codes[typ]
		f.mu.Unlock()
		return nil, connect.NewError(code, errors.New("the stack refused "+typ))
	}
	f.mu.Unlock()
	return f.fakeBackend.RegisterCredentialConfiguration(ctx, req)
}

// publishAll publishes one version of each type.
func publishAll(t *testing.T, a *App, types ...string) {
	t.Helper()
	ctx := context.Background()
	for _, typ := range types {
		created, err := a.Service.Create(ctx, connect.NewRequest(&schemav1.CreateRequest{Schema: &schemav1.Schema{
			Type: typ, JsonSchema: `{"type":"object","properties":{"name":{"type":"string"}}}`,
			Formats: []commonv1.Format{commonv1.Format_FORMAT_DC_SD_JWT},
		}}))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.Service.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: created.Msg.GetSchema().GetId()})); err != nil {
			t.Fatal(err)
		}
	}
}

// logged builds an app whose log goes to the buffer.
func logged(t *testing.T, backend backendv1connect.IssuerBackendServiceClient, buf *bytes.Buffer) *App {
	t.Helper()
	issuer := staff(t)
	a, err := Build(settings(t), Deps{
		Backend: backend, Now: func() time.Time { return now }, SessionKeys: issuer.Keys(),
		Log: slog.New(slog.NewTextHandler(buf, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestRepublishWaitsForTheStack is ADR-077: at start the registry
// registers every published version again, and it tries again until the
// adapter answers.
func TestRepublishWaitsForTheStack(t *testing.T) {
	backend := &flakyBackend{refuse: map[string]int{}, codes: map[string]connect.Code{}, tries: map[string]int{}}
	var buf bytes.Buffer
	a := logged(t, backend, &buf)
	publishAll(t, a, "Degree")
	backend.ids = nil
	backend.refuse["Degree"], backend.codes["Degree"] = 2, connect.CodeUnavailable
	ctx := context.Background()
	if err := a.Republish(ctx, Backoff{First: time.Millisecond, Max: time.Millisecond}); err != nil {
		t.Fatalf("Republish: %v", err)
	}
	if len(backend.ids) != 1 || backend.refuse["Degree"] != 0 {
		t.Fatalf("registered %v after the refusals, want the one version once", backend.ids)
	}
	// A stack that never answers keeps the registry trying until it stops.
	backend.refuse["Degree"] = 1 << 30
	stopped, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if err := a.Republish(stopped, Backoff{First: time.Millisecond, Max: time.Millisecond}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Republish against a silent stack = %v, want the end of the context", err)
	}
}

// TestRepublishBacksOffAndStopsOnARefusal is ADR-077 as amended on
// 2026-10-04: the wait doubles up to its cap, only the versions that
// the stack could still take go again, and a refusal with any other
// code stops that version with one log line.
func TestRepublishBacksOffAndStopsOnARefusal(t *testing.T) {
	backend := &flakyBackend{refuse: map[string]int{}, codes: map[string]connect.Code{}, tries: map[string]int{}}
	var buf bytes.Buffer
	a := logged(t, backend, &buf)
	publishAll(t, a, "Degree", "Permit", "Card")
	backend.refuse = map[string]int{"Permit": 4, "Card": 1 << 30}
	backend.codes = map[string]connect.Code{"Permit": connect.CodeUnavailable, "Card": connect.CodeAlreadyExists}
	backend.tries = map[string]int{}
	var waits []time.Duration
	err := a.Republish(context.Background(), Backoff{First: time.Second, Max: 4 * time.Second, Wait: func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}})
	if err != nil {
		t.Fatalf("Republish: %v", err)
	}
	if want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second}; !equalDurations(waits, want) {
		t.Errorf("waits = %v, want %v", waits, want)
	}
	if backend.tries["Degree"] != 1 || backend.tries["Card"] != 1 || backend.tries["Permit"] != 5 {
		t.Errorf("tries = %v, want Degree and Card once, Permit until it went", backend.tries)
	}
	if n := strings.Count(buf.String(), "the stack refused Card"); n != 1 {
		t.Errorf("the refusal of Card shows %d times in the log, want once:\n%s", n, buf.String())
	}
	if !strings.Contains(a.Service.RegistrationFailure(cardID(t, a), 1), "the stack refused Card") {
		t.Error("the detail page of Card shows no reason")
	}
	// A wait that the end of the service cuts ends the run.
	backend.refuse["Permit"] = 1
	stop := errors.New("stopped")
	if err := a.Republish(context.Background(), Backoff{First: time.Second, Max: time.Second, Wait: func(context.Context, time.Duration) error {
		return stop
	}}); !errors.Is(err, stop) {
		t.Errorf("Republish with a cut wait = %v", err)
	}
}

// TestBackoffDefaults: a backoff with no wait sleeps on a timer, and a
// cap below the first wait keeps the first wait.
func TestBackoffDefaults(t *testing.T) {
	b := Backoff{First: time.Millisecond}
	if got := b.next(time.Millisecond); got != time.Millisecond {
		t.Errorf("next with no cap = %v", got)
	}
	if err := b.wait(context.Background(), time.Millisecond); err != nil {
		t.Errorf("wait = %v", err)
	}
	done, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.wait(done, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("wait after the end = %v", err)
	}
}

// cardID returns the id of the schema of the type Card.
func cardID(t *testing.T, a *App) string {
	t.Helper()
	resp, err := a.Service.List(context.Background(), connect.NewRequest(&schemav1.ListRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range resp.Msg.GetSchemas() {
		if m.GetType() == "Card" {
			return m.GetId()
		}
	}
	t.Fatal("no schema Card")
	return ""
}

func equalDurations(a, b []time.Duration) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
