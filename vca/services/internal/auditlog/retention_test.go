// SPDX-License-Identifier: Apache-2.0

package auditlog_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"

	auditv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/audit/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// appendAt writes one event at each of the given day offsets from start.
func appendAt(t *testing.T, l *auditlog.Log, clock *time.Time, days ...int) {
	t.Helper()
	for _, d := range days {
		*clock = start.AddDate(0, 0, d)
		if _, err := l.Append(context.Background(), auditlog.Entry{Action: "trust.Upsert", OK: true}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
}

func count(t *testing.T, l *auditlog.Log) int {
	t.Helper()
	page, err := l.Query(context.Background(), auditlog.Filter{PageSize: auditlog.MaxPageSize})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	return page.TotalSize
}

// TestSetRetentionPrunesOldEvents removes the events older than the
// retention at once and keeps the setting.
func TestSetRetentionPrunesOldEvents(t *testing.T) {
	clock := start
	l := newLog(t, &clock)
	ctx := context.Background()
	appendAt(t, l, &clock, 0, 1, 8, 10)
	if days, err := l.Retention(ctx); err != nil || days != 0 {
		t.Fatalf("Retention = %d, %v before a setting", days, err)
	}
	removed, err := l.SetRetention(ctx, 5)
	if err != nil || removed != 2 {
		t.Fatalf("SetRetention = %d, %v", removed, err)
	}
	if days, err := l.Retention(ctx); err != nil || days != 5 {
		t.Fatalf("Retention = %d, %v", days, err)
	}
	if n := count(t, l); n != 2 {
		t.Fatalf("events = %d", n)
	}
	if removed, err := l.SetRetention(ctx, 0); err != nil || removed != 0 {
		t.Fatalf("SetRetention(0) = %d, %v", removed, err)
	}
	if _, err := l.SetRetention(ctx, -1); !errors.Is(err, auditlog.ErrRetention) {
		t.Fatalf("negative days: %v", err)
	}
	if _, err := l.SetRetention(ctx, auditlog.MaxRetentionDays+1); !errors.Is(err, auditlog.ErrRetention) {
		t.Fatalf("too many days: %v", err)
	}
}

// TestAppendPrunesAsTimePasses keeps the store inside the retention
// without a call from the admin. The log lists the store at most once
// an hour for it.
func TestAppendPrunesAsTimePasses(t *testing.T) {
	clock := start
	kv := &counting{KeyValue: store.Memory()}
	l, err := auditlog.New(kv, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, serr := l.SetRetention(ctx, 1); serr != nil {
		t.Fatal(err)
	}
	appendAt(t, l, &clock, 0)
	// A second log over the same store reads the setting from the store.
	other, err := auditlog.New(kv, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	appendAt(t, other, &clock, 3)
	if n := count(t, other); n != 1 {
		t.Fatalf("events = %d after three days", n)
	}
	lists := kv.lists
	clock = clock.Add(10 * time.Minute)
	other.Write(ctx, auditlog.Entry{Action: "trust.Upsert", OK: true})
	if kv.lists != lists {
		t.Fatalf("the log listed the store %d times within the hour", kv.lists-lists)
	}
	clock = clock.Add(2 * time.Hour)
	other.Write(ctx, auditlog.Entry{Action: "trust.Upsert", OK: true})
	if kv.lists != lists+1 {
		t.Fatalf("the log listed the store %d times after two hours", kv.lists-lists)
	}
}

// counting counts the List calls of a store.
type counting struct {
	store.KeyValue
	lists int
}

func (c *counting) List(ctx context.Context, prefix string) ([]string, error) {
	c.lists++
	return c.KeyValue.List(ctx, prefix)
}

func TestRetentionReportsAStoreFault(t *testing.T) {
	ctx := context.Background()
	kv := &flaky{KeyValue: store.Memory()}
	l, err := auditlog.New(kv, nil)
	if err != nil {
		t.Fatal(err)
	}
	if perr := kv.Put(ctx, auditlog.RetentionKey, []byte("x")); perr != nil {
		t.Fatal(err)
	}
	if _, rerr := l.Retention(ctx); rerr == nil {
		t.Error("Retention read a broken setting")
	}
	kv.failList = true
	if _, serr := l.SetRetention(ctx, 3); serr == nil {
		t.Error("SetRetention hid a list error")
	}
	broken, err := auditlog.New(failStore{KeyValue: store.Memory(), failSwap: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broken.Prune(ctx, start); err != nil {
		t.Errorf("Prune of an empty store: %v", err)
	}
}

func TestHandlerSetRetention(t *testing.T) {
	kv := store.Memory()
	client := serveLog(t, adminOnly, kv)
	if _, err := client.SetRetention(context.Background(), withBearer(&auditv1.SetRetentionRequest{Days: 3}, "")); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("no token: %v", err)
	}
	if _, err := client.SetRetention(context.Background(), withBearer(&auditv1.SetRetentionRequest{Days: -2}, "admin")); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("negative: %v", err)
	}
	res, err := client.SetRetention(context.Background(), withBearer(&auditv1.SetRetentionRequest{Days: 30}, "admin"))
	if err != nil || res.Msg.GetDays() != 30 {
		t.Fatalf("SetRetention = %+v, %v", res, err)
	}
	flakyKV := &flaky{KeyValue: store.Memory()}
	broken := serveLog(t, adminOnly, flakyKV)
	flakyKV.failList = true
	if _, err := broken.SetRetention(context.Background(), withBearer(&auditv1.SetRetentionRequest{Days: 1}, "admin")); connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("store fault: %v", err)
	}
}

func TestActorFromTheHeader(t *testing.T) {
	cases := map[string]string{
		"":                        "",
		"kc|alice":                "kc|alice",
		"  spaced  ":              "spaced",
		"bad\nline":               "",
		string(make([]byte, 300)): "",
	}
	for in, want := range cases {
		h := http.Header{}
		h.Set(auditlog.ActorHeader, in)
		if got := auditlog.ActorFrom(h); got != want {
			t.Errorf("ActorFrom(%q) = %q, want %q", in, got, want)
		}
	}
	ctx := auditlog.WithActor(context.Background(), "kc|root")
	if got := auditlog.ActorOf(ctx); got != "kc|root" {
		t.Errorf("ActorOf = %q", got)
	}
	if got := auditlog.ActorOf(context.Background()); got != "" {
		t.Errorf("ActorOf empty = %q", got)
	}
}

func TestOpenPicksTheStore(t *testing.T) {
	mem, err := auditlog.Open("", nil)
	if err != nil || mem == nil {
		t.Fatalf("Open memory = %v", err)
	}
	dir := filepath.Join(t.TempDir(), "audit")
	l, err := auditlog.Open(dir, nil)
	if err != nil {
		t.Fatalf("Open dir: %v", err)
	}
	l.Write(context.Background(), auditlog.Entry{Action: "trust.Upsert", OK: true})
	again, err := auditlog.Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := count(t, again); n != 1 {
		t.Fatalf("events after a reopen = %d", n)
	}
	if _, err := auditlog.Open(string([]byte{0}), nil); err == nil {
		t.Error("Open took a bad directory")
	}
}

// TestPruneReadsBothIDForms removes an old event of the older id form
// and leaves a key that holds no time.
func TestPruneReadsBothIDForms(t *testing.T) {
	ctx := context.Background()
	kv := store.Memory()
	l, err := auditlog.New(kv, func() time.Time { return start })
	if err != nil {
		t.Fatal(err)
	}
	old := auditlog.Prefix + fmt.Sprintf("%015d-AAAAAAAAAAAA", start.AddDate(0, 0, -9).UnixMilli())
	for _, k := range []string{old, auditlog.Prefix + "short-x", auditlog.Prefix + "nodash"} {
		if perr := kv.Put(ctx, k, []byte(`{"action":"x"}`)); perr != nil {
			t.Fatal(err)
		}
	}
	removed, err := l.Prune(ctx, start.AddDate(0, 0, -1))
	if err != nil || removed != 1 {
		t.Fatalf("Prune = %d, %v", removed, err)
	}
	if _, err := kv.Get(ctx, old); err == nil {
		t.Fatal("the old event stayed")
	}
}
