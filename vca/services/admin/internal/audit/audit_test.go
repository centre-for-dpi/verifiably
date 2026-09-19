// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/audit"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

var start = time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)

// newLog returns a log with a clock the test moves forward.
func newLog(t *testing.T, clock *time.Time) *audit.Log {
	t.Helper()
	l, err := audit.New(store.Memory(), func() time.Time { return *clock })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return l
}

func TestNewNeedsAStore(t *testing.T) {
	if _, err := audit.New(nil, nil); err == nil {
		t.Fatal("New accepted a nil store")
	}
	if _, err := audit.New(store.Memory(), nil); err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestAppendNeedsAnAction(t *testing.T) {
	clock := start
	l := newLog(t, &clock)
	if _, err := audit.New(store.Memory(), nil); err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := l.Append(context.Background(), audit.Entry{Actor: "a"}); err == nil {
		t.Fatal("Append accepted an entry without an action")
	}
}

func TestAppendFillsTheRecord(t *testing.T) {
	clock := start
	l := newLog(t, &clock)
	rec, err := l.Append(context.Background(), audit.Entry{
		Actor: "https://idp.example|user-1", Action: "admin.CreateTenant", RequestID: "req-1", Target: "t1", OK: true,
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if rec.ID == "" || !rec.At.Equal(start) || !rec.OK {
		t.Fatalf("record = %+v", rec)
	}
	if rec.Actor != "https://idp.example|user-1" || rec.Action != "admin.CreateTenant" {
		t.Fatalf("record = %+v", rec)
	}
}

func TestAppendNeverOverwritesARecord(t *testing.T) {
	clock := start
	l := newLog(t, &clock)
	ctx := context.Background()
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		rec, err := l.Append(ctx, audit.Entry{Action: "admin.ListTenants"})
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
		if seen[rec.ID] {
			t.Fatalf("id %q appeared twice", rec.ID)
		}
		seen[rec.ID] = true
	}
	page, err := l.Query(ctx, audit.Filter{PageSize: 100})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(page.Records) != 20 || page.TotalSize != 20 {
		t.Fatalf("records = %d total = %d", len(page.Records), page.TotalSize)
	}
}

func TestQueryReturnsTheNewestRecordFirst(t *testing.T) {
	clock := start
	l := newLog(t, &clock)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := l.Append(ctx, audit.Entry{Action: "admin.CreateTenant", Target: string(rune('a' + i))}); err != nil {
			t.Fatalf("Append: %v", err)
		}
		clock = clock.Add(time.Second)
	}
	page, err := l.Query(ctx, audit.Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(page.Records) != 3 {
		t.Fatalf("records = %d", len(page.Records))
	}
	if page.Records[0].Target != "c" || page.Records[2].Target != "a" {
		t.Fatalf("order = %q %q %q", page.Records[0].Target, page.Records[1].Target, page.Records[2].Target)
	}
	if page.NextPageToken != "" {
		t.Errorf("token = %q on the last page", page.NextPageToken)
	}
}

func TestQueryPagesThroughTheLog(t *testing.T) {
	clock := start
	l := newLog(t, &clock)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := l.Append(ctx, audit.Entry{Action: "admin.CreateTenant"}); err != nil {
			t.Fatalf("Append: %v", err)
		}
		clock = clock.Add(time.Second)
	}
	var seen int
	token := ""
	for round := 0; round < 5; round++ {
		page, err := l.Query(ctx, audit.Filter{PageSize: 2, PageToken: token})
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if page.TotalSize != 5 {
			t.Errorf("total = %d", page.TotalSize)
		}
		seen += len(page.Records)
		token = page.NextPageToken
		if token == "" {
			break
		}
	}
	if seen != 5 {
		t.Fatalf("saw %d records", seen)
	}
}

func TestQueryFiltersByActorActionAndTime(t *testing.T) {
	clock := start
	l := newLog(t, &clock)
	ctx := context.Background()
	if _, err := l.Append(ctx, audit.Entry{Actor: "one", Action: "admin.CreateTenant"}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	clock = clock.Add(time.Hour)
	if _, err := l.Append(ctx, audit.Entry{Actor: "two", Action: "admin.DeleteTenant"}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	cases := map[string]audit.Filter{
		"actor":  {Actor: "one"},
		"action": {Action: "admin.CreateTenant"},
		"to":     {To: start.Add(time.Minute)},
		"from":   {From: start.Add(30 * time.Minute), Actor: "two"},
	}
	for name, f := range cases {
		page, err := l.Query(ctx, f)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(page.Records) != 1 {
			t.Errorf("%s: records = %d", name, len(page.Records))
		}
	}
	page, err := l.Query(ctx, audit.Filter{Actor: "nobody"})
	if err != nil || len(page.Records) != 0 || page.TotalSize != 0 {
		t.Fatalf("unknown actor: %+v, %v", page, err)
	}
}

func TestQueryCapsThePageSize(t *testing.T) {
	clock := start
	l := newLog(t, &clock)
	ctx := context.Background()
	if _, err := l.Append(ctx, audit.Entry{Action: "admin.ListTenants"}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	page, err := l.Query(ctx, audit.Filter{PageSize: audit.MaxPageSize + 100})
	if err != nil || len(page.Records) != 1 {
		t.Fatalf("Query = %+v, %v", page, err)
	}
}

func TestQueryWithAnUnknownTokenReturnsNothing(t *testing.T) {
	clock := start
	l := newLog(t, &clock)
	ctx := context.Background()
	if _, err := l.Append(ctx, audit.Entry{Action: "admin.ListTenants"}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	page, err := l.Query(ctx, audit.Filter{PageToken: "missing"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(page.Records) != 0 {
		t.Fatalf("records = %d", len(page.Records))
	}
}

func TestMatchesIgnoresThePageFields(t *testing.T) {
	rec := audit.Record{Actor: "a", Action: "b", At: start}
	if !audit.Matches(rec, audit.Filter{PageSize: 1, PageToken: "x"}) {
		t.Fatal("Matches used the page fields")
	}
	if audit.Matches(rec, audit.Filter{Action: "c"}) {
		t.Fatal("Matches accepted a wrong action")
	}
}

func TestNewIDIsSortableByTime(t *testing.T) {
	early := audit.NewID(start)
	late := audit.NewID(start.Add(time.Millisecond))
	if early >= late {
		t.Fatalf("%q is not before %q", early, late)
	}
}

// failStore fails the operations the test names.
type failStore struct {
	store.KeyValue
	failList bool
	failSwap bool
	failGet  bool
}

func (f failStore) List(ctx context.Context, prefix string) ([]string, error) {
	if f.failList {
		return nil, errors.New("list failed")
	}
	return f.KeyValue.List(ctx, prefix)
}

func (f failStore) CompareAndSwap(ctx context.Context, key string, old, value []byte) error {
	if f.failSwap {
		return errors.New("swap failed")
	}
	return f.KeyValue.CompareAndSwap(ctx, key, old, value)
}

func (f failStore) Get(ctx context.Context, key string) ([]byte, error) {
	if f.failGet {
		return nil, errors.New("get failed")
	}
	return f.KeyValue.Get(ctx, key)
}

func TestStoreErrorsTravelToTheCaller(t *testing.T) {
	ctx := context.Background()
	kv := store.Memory()
	appendFail, _ := audit.New(failStore{KeyValue: kv, failSwap: true}, nil)
	if _, err := appendFail.Append(ctx, audit.Entry{Action: "admin.CreateTenant"}); err == nil {
		t.Error("Append hid a store error")
	}
	listFail, _ := audit.New(failStore{KeyValue: kv, failList: true}, nil)
	if _, err := listFail.Query(ctx, audit.Filter{}); err == nil {
		t.Error("Query hid a list error")
	}
	good, _ := audit.New(kv, nil)
	if _, err := good.Append(ctx, audit.Entry{Action: "admin.CreateTenant"}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	getFail, _ := audit.New(failStore{KeyValue: kv, failGet: true}, nil)
	if _, err := getFail.Query(ctx, audit.Filter{}); err == nil {
		t.Error("Query hid a get error")
	}
}

func TestQueryReportsABrokenRecord(t *testing.T) {
	ctx := context.Background()
	kv := store.Memory()
	if err := kv.Put(ctx, audit.Prefix+"broken", []byte("{")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	l, _ := audit.New(kv, nil)
	if _, err := l.Query(ctx, audit.Filter{}); err == nil {
		t.Fatal("Query read a broken record")
	}
}
