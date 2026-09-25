// SPDX-License-Identifier: Apache-2.0

package auditlog_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/internal/serve"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

var start = time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)

// newLog returns a log with a clock the test moves forward.
func newLog(t *testing.T, clock *time.Time) *auditlog.Log {
	t.Helper()
	l, err := auditlog.New(store.Memory(), func() time.Time { return *clock })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return l
}

func TestNewNeedsAStore(t *testing.T) {
	if _, err := auditlog.New(nil, nil); err == nil {
		t.Fatal("New accepted a nil store")
	}
	if _, err := auditlog.New(store.Memory(), nil); err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestAppendNeedsAnAction(t *testing.T) {
	clock := start
	l := newLog(t, &clock)
	if _, err := auditlog.New(store.Memory(), nil); err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := l.Append(context.Background(), auditlog.Entry{Actor: "a"}); err == nil {
		t.Fatal("Append accepted an entry without an action")
	}
}

func TestAppendFillsTheRecord(t *testing.T) {
	clock := start
	l := newLog(t, &clock)
	rec, err := l.Append(context.Background(), auditlog.Entry{
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
		rec, err := l.Append(ctx, auditlog.Entry{Action: "admin.ListTenants"})
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
		if seen[rec.ID] {
			t.Fatalf("id %q appeared twice", rec.ID)
		}
		seen[rec.ID] = true
	}
	page, err := l.Query(ctx, auditlog.Filter{PageSize: 100})
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
		if _, err := l.Append(ctx, auditlog.Entry{Action: "admin.CreateTenant", Target: string(rune('a' + i))}); err != nil {
			t.Fatalf("Append: %v", err)
		}
		clock = clock.Add(time.Second)
	}
	page, err := l.Query(ctx, auditlog.Filter{})
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
		if _, err := l.Append(ctx, auditlog.Entry{Action: "admin.CreateTenant"}); err != nil {
			t.Fatalf("Append: %v", err)
		}
		clock = clock.Add(time.Second)
	}
	var seen int
	token := ""
	for round := 0; round < 5; round++ {
		page, err := l.Query(ctx, auditlog.Filter{PageSize: 2, PageToken: token})
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
	if _, err := l.Append(ctx, auditlog.Entry{Actor: "one", Action: "admin.CreateTenant"}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	clock = clock.Add(time.Hour)
	if _, err := l.Append(ctx, auditlog.Entry{Actor: "two", Action: "admin.DeleteTenant"}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	cases := map[string]auditlog.Filter{
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
	page, err := l.Query(ctx, auditlog.Filter{Actor: "nobody"})
	if err != nil || len(page.Records) != 0 || page.TotalSize != 0 {
		t.Fatalf("unknown actor: %+v, %v", page, err)
	}
}

// TestQueryFiltersByTarget returns the events of one target only, so a
// page can show the history of one record.
func TestQueryFiltersByTarget(t *testing.T) {
	clock := start
	l := newLog(t, &clock)
	ctx := context.Background()
	for _, target := range []string{"rec-1", "rec-2", "rec-1", "rec-10"} {
		clock = clock.Add(time.Minute)
		if _, err := l.Append(ctx, auditlog.Entry{Actor: "one", Action: "issued.Revoke", Target: target}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	page, err := l.Query(ctx, auditlog.Filter{Target: "rec-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 2 || page.TotalSize != 2 {
		t.Fatalf("records = %+v", page.Records)
	}
	for _, r := range page.Records {
		if r.Target != "rec-1" {
			t.Errorf("target %q passed the filter", r.Target)
		}
	}
}

func TestQueryCapsThePageSize(t *testing.T) {
	clock := start
	l := newLog(t, &clock)
	ctx := context.Background()
	if _, err := l.Append(ctx, auditlog.Entry{Action: "admin.ListTenants"}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	page, err := l.Query(ctx, auditlog.Filter{PageSize: auditlog.MaxPageSize + 100})
	if err != nil || len(page.Records) != 1 {
		t.Fatalf("Query = %+v, %v", page, err)
	}
}

func TestQueryWithAnUnknownTokenReturnsNothing(t *testing.T) {
	clock := start
	l := newLog(t, &clock)
	ctx := context.Background()
	if _, err := l.Append(ctx, auditlog.Entry{Action: "admin.ListTenants"}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	page, err := l.Query(ctx, auditlog.Filter{PageToken: "missing"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(page.Records) != 0 {
		t.Fatalf("records = %d", len(page.Records))
	}
}

func TestMatchesIgnoresThePageFields(t *testing.T) {
	rec := auditlog.Record{Actor: "a", Action: "b", At: start}
	if !auditlog.Matches(rec, auditlog.Filter{PageSize: 1, PageToken: "x"}) {
		t.Fatal("Matches used the page fields")
	}
	if auditlog.Matches(rec, auditlog.Filter{Action: "c"}) {
		t.Fatal("Matches accepted a wrong action")
	}
}

func TestNewIDIsSortableByTime(t *testing.T) {
	early := auditlog.NewID(start)
	late := auditlog.NewID(start.Add(time.Millisecond))
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
	appendFail, verr := auditlog.New(failStore{KeyValue: kv, failSwap: true}, nil)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if _, err := appendFail.Append(ctx, auditlog.Entry{Action: "admin.CreateTenant"}); err == nil {
		t.Error("Append hid a store error")
	}
	listFail, verr := auditlog.New(failStore{KeyValue: kv, failList: true}, nil)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if _, err := listFail.Query(ctx, auditlog.Filter{}); err == nil {
		t.Error("Query hid a list error")
	}
	good, verr := auditlog.New(kv, nil)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if _, err := good.Append(ctx, auditlog.Entry{Action: "admin.CreateTenant"}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	getFail, verr := auditlog.New(failStore{KeyValue: kv, failGet: true}, nil)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if _, err := getFail.Query(ctx, auditlog.Filter{}); err == nil {
		t.Error("Query hid a get error")
	}
}

func TestQueryReportsABrokenRecord(t *testing.T) {
	ctx := context.Background()
	kv := store.Memory()
	if err := kv.Put(ctx, auditlog.Prefix+"broken", []byte("{")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	l, verr := auditlog.New(kv, nil)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if _, err := l.Query(ctx, auditlog.Filter{}); err == nil {
		t.Fatal("Query read a broken record")
	}
}

// TestAppendOnlyAndTimeOrder appends events at three times, out of
// the order of their targets, and reads them back newest first with
// every field the ADR names. A second write under a taken key fails.
func TestAppendOnlyAndTimeOrder(t *testing.T) {
	clock := start
	kv := store.Memory()
	l, err := auditlog.New(kv, func() time.Time { return clock })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	for i, target := range []string{"first", "second", "third"} {
		if _, aerr := l.Append(ctx, auditlog.Entry{
			Actor: "actor", Action: "auth.Login", Target: target, OK: i != 1, Detail: "note " + target,
		}); aerr != nil {
			t.Fatalf("Append: %v", aerr)
		}
		clock = clock.Add(time.Minute)
	}
	page, err := l.Query(ctx, auditlog.Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	var got []string
	for _, r := range page.Records {
		got = append(got, r.Target+"/"+r.Detail+"/"+r.Outcome())
	}
	want := "third/note third/success second/note second/failure first/note first/success"
	if strings.Join(got, " ") != want {
		t.Fatalf("order = %q, want %q", strings.Join(got, " "), want)
	}
	keys, err := kv.List(ctx, auditlog.Prefix)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if err := kv.CompareAndSwap(ctx, keys[0], nil, []byte("{}")); err == nil {
		t.Fatal("the store let a record be written twice")
	}
}

// TestQueryFilters covers each filter of the query alone and together.
func TestQueryFilters(t *testing.T) {
	clock := start
	l := newLog(t, &clock)
	ctx := context.Background()
	entries := []auditlog.Entry{
		{Actor: "alice", Action: "auth.Login", OK: true},
		{Actor: "", Action: "auth.Login", OK: false, Detail: "the provider refused the code"},
		{Actor: "alice", Action: "auth.Logout", OK: true},
		{Actor: "bob", Action: "auth.Register", OK: true},
	}
	for _, e := range entries {
		if _, err := l.Append(ctx, e); err != nil {
			t.Fatalf("Append: %v", err)
		}
		clock = clock.Add(time.Hour)
	}
	cases := []struct {
		name string
		f    auditlog.Filter
		want int
	}{
		{"none", auditlog.Filter{}, 4},
		{"actor", auditlog.Filter{Actor: "alice"}, 2},
		{"action", auditlog.Filter{Action: "auth.Login"}, 2},
		{"failure", auditlog.Filter{Outcome: auditlog.OutcomeFailure}, 1},
		{"success", auditlog.Filter{Outcome: auditlog.OutcomeSuccess}, 3},
		{"from", auditlog.Filter{From: start.Add(90 * time.Minute)}, 2},
		{"to", auditlog.Filter{To: start.Add(90 * time.Minute)}, 2},
		{"together", auditlog.Filter{Action: "auth.Login", Outcome: auditlog.OutcomeSuccess, Actor: "alice"}, 1},
		{"no match", auditlog.Filter{Action: "auth.Logout", Outcome: auditlog.OutcomeFailure}, 0},
	}
	for _, c := range cases {
		page, err := l.Query(ctx, c.f)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(page.Records) != c.want || page.TotalSize != c.want {
			t.Errorf("%s: records = %d total = %d, want %d", c.name, len(page.Records), page.TotalSize, c.want)
		}
	}
	if auditlog.ValidOutcome("maybe") || !auditlog.ValidOutcome("") || !auditlog.ValidOutcome(auditlog.OutcomeFailure) {
		t.Error("ValidOutcome is wrong")
	}
}

// TestAppendTakesTheRequestIDFromTheContext reads the id that the
// request id middleware stored, when the entry names none.
func TestAppendTakesTheRequestIDFromTheContext(t *testing.T) {
	clock := start
	l := newLog(t, &clock)
	var rec auditlog.Record
	h := serve.RequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		var err error
		if rec, err = l.Append(r.Context(), auditlog.Entry{Action: "auth.Login"}); err != nil {
			t.Errorf("Append: %v", err)
		}
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(serve.RequestIDHeader, "req-42")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if rec.RequestID != "req-42" {
		t.Fatalf("request id = %q", rec.RequestID)
	}
}

// TestWriteIgnoresANilLogAndAFault keeps the action of a caller
// independent of its audit store.
func TestWriteIgnoresANilLogAndAFault(t *testing.T) {
	var none *auditlog.Log
	none.Write(context.Background(), auditlog.Entry{Action: "auth.Login"})
	broken, err := auditlog.New(failStore{KeyValue: store.Memory(), failSwap: true}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	broken.Write(context.Background(), auditlog.Entry{Action: "auth.Login"})
	clock := start
	l := newLog(t, &clock)
	l.Write(context.Background(), auditlog.Entry{Action: "auth.Login", OK: true})
	page, err := l.Query(context.Background(), auditlog.Filter{})
	if err != nil || len(page.Records) != 1 {
		t.Fatalf("Query = %+v, %v", page, err)
	}
}

// TestNewIDKeepsTheOrderInsideAMillisecond sorts two events of one
// millisecond by time, so a page that ends inside that millisecond
// loses no event. An id of the older form, with milliseconds only,
// still sorts before every newer id of its millisecond.
func TestNewIDKeepsTheOrderInsideAMillisecond(t *testing.T) {
	for i := 0; i < 50; i++ {
		early := auditlog.NewID(start.Add(10 * time.Microsecond))
		late := auditlog.NewID(start.Add(900 * time.Microsecond))
		if early >= late {
			t.Fatalf("%q is not before %q", early, late)
		}
	}
	old := fmt.Sprintf("%015d-AAAAAAAAAAAA", start.UnixMilli())
	if newer := auditlog.NewID(start); old >= newer {
		t.Fatalf("the old id %q is not before %q", old, newer)
	}
	if next := auditlog.NewID(start.Add(time.Millisecond)); next <= old {
		t.Fatalf("%q is not after the old id %q", next, old)
	}
}
