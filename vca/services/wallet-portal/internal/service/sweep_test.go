// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/service"
)

// openRequest scans the request of the verifier and opens its consent
// page, which keeps the request object. It returns the presentation id.
func openRequest(t *testing.T, svc *service.Service) string {
	t.Helper()
	scan, err := svc.Scan(ctx(), connect.NewRequest(&walletportalv1.ScanRequest{
		Text: "openid4vp://?client_id=v&request_uri=https://verifier.example/r/1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	id := scan.Msg.GetDetected().GetPresentationId()
	if _, err := svc.PresentStart(ctx(), connect.NewRequest(&walletportalv1.PresentStartRequest{PresentationId: id})); err != nil {
		t.Fatal(err)
	}
	return id
}

// keys lists every pending key of the store.
func keys(t *testing.T, st store.KeyValue) []string {
	t.Helper()
	var out []string
	for _, kind := range []string{service.KindOffer, service.KindPresentation, service.KindHeld, service.KindSignIn} {
		got, err := st.List(context.Background(), kind+"/")
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, got...)
	}
	return out
}

// TestSweepRemovesEveryExpiredRecord: a holder who opens requests and
// never answers leaves a record with its request object each time. The
// sweep removes every expired record of every wallet, and keeps the
// records that still count.
func TestSweepRemovesEveryExpiredRecord(t *testing.T) {
	st := store.Memory()
	at := now()
	svc := build(t, func(o *service.Options) {
		o.Store, o.Fetch = st, fetchRequest
		o.Now = func() time.Time { return at }
	})
	openRequest(t, svc)
	openRequest(t, svc)
	if n := len(keys(t, st)); n != 2 {
		t.Fatalf("%d records before the sweep, want 2", n)
	}
	at = at.Add(16 * time.Minute)
	fresh := openRequest(t, svc)
	removed, err := svc.Sweep(context.Background())
	if err != nil || removed != 2 {
		t.Fatalf("Sweep = %d, %v; want the two expired records", removed, err)
	}
	left := keys(t, st)
	if len(left) != 1 || !strings.HasSuffix(left[0], "/"+fresh) {
		t.Fatalf("records after the sweep = %v, want %s only", left, fresh)
	}
	if removed, err = svc.Sweep(context.Background()); err != nil || removed != 0 {
		t.Fatalf("a second sweep = %d, %v", removed, err)
	}
}

// TestARequestObjectAboveTheCapIsRefused: the wallet keeps the request
// object of each open request, so it refuses an object above its cap
// with a clear reason and keeps none of it.
func TestARequestObjectAboveTheCapIsRefused(t *testing.T) {
	st := store.Memory()
	svc := build(t, func(o *service.Options) {
		o.Store, o.Fetch = st, fetchRequest
		o.MaxRequestObjectBytes = 16
	})
	scan, err := svc.Scan(ctx(), connect.NewRequest(&walletportalv1.ScanRequest{
		Text: "openid4vp://?client_id=v&request_uri=https://verifier.example/r/1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.PresentStart(ctx(), connect.NewRequest(&walletportalv1.PresentStartRequest{
		PresentationId: scan.Msg.GetDetected().GetPresentationId(),
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument || !strings.Contains(err.Error(), "at most 16 bytes") {
		t.Fatalf("PresentStart of a large object = %v, want invalid_argument that names the cap", err)
	}
	for _, k := range keys(t, st) {
		raw, gerr := st.Get(context.Background(), k)
		if gerr != nil {
			t.Fatal(gerr)
		}
		if strings.Contains(string(raw), `"object"`) {
			t.Errorf("%s keeps the refused object", k)
		}
	}
}

// brokenStore fails the calls it names, as a full disk does.
type brokenStore struct {
	store.KeyValue
	list, del bool
}

func (b brokenStore) List(ctx context.Context, prefix string) ([]string, error) {
	if b.list {
		return nil, errors.New("disk failed")
	}
	return b.KeyValue.List(ctx, prefix)
}

func (b brokenStore) Delete(ctx context.Context, key string) error {
	if b.del {
		return errors.New("disk failed")
	}
	return b.KeyValue.Delete(ctx, key)
}

// TestSweepReportsAStoreThatFails: a store that cannot list or delete
// stops the sweep with the error. A record that does not parse stays for
// an operator to read.
func TestSweepReportsAStoreThatFails(t *testing.T) {
	mem := store.Memory()
	at := now()
	svc := build(t, func(o *service.Options) {
		o.Store, o.Fetch = mem, fetchRequest
		o.Now = func() time.Time { return at }
	})
	openRequest(t, svc)
	if err := mem.Put(context.Background(), service.KindOffer+"/wallet-1/junk", []byte("not json")); err != nil {
		t.Fatal(err)
	}
	at = at.Add(time.Hour)
	for name, broken := range map[string]brokenStore{"list": {KeyValue: mem, list: true}, "delete": {KeyValue: mem, del: true}} {
		bad := build(t, func(o *service.Options) {
			o.Store = broken
			o.Now = func() time.Time { return at }
		})
		if _, err := bad.Sweep(context.Background()); err == nil {
			t.Errorf("a store that cannot %s: the sweep gave no error", name)
		}
	}
	if n, err := svc.Sweep(context.Background()); err != nil || n != 1 {
		t.Fatalf("Sweep = %d, %v; want the expired request only", n, err)
	}
	if left := keys(t, mem); len(left) != 1 || !strings.HasSuffix(left[0], "/junk") {
		t.Fatalf("records after the sweep = %v, want the record that does not parse", left)
	}
}
