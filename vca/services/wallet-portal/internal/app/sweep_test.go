// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/session"
)

// TestTheAppSweepsExpiredRecordsOnATimer: the app removes the expired
// pending records of every wallet on a timer, so a request that nobody
// answers leaves no file on the volume.
func TestTheAppSweepsExpiredRecordsOnATimer(t *testing.T) {
	k := newKeys(t)
	dir := t.TempDir()
	var mu sync.Mutex
	at := time.Now()
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return at
	}
	cfg := load(t, map[string]string{"VCA_WALLET_PORTAL_AUTH_JWKS_FILE": k.file(t), "VCA_WALLET_PORTAL_STATE_DIR": dir})
	var logs bytes.Buffer
	a, err := app.Build(cfg, app.Deps{Now: clock, Log: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	holder := session.With(context.Background(), session.Citizen{Subject: "https://idp|abc", WalletID: "wallet-1", SessionID: "sid-1"})
	if _, serr := a.Service.Scan(holder, connect.NewRequest(&walletportalv1.ScanRequest{
		Text: "openid4vp://?client_id=v&request_uri=https://verifier.example/r/1",
	})); serr != nil {
		t.Fatal(serr)
	}
	kv, err := store.File(dir)
	if err != nil {
		t.Fatal(err)
	}
	list := func() []string {
		keys, lerr := kv.List(context.Background(), "vp/")
		if lerr != nil {
			t.Fatal(lerr)
		}
		return keys
	}
	if len(list()) != 1 {
		t.Fatalf("the scan kept %v, want one record", list())
	}
	mu.Lock()
	at = at.Add(time.Hour)
	mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.SweepPending(ctx, time.Millisecond) }()
	for len(list()) != 0 && ctx.Err() == nil {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if derr := <-done; derr == nil {
		t.Error("the sweep ended before its context")
	}
	if len(list()) != 0 {
		t.Fatalf("records after the sweep: %v", list())
	}
	if !strings.Contains(logs.String(), "removed expired pending records") {
		t.Errorf("the sweep logged nothing:\n%s", logs.String())
	}
}
