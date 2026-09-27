// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/service"
)

// TestWalletKeysGoToTheStackWallet reads and changes the keys and the
// DIDs of the wallet of the stack for the citizen of the session.
func TestWalletKeysGoToTheStackWallet(t *testing.T) {
	holder := &fakeHolder{}
	svc := build(t, withHolder(holder))
	got, err := svc.ReadWalletKeys(ctx(), service.WalletParts{Keys: true, Dids: true, Events: true})
	if err != nil || len(got.Keys) != 1 || len(got.Dids) != 1 || len(got.Events) != 1 {
		t.Fatalf("read = %+v %v", got, err)
	}
	if only, err := svc.ReadWalletKeys(ctx(), service.WalletParts{Keys: true}); err != nil || only.Dids != nil || only.Events != nil {
		t.Fatalf("keys only = %+v %v", only, err)
	}
	// A wallet that lists DIDs and no keys reads no key (ADR-062
	// decision 6).
	if dids, err := svc.ReadWalletKeys(ctx(), service.WalletParts{Dids: true}); err != nil || dids.Keys != nil || len(dids.Dids) != 1 {
		t.Fatalf("DIDs only = %+v %v", dids, err)
	}
	for _, err := range []error{
		svc.CreateWalletKey(ctx(), "Ed25519"),
		svc.CreateWalletDid(ctx(), "did:jwk", "k1", "Work"),
		svc.SetWalletDefaultDid(ctx(), "did:key:z1"),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	want := "keys:" + citizen().WalletID + ",dids,events,keys:" + citizen().WalletID + ",dids,key:Ed25519,did:did:jwk:k1:Work,default:did:key:z1"
	if strings.Join(holder.keyCalls, ",") != want {
		t.Fatalf("calls = %v", holder.keyCalls)
	}
	holder.keysErr = errors.New("down")
	if _, err := svc.ReadWalletKeys(ctx(), service.WalletParts{Keys: true, Dids: true, Events: true}); err == nil {
		t.Error("a failed read passed")
	}
	browser := build(t, func(o *service.Options) { o.Holder = nil })
	if _, err := browser.ReadWalletKeys(ctx(), service.WalletParts{Keys: true, Dids: true, Events: true}); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("browser wallet: %v", err)
	}
	for _, err := range []error{
		browser.CreateWalletKey(ctx(), "Ed25519"), browser.CreateWalletDid(ctx(), "did:jwk", "", ""), browser.SetWalletDefaultDid(ctx(), "did:x"),
	} {
		if connect.CodeOf(err) != connect.CodeFailedPrecondition {
			t.Errorf("browser wallet: %v", err)
		}
	}
	if _, err := svc.ReadWalletKeys(context.Background(), service.WalletParts{Keys: true, Dids: true, Events: true}); err == nil {
		t.Error("no session passed")
	}
}
