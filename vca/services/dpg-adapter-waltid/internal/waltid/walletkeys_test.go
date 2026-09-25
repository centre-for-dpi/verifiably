// SPDX-License-Identifier: Apache-2.0

package waltid

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// walletServer answers each path with one body; a missing path fails.
func walletServer(t *testing.T, answers map[string]string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := answers[r.URL.Path]
		if !ok {
			http.Error(w, "no", http.StatusBadRequest)
			return
		}
		mustWrite(t, w, []byte(body))
	}))
	t.Cleanup(srv.Close)
	return New(Options{Wallet: dpgclient.New(dpgclient.Options{BaseURL: srv.URL, HTTP: srv.Client(), Retries: -1})})
}

func TestWalletKeyCallsNeedTheWallet(t *testing.T) {
	c, ctx, s := New(Options{}), context.Background(), WalletSession{WalletID: "w"}
	_, e1 := c.ListKeys(ctx, s)
	_, e2 := c.GenerateKey(ctx, s, "Ed25519")
	_, e3 := c.ListDIDs(ctx, s)
	_, e4 := c.CreateDID(ctx, s, "key", "", "")
	e5 := c.SetDefaultDID(ctx, s, "did:key:z")
	e6 := c.RejectOffer(ctx, s, "offer", "")
	_, _, e7 := c.ListEvents(ctx, s, 10, "")
	for i, err := range []error{e1, e2, e3, e4, e5, e6, e7} {
		if !errors.Is(err, ErrNoWallet) {
			t.Errorf("call %d: %v", i, err)
		}
	}
}

func TestWalletKeyCallsReportFailures(t *testing.T) {
	c, ctx, s := walletServer(t, map[string]string{
		"/wallet-api/wallet/w/exchange/useOfferRequest": "not json",
		"/wallet-api/wallet/w/eventlog":                 `{"reason":"bad filter"}`,
	}), context.Background(), WalletSession{WalletID: "w"}
	if _, err := c.ListKeys(ctx, s); err == nil {
		t.Error("keys")
	}
	if _, err := c.GenerateKey(ctx, s, "Ed25519"); err == nil {
		t.Error("generate")
	}
	if _, err := c.ListDIDs(ctx, s); err == nil {
		t.Error("dids")
	}
	if _, err := c.CreateDID(ctx, s, "key", "", ""); err == nil {
		t.Error("create")
	}
	if err := c.RejectOffer(ctx, s, "offer", ""); err == nil || !strings.Contains(err.Error(), "pending") {
		t.Errorf("reject: %v", err)
	}
	if _, _, err := c.ListEvents(ctx, s, 5, "3"); err == nil || !strings.Contains(err.Error(), "bad filter") {
		t.Errorf("events: %v", err)
	}
	down := walletServer(t, nil)
	if _, _, err := down.ListEvents(ctx, s, 5, ""); err == nil {
		t.Error("events of a failed call")
	}
	if err := down.RejectOffer(ctx, s, "offer", ""); err == nil {
		t.Error("reject of a failed call")
	}
}

func TestWalletEventParts(t *testing.T) {
	var e WalletEvent
	if err := json.Unmarshal([]byte(`{"originator":"https://issuer.example","timestamp":"2026-09-25T09:00:00Z","data":{}}`), &e); err != nil {
		t.Fatal(err)
	}
	if e.Counterpart() != "https://issuer.example" || !e.Time().Equal(time.Date(2026, 9, 25, 9, 0, 0, 0, time.UTC)) {
		t.Fatalf("event = %+v", e)
	}
	if (WalletDID{CreatedOn: "yesterday"}).Time() != (time.Time{}) {
		t.Fatal("a bad time must give the zero time")
	}
	c, ctx, s := walletServer(t, map[string]string{
		"/wallet-api/wallet/w/eventlog": `{"items":[],"nextStartingAfter":"9"}`,
	}), context.Background(), WalletSession{WalletID: "w"}
	if _, next, err := c.ListEvents(ctx, s, 5, ""); err != nil || next != "9" {
		t.Fatalf("next = %q %v", next, err)
	}
}

func TestWalletKeyCallsReadTheAnswers(t *testing.T) {
	c, ctx, s := walletServer(t, map[string]string{
		"/wallet-api/wallet/w/keys":                     `[{"algorithm":"Ed25519","cryptoProvider":"LocalKey","keyId":{"id":"k1"}}]`,
		"/wallet-api/wallet/w/keys/generate":            `"k2"`,
		"/wallet-api/wallet/w/dids":                     `[{"did":"did:key:z1","default":true}]`,
		"/wallet-api/wallet/w/dids/create/key":          `did:key:z2`,
		"/wallet-api/wallet/w/dids/default":             ``,
		"/wallet-api/wallet/w/exchange/useOfferRequest": `[{"id":"c1"}]`,
		"/wallet-api/wallet/w/credentials/c1/reject":    ``,
		"/wallet-api/wallet/w/eventlog":                 `{"items":[{"id":3,"data":{"organization":{"name":"Ministry of Transport"}}}]}`,
		"/verification-session/s1/response":             `{}`,
	}), context.Background(), WalletSession{WalletID: "w"}
	keys, err := c.ListKeys(ctx, s)
	if err != nil || len(keys) != 1 || keys[0].KeyID.ID != "k1" {
		t.Fatalf("keys = %v %v", keys, err)
	}
	if id, ierr := c.GenerateKey(ctx, s, "Ed25519"); ierr != nil || id != "k2" {
		t.Fatalf("generate = %q %v", id, ierr)
	}
	if dids, ierr := c.ListDIDs(ctx, s); ierr != nil || !dids[0].Default {
		t.Fatalf("dids = %v %v", dids, ierr)
	}
	if did, ierr := c.CreateDID(ctx, s, "key", "k1", "Travel"); ierr != nil || did != "did:key:z2" {
		t.Fatalf("create = %q %v", did, ierr)
	}
	if ierr := c.SetDefaultDID(ctx, s, "did:key:z2"); ierr != nil {
		t.Fatal(ierr)
	}
	if ierr := c.RejectOffer(ctx, s, "offer", "Not mine"); ierr != nil {
		t.Fatal(ierr)
	}
	events, _, err := c.ListEvents(ctx, s, 5, "")
	if err != nil || events[0].Counterpart() != "Ministry of Transport" || events[0].ID.String() != "3" {
		t.Fatalf("events = %v %v", events, err)
	}
	failing := walletServer(t, map[string]string{"/wallet-api/wallet/w/exchange/useOfferRequest": `[{"id":"c1"}]`})
	if err := failing.RejectOffer(ctx, s, "offer", ""); err == nil {
		t.Error("a refused reject passed")
	}
	if err := failing.SetDefaultDID(ctx, s, "did:key:z2"); err == nil {
		t.Error("a refused default passed")
	}
	v2 := New(Options{Verifier2: c.wallet})
	if err := v2.SubmitResponse2(ctx, "s1", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := v2.SubmitResponse2(ctx, "gone", json.RawMessage(`{}`)); err == nil {
		t.Error("a refused answer passed")
	}
	if err := New(Options{}).SubmitResponse2(ctx, "s1", nil); !errors.Is(err, ErrNoVerifier2) {
		t.Errorf("no verifier 2: %v", err)
	}
	if (Session2Created{BootstrapURL: "openid4vp://b", FullURL: "openid4vp://f"}).RequestURL() != "openid4vp://b" {
		t.Error("the bootstrap URL loses to the full URL")
	}
}
