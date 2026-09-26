// SPDX-License-Identifier: Apache-2.0

package wallets_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/wallets"
)

type failStore struct {
	oidcflow.Persister
	fail bool
}

func (f *failStore) Save(name string, v any) error {
	if f.fail {
		return errors.New("fail")
	}
	return f.Persister.Save(name, v)
}

func (f *failStore) Load(name string, v any) error {
	if f.fail {
		return errors.New("fail")
	}
	return f.Persister.Load(name, v)
}

type fakeBackend struct {
	backendv1connect.UnimplementedHolderBackendServiceHandler
	fail  bool
	code  connect.Code
	got   string
	token string
	calls int
}

func (b *fakeBackend) Register(_ context.Context, req *connect.Request[backendv1.RegisterRequest]) (*connect.Response[backendv1.RegisterResponse], error) {
	b.calls++
	if b.fail {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("down"))
	}
	if b.code != 0 {
		return nil, connect.NewError(b.code, errors.New("no wallet for this holder"))
	}
	b.got = req.Msg.GetPairwiseSubject()
	b.token = req.Msg.GetIdToken()
	return connect.NewResponse(&backendv1.RegisterResponse{WalletId: "w-" + req.Msg.GetPairwiseSubject(), HolderDid: "did:example:1"}), nil
}

func TestRegistry(t *testing.T) {
	store := &failStore{Persister: oidcflow.NewMemoryPersister()}
	reg, err := wallets.New(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	w, created, err := reg.Ensure(ctx, "hash1", "", wallets.LocalRegistrar{})
	if err != nil || !created || w.WalletID != "hash1" || w.CreatedAt.IsZero() {
		t.Fatalf("%+v %v %v", w, created, err)
	}
	w, created, err = reg.Ensure(ctx, "hash1", "", wallets.LocalRegistrar{})
	if err != nil || created {
		t.Fatalf("second: %+v %v %v", w, created, err)
	}
	if reg.Count() != 1 {
		t.Fatal("count")
	}
	if _, serr := reg.Get("nope"); !errors.Is(serr, wallets.ErrNotFound) {
		t.Fatal(serr)
	}
	if _, serr := reg.BindKey("nope", "tp", "did"); !errors.Is(serr, wallets.ErrNotFound) {
		t.Fatal(serr)
	}
	w, err = reg.BindKey("hash1", "tp", "did:jwk:x")
	if err != nil || w.KeyThumbprint != "tp" || w.HolderDID != "did:jwk:x" {
		t.Fatalf("%+v %v", w, err)
	}
	reg2, verr := wallets.New(store, nil)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if got, ierr := reg2.Get("hash1"); ierr != nil || got.KeyThumbprint != "tp" {
		t.Fatal("not persisted")
	}
	// Save failures roll back.
	store.fail = true
	if _, _, err := reg.Ensure(ctx, "hash2", "", wallets.LocalRegistrar{}); err == nil {
		t.Fatal("save error hidden")
	}
	if _, err := reg.Get("hash2"); err == nil {
		t.Fatal("create not rolled back")
	}
	if _, err := reg.BindKey("hash1", "other", ""); err == nil {
		t.Fatal("save error hidden")
	}
	if got, ierr := reg.Get("hash1"); ierr != nil || got.KeyThumbprint != "tp" {
		t.Fatal("bind not rolled back")
	}
	if _, err := wallets.New(store, nil); err == nil {
		t.Fatal("load error hidden")
	}
}

func TestConnectRegistrar(t *testing.T) {
	be := &fakeBackend{}
	path, h := backendv1connect.NewHolderBackendServiceHandler(be)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	reg, verr := wallets.New(oidcflow.NewMemoryPersister(), nil)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	r := wallets.NewConnectRegistrar(srv.Client(), srv.URL)
	w, created, err := reg.Ensure(context.Background(), "hash", "id.token", r)
	if err != nil || !created || w.WalletID != "w-hash" || w.HolderDID != "did:example:1" || be.got != "hash" || be.token != "id.token" {
		t.Fatalf("%+v %v %v", w, created, err)
	}
	be.fail = true
	if _, _, err := reg.Ensure(context.Background(), "other", "", r); !errors.Is(err, oidcflow.ErrUpstream) {
		t.Fatalf("down: %v", err)
	}
	r2 := wallets.NewConnectRegistrar(nil, "http://127.0.0.1:1")
	if _, _, err := r2.Register(context.Background(), "k", "", ""); !errors.Is(err, oidcflow.ErrUpstream) {
		t.Fatalf("unreachable: %v", err)
	}
}

// TestEnsureOpensTheWalletAtEveryLogin passes the ID token of each login
// to a registrar that opens every login. A later failure keeps the
// record, so the login goes on.
func TestEnsureOpensTheWalletAtEveryLogin(t *testing.T) {
	be := &fakeBackend{}
	srv := holderServer(be)
	defer srv.Close()
	reg, err := wallets.New(oidcflow.NewMemoryPersister(), nil)
	if err != nil {
		t.Fatal(err)
	}
	r := wallets.NewConnectRegistrar(srv.Client(), srv.URL)
	ctx := context.Background()
	if _, _, ferr := reg.Ensure(ctx, "hash", "first.token", r); ferr != nil {
		t.Fatal(ferr)
	}
	w, created, err := reg.Ensure(ctx, "hash", "second.token", r)
	if err != nil || created || w.WalletID != "w-hash" || be.token != "second.token" || be.calls != 2 {
		t.Fatalf("second login: %+v %v %v, token %q, calls %d", w, created, err, be.token, be.calls)
	}
	be.fail = true
	if w, _, err := reg.Ensure(ctx, "hash", "third.token", r); err != nil || w.WalletID != "w-hash" {
		t.Fatalf("a failed reopen: %+v %v", w, err)
	}
	// A local registrar opens nothing at a later login.
	if w, _, err := reg.Ensure(ctx, "hash", "", wallets.LocalRegistrar{}); err != nil || w.WalletID != "w-hash" {
		t.Fatalf("local: %+v %v", w, err)
	}
}

// TestEnsureKeepsTheBrowserStore gives the local wallet id when the
// backend serves no wallet for the holder, and takes the wallet of the
// backend once it serves one.
func TestEnsureKeepsTheBrowserStore(t *testing.T) {
	for _, code := range []connect.Code{connect.CodeUnimplemented, connect.CodeFailedPrecondition, connect.CodePermissionDenied} {
		be := &fakeBackend{code: code}
		srv := holderServer(be)
		reg, err := wallets.New(oidcflow.NewMemoryPersister(), nil)
		if err != nil {
			t.Fatal(err)
		}
		r := wallets.NewConnectRegistrar(srv.Client(), srv.URL)
		w, created, err := reg.Ensure(context.Background(), "hash", "t", r)
		if err != nil || !created || w.WalletID != "hash" {
			t.Fatalf("%v: %+v %v %v", code, w, created, err)
		}
		be.code = 0
		if w, _, err = reg.Ensure(context.Background(), "hash", "t", r); err != nil || w.WalletID != "w-hash" {
			t.Fatalf("%v: the backend wallet did not replace the local id: %+v %v", code, w, err)
		}
		srv.Close()
	}
}

// TestReopenKeepsTheRecordWhenTheSaveFails keeps the stored wallet id
// when the store refuses the new one.
func TestReopenKeepsTheRecordWhenTheSaveFails(t *testing.T) {
	be := &fakeBackend{code: connect.CodeUnimplemented}
	srv := holderServer(be)
	defer srv.Close()
	store := &failStore{Persister: oidcflow.NewMemoryPersister()}
	reg, err := wallets.New(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := wallets.NewConnectRegistrar(srv.Client(), srv.URL)
	if _, _, err := reg.Ensure(context.Background(), "hash", "t", r); err != nil {
		t.Fatal(err)
	}
	be.code = 0
	store.fail = true
	if w, _, err := reg.Ensure(context.Background(), "hash", "t", r); err != nil || w.WalletID != "hash" {
		t.Fatalf("%+v %v", w, err)
	}
}

// holderServer serves the fake holder backend.
func holderServer(be *fakeBackend) *httptest.Server {
	path, h := backendv1connect.NewHolderBackendServiceHandler(be)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	return httptest.NewServer(mux)
}
