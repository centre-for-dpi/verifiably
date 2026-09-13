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
	fail bool
	got  string
}

func (b *fakeBackend) Register(_ context.Context, req *connect.Request[backendv1.RegisterRequest]) (*connect.Response[backendv1.RegisterResponse], error) {
	if b.fail {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("down"))
	}
	b.got = req.Msg.GetPairwiseSubject()
	return connect.NewResponse(&backendv1.RegisterResponse{WalletId: "w-" + req.Msg.GetPairwiseSubject(), HolderDid: "did:example:1"}), nil
}

func TestRegistry(t *testing.T) {
	store := &failStore{Persister: oidcflow.NewMemoryPersister()}
	reg, err := wallets.New(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	w, created, err := reg.Ensure(ctx, "hash1", wallets.LocalRegistrar{})
	if err != nil || !created || w.WalletID != "hash1" || w.CreatedAt.IsZero() {
		t.Fatalf("%+v %v %v", w, created, err)
	}
	w, created, err = reg.Ensure(ctx, "hash1", wallets.LocalRegistrar{})
	if err != nil || created {
		t.Fatalf("second: %+v %v %v", w, created, err)
	}
	if reg.Count() != 1 {
		t.Fatal("count")
	}
	if _, err := reg.Get("nope"); !errors.Is(err, wallets.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := reg.BindKey("nope", "tp", "did"); !errors.Is(err, wallets.ErrNotFound) {
		t.Fatal(err)
	}
	w, err = reg.BindKey("hash1", "tp", "did:jwk:x")
	if err != nil || w.KeyThumbprint != "tp" || w.HolderDID != "did:jwk:x" {
		t.Fatalf("%+v %v", w, err)
	}
	reg2, _ := wallets.New(store, nil)
	if got, _ := reg2.Get("hash1"); got.KeyThumbprint != "tp" {
		t.Fatal("not persisted")
	}
	// Save failures roll back.
	store.fail = true
	if _, _, err := reg.Ensure(ctx, "hash2", wallets.LocalRegistrar{}); err == nil {
		t.Fatal("save error hidden")
	}
	if _, err := reg.Get("hash2"); err == nil {
		t.Fatal("create not rolled back")
	}
	if _, err := reg.BindKey("hash1", "other", ""); err == nil {
		t.Fatal("save error hidden")
	}
	if got, _ := reg.Get("hash1"); got.KeyThumbprint != "tp" {
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
	reg, _ := wallets.New(oidcflow.NewMemoryPersister(), nil)
	r := wallets.NewConnectRegistrar(srv.Client(), srv.URL)
	w, created, err := reg.Ensure(context.Background(), "hash", r)
	if err != nil || !created || w.WalletID != "w-hash" || w.HolderDID != "did:example:1" || be.got != "hash" {
		t.Fatalf("%+v %v %v", w, created, err)
	}
	be.fail = true
	if _, _, err := reg.Ensure(context.Background(), "other", r); !errors.Is(err, oidcflow.ErrUpstream) {
		t.Fatalf("down: %v", err)
	}
	r2 := wallets.NewConnectRegistrar(nil, "http://127.0.0.1:1")
	if _, _, err := r2.Register(context.Background(), "k", ""); !errors.Is(err, oidcflow.ErrUpstream) {
		t.Fatalf("unreachable: %v", err)
	}
}
