// SPDX-License-Identifier: Apache-2.0

// Package wallets keeps the wallet record of each citizen. A record is
// keyed by the salted hash of the pairwise subject and holds no personal
// data (ADR-020 decisions 1 and 2).
package wallets

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
)

// ErrNotFound reports an unknown wallet key.
var ErrNotFound = errors.New("wallets: wallet not found")

// Wallet is one record. Key is the salted hash of iss|sub.
type Wallet struct {
	Key           string    `json:"key"`
	WalletID      string    `json:"wallet_id"`
	HolderDID     string    `json:"holder_did,omitempty"`
	KeyThumbprint string    `json:"key_thumbprint,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// Registrar creates the wallet at the holder backend.
type Registrar interface {
	// Register creates a wallet for the hashed pairwise subject and
	// returns the wallet id and, when the backend made one, a holder DID.
	Register(ctx context.Context, key, holderJWK string) (walletID, holderDID string, err error)
}

// LocalRegistrar uses the hashed subject as the wallet id. It serves
// deployments without a holder backend.
type LocalRegistrar struct{}

// Register implements Registrar.
func (LocalRegistrar) Register(_ context.Context, key, _ string) (string, string, error) {
	return key, "", nil
}

// ConnectRegistrar calls HolderBackendService.Register at a DPG adapter.
type ConnectRegistrar struct {
	client backendv1connect.HolderBackendServiceClient
}

// NewConnectRegistrar returns a registrar for the adapter at baseURL.
func NewConnectRegistrar(httpClient connect.HTTPClient, baseURL string) ConnectRegistrar {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return ConnectRegistrar{client: backendv1connect.NewHolderBackendServiceClient(httpClient, baseURL)}
}

// Register implements Registrar. The backend receives the hashed
// subject, never iss or sub.
func (r ConnectRegistrar) Register(ctx context.Context, key, holderJWK string) (string, string, error) {
	res, err := r.client.Register(ctx, connect.NewRequest(&backendv1.RegisterRequest{PairwiseSubject: key, HolderPublicJwk: holderJWK}))
	if err != nil {
		return "", "", fmt.Errorf("%w: holder backend: %w", oidcflow.ErrUpstream, err)
	}
	return res.Msg.GetWalletId(), res.Msg.GetHolderDid(), nil
}

const doc = "wallets"

// Registry stores wallet records through a Persister.
type Registry struct {
	store oidcflow.Persister
	now   func() time.Time
	mu    sync.RWMutex
	m     map[string]Wallet
}

// New loads the registry from store.
func New(store oidcflow.Persister, now func() time.Time) (*Registry, error) {
	if now == nil {
		now = time.Now
	}
	var list []Wallet
	if err := store.Load(doc, &list); err != nil {
		return nil, err
	}
	r := &Registry{store: store, now: now, m: map[string]Wallet{}}
	for _, w := range list {
		r.m[w.Key] = w
	}
	return r, nil
}

// Get returns one wallet.
func (r *Registry) Get(key string) (Wallet, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	w, ok := r.m[key]
	if !ok {
		return Wallet{}, ErrNotFound
	}
	return w, nil
}

// Count returns the number of wallets.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.m)
}

// Ensure returns the wallet for key. On the first login it asks the
// registrar for a wallet and stores the record. created is true then.
func (r *Registry) Ensure(ctx context.Context, key string, reg Registrar) (Wallet, bool, error) {
	if w, err := r.Get(key); err == nil {
		return w, false, nil
	}
	id, did, err := reg.Register(ctx, key, "")
	if err != nil {
		return Wallet{}, false, err
	}
	w := Wallet{Key: key, WalletID: id, HolderDID: did, CreatedAt: r.now().UTC()}
	if err := r.put(w); err != nil {
		return Wallet{}, false, err
	}
	return w, true, nil
}

// BindKey records the holder key thumbprint and DID of a wallet.
func (r *Registry) BindKey(key, thumbprint, holderDID string) (Wallet, error) {
	w, err := r.Get(key)
	if err != nil {
		return Wallet{}, err
	}
	w.KeyThumbprint = thumbprint
	w.HolderDID = holderDID
	if err := r.put(w); err != nil {
		return Wallet{}, err
	}
	return w, nil
}

func (r *Registry) put(w Wallet) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	prev, had := r.m[w.Key]
	r.m[w.Key] = w
	list := make([]Wallet, 0, len(r.m))
	for _, v := range r.m {
		list = append(list, v)
	}
	if err := r.store.Save(doc, list); err != nil {
		if had {
			r.m[w.Key] = prev
		} else {
			delete(r.m, w.Key)
		}
		return err
	}
	return nil
}
