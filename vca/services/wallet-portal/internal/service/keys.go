// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/session"
)

// WalletKeys is what the keys page shows of the wallet of the stack:
// its keys, its DIDs, and its latest events (P6-W4).
type WalletKeys struct {
	Keys   []*backendv1.WalletKey
	Dids   []*backendv1.WalletDid
	Events []*backendv1.WalletEvent
}

// errNoStackWallet answers a key call of a browser held wallet.
var errNoStackWallet = connect.NewError(connect.CodeFailedPrecondition,
	errors.New("this wallet keeps its keys in the browser; the stack holds no key of it"))

// holderOf returns the citizen and the holder backend of a key call.
func (s *Service) holderOf(ctx context.Context) (session.Citizen, error) {
	citizen, err := session.Require(ctx)
	if err != nil {
		return session.Citizen{}, err
	}
	if s.opts.Holder == nil {
		return session.Citizen{}, errNoStackWallet
	}
	return citizen, nil
}

// WalletParts names the parts of the stack wallet a page reads. Each
// part maps onto one feature of the adapter.
type WalletParts struct {
	// Keys reads the keys (FEATURE_WALLET_KEYS).
	Keys bool
	// Dids reads the DIDs (FEATURE_WALLET_DIDS).
	Dids bool
	// Events reads the event log (FEATURE_WALLET_EVENTS).
	Events bool
}

// ReadWalletKeys reads the parts of the wallet a page shows: its keys,
// its DIDs, and its events.
func (s *Service) ReadWalletKeys(ctx context.Context, parts WalletParts) (WalletKeys, error) {
	citizen, err := s.holderOf(ctx)
	if err != nil {
		return WalletKeys{}, err
	}
	var out WalletKeys
	if parts.Keys {
		keys, kerr := s.opts.Holder.ListKeys(ctx, connect.NewRequest(&backendv1.ListKeysRequest{WalletId: citizen.WalletID}))
		if kerr != nil {
			return WalletKeys{}, kerr
		}
		out.Keys = keys.Msg.GetKeys()
	}
	if parts.Dids {
		list, derr := s.opts.Holder.ListDids(ctx, connect.NewRequest(&backendv1.ListDidsRequest{WalletId: citizen.WalletID}))
		if derr != nil {
			return WalletKeys{}, derr
		}
		out.Dids = list.Msg.GetDids()
	}
	if parts.Events {
		list, eerr := s.opts.Holder.ListEvents(ctx, connect.NewRequest(&backendv1.ListEventsRequest{WalletId: citizen.WalletID}))
		if eerr != nil {
			return WalletKeys{}, eerr
		}
		out.Events = list.Msg.GetEvents()
	}
	return out, nil
}

// CreateWalletKey makes a key of one type in the wallet.
func (s *Service) CreateWalletKey(ctx context.Context, keyType string) error {
	citizen, err := s.holderOf(ctx)
	if err != nil {
		return err
	}
	_, err = s.opts.Holder.CreateKey(ctx, connect.NewRequest(&backendv1.CreateKeyRequest{WalletId: citizen.WalletID, KeyType: keyType}))
	return err
}

// CreateWalletDid makes a DID in the wallet with a key of the wallet, or
// a new key when keyID is empty.
func (s *Service) CreateWalletDid(ctx context.Context, method, keyID, alias string) error {
	citizen, err := s.holderOf(ctx)
	if err != nil {
		return err
	}
	_, err = s.opts.Holder.CreateDid(ctx, connect.NewRequest(&backendv1.CreateDidRequest{
		WalletId: citizen.WalletID, Method: method, KeyId: keyID, Alias: alias,
	}))
	return err
}

// SetWalletDefaultDid picks the DID the wallet binds new credentials to.
func (s *Service) SetWalletDefaultDid(ctx context.Context, did string) error {
	citizen, err := s.holderOf(ctx)
	if err != nil {
		return err
	}
	_, err = s.opts.Holder.SetDefaultDid(ctx, connect.NewRequest(&backendv1.SetDefaultDidRequest{WalletId: citizen.WalletID, Did: did}))
	return err
}
