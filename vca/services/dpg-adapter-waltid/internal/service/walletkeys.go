// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/waltid"
)

// WalletKeyTypes are the key types the wallet-api makes in a jwk key.
var WalletKeyTypes = []string{"Ed25519", "secp256r1", "secp256k1", "RSA"}

// WalletDidMethods are the DID methods the wallet makes without more
// settings. A did:web needs a host the holder serves, so the adapter
// does not offer it. A did:cheqd needs an Ed25519 key.
var WalletDidMethods = []string{"did:key", "did:jwk", "did:cheqd"}

// walletFeatures are the wallet features the adapter lists with a
// wallet URL.
var walletFeatures = []backendv1.Feature{
	backendv1.Feature_FEATURE_WALLET_KEYS, backendv1.Feature_FEATURE_WALLET_DIDS,
	backendv1.Feature_FEATURE_WALLET_EVENTS, backendv1.Feature_FEATURE_WALLET_REJECT_OFFER,
}

// walletSession checks the role and returns the session of a wallet.
func (s *Service) walletSession(ctx context.Context, walletID string) (waltid.WalletSession, error) {
	if !s.client.HasWallet() {
		return waltid.WalletSession{}, unimplemented("this adapter has no wallet URL, so it serves no holder role")
	}
	return s.session(ctx, walletID)
}

// ListKeys lists the keys of a wallet.
func (s *Service) ListKeys(
	ctx context.Context, req *connect.Request[backendv1.ListKeysRequest],
) (*connect.Response[backendv1.ListKeysResponse], error) {
	session, err := s.walletSession(ctx, req.Msg.GetWalletId())
	if err != nil {
		return nil, err
	}
	keys, err := s.client.ListKeys(ctx, session)
	if err != nil {
		return nil, failed("list the keys", err)
	}
	out := &backendv1.ListKeysResponse{}
	for _, k := range keys {
		out.Keys = append(out.Keys, &backendv1.WalletKey{Id: k.KeyID.ID, Type: k.Algorithm, Backend: k.CryptoProvider, Name: k.Name})
	}
	return connect.NewResponse(out), nil
}

// CreateKey makes a jwk key in a wallet.
func (s *Service) CreateKey(
	ctx context.Context, req *connect.Request[backendv1.CreateKeyRequest],
) (*connect.Response[backendv1.CreateKeyResponse], error) {
	session, err := s.walletSession(ctx, req.Msg.GetWalletId())
	if err != nil {
		return nil, err
	}
	if !contains(WalletKeyTypes, req.Msg.GetKeyType()) {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("the key type %q is not one of %s", req.Msg.GetKeyType(), strings.Join(WalletKeyTypes, ", ")))
	}
	id, err := s.client.GenerateKey(ctx, session, req.Msg.GetKeyType())
	if err != nil {
		return nil, failed("make the key", err)
	}
	return connect.NewResponse(&backendv1.CreateKeyResponse{Key: &backendv1.WalletKey{Id: id, Type: req.Msg.GetKeyType(), Backend: DefaultKeyBackend}}), nil
}

// ListDids lists the DIDs of a wallet.
func (s *Service) ListDids(
	ctx context.Context, req *connect.Request[backendv1.ListDidsRequest],
) (*connect.Response[backendv1.ListDidsResponse], error) {
	session, err := s.walletSession(ctx, req.Msg.GetWalletId())
	if err != nil {
		return nil, err
	}
	dids, err := s.client.ListDIDs(ctx, session)
	if err != nil {
		return nil, failed("list the DIDs", err)
	}
	out := &backendv1.ListDidsResponse{}
	for _, d := range dids {
		out.Dids = append(out.Dids, &backendv1.WalletDid{Did: d.DID, Alias: d.Alias, KeyId: d.KeyID, Default: d.Default, CreatedAt: timestamp(d.Time())})
	}
	return connect.NewResponse(out), nil
}

// CreateDid makes a DID in a wallet.
func (s *Service) CreateDid(
	ctx context.Context, req *connect.Request[backendv1.CreateDidRequest],
) (*connect.Response[backendv1.CreateDidResponse], error) {
	session, err := s.walletSession(ctx, req.Msg.GetWalletId())
	if err != nil {
		return nil, err
	}
	if !contains(WalletDidMethods, req.Msg.GetMethod()) {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("the method %q is not one of %s", req.Msg.GetMethod(), strings.Join(WalletDidMethods, ", ")))
	}
	alias := strings.TrimSpace(req.Msg.GetAlias())
	did, err := s.client.CreateDID(ctx, session, strings.TrimPrefix(req.Msg.GetMethod(), "did:"), strings.TrimSpace(req.Msg.GetKeyId()), alias)
	if err != nil {
		return nil, failed("make the DID", err)
	}
	return connect.NewResponse(&backendv1.CreateDidResponse{Did: &backendv1.WalletDid{Did: did, Alias: alias, KeyId: req.Msg.GetKeyId()}}), nil
}

// SetDefaultDid picks the DID the wallet binds new credentials to.
func (s *Service) SetDefaultDid(
	ctx context.Context, req *connect.Request[backendv1.SetDefaultDidRequest],
) (*connect.Response[backendv1.SetDefaultDidResponse], error) {
	session, err := s.walletSession(ctx, req.Msg.GetWalletId())
	if err != nil {
		return nil, err
	}
	did := strings.TrimSpace(req.Msg.GetDid())
	if did == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the request needs a did"))
	}
	if err := s.client.SetDefaultDID(ctx, session, did); err != nil {
		return nil, failed("set the default DID", err)
	}
	return connect.NewResponse(&backendv1.SetDefaultDidResponse{}), nil
}

// RejectOffer declines a credential offer in the wallet.
func (s *Service) RejectOffer(
	ctx context.Context, req *connect.Request[backendv1.RejectOfferRequest],
) (*connect.Response[backendv1.RejectOfferResponse], error) {
	session, err := s.walletSession(ctx, req.Msg.GetWalletId())
	if err != nil {
		return nil, err
	}
	offer := strings.TrimSpace(req.Msg.GetOfferUri())
	if offer == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the request needs an offer_uri"))
	}
	if err := s.client.RejectOffer(ctx, session, offer, strings.TrimSpace(req.Msg.GetReason())); err != nil {
		return nil, failed("decline the offer", err)
	}
	return connect.NewResponse(&backendv1.RejectOfferResponse{}), nil
}

// ListEvents returns one page of the event log of a wallet, newest
// first. The page token is the cursor of walt.id.
func (s *Service) ListEvents(
	ctx context.Context, req *connect.Request[backendv1.ListEventsRequest],
) (*connect.Response[backendv1.ListEventsResponse], error) {
	session, err := s.walletSession(ctx, req.Msg.GetWalletId())
	if err != nil {
		return nil, err
	}
	size := int(req.Msg.GetPage().GetPageSize())
	if size <= 0 || size > s.pageSizeMax {
		size = s.pageSizeMax
	}
	events, next, err := s.client.ListEvents(ctx, session, size, req.Msg.GetPage().GetPageToken())
	if err != nil {
		return nil, failed("read the event log", err)
	}
	out := &backendv1.ListEventsResponse{Page: &commonv1.PageResult{NextPageToken: next}}
	for _, e := range events {
		out.Events = append(out.Events, &backendv1.WalletEvent{
			Id: e.ID.String(), At: timestamp(e.Time()), Event: e.Event, Action: e.Action,
			CredentialId: e.CredentialID, Counterpart: e.Counterpart(),
		})
	}
	return connect.NewResponse(out), nil
}
