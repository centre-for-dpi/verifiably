// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

// The PIN of a stack wallet (P6-I7c). A stack wallet that lists
// FEATURE_WALLET_PIN keeps a PIN that the holder sets on first use and
// enters in each session. The service passes the PIN to the holder
// backend and keeps it nowhere.

// ErrPinMismatch reports two PINs of the first use that differ.
var ErrPinMismatch = connect.NewError(connect.CodeInvalidArgument, errors.New("the two PINs differ"))

// WalletLock returns the PIN state of the stack wallet of the citizen.
func (s *Service) WalletLock(ctx context.Context) (backendv1.WalletLock, error) {
	citizen, err := s.holderOf(ctx)
	if err != nil {
		return backendv1.WalletLock_WALLET_LOCK_UNSPECIFIED, err
	}
	resp, err := s.opts.Holder.GetWalletLock(ctx, connect.NewRequest(&backendv1.GetWalletLockRequest{WalletId: citizen.WalletID}))
	if err != nil {
		return backendv1.WalletLock_WALLET_LOCK_UNSPECIFIED, connect.NewError(connect.CodeUnavailable,
			errors.New("the wallet is not available, try again later"))
	}
	return resp.Msg.GetState(), nil
}

// Unlock opens the stack wallet with the PIN the citizen typed. On the
// first use, confirm repeats the PIN, and the two must match. A refused
// PIN keeps the sentence of the backend, which the page shows.
func (s *Service) Unlock(ctx context.Context, pin, confirm string, first bool) error {
	citizen, err := s.holderOf(ctx)
	if err != nil {
		return err
	}
	if first && pin != confirm {
		return ErrPinMismatch
	}
	_, err = s.opts.Holder.UnlockWallet(ctx, connect.NewRequest(&backendv1.UnlockWalletRequest{WalletId: citizen.WalletID, Pin: pin}))
	switch connect.CodeOf(err) {
	case connect.CodeInvalidArgument, connect.CodeFailedPrecondition, connect.CodeUnauthenticated:
		return err
	}
	if err != nil {
		return connect.NewError(connect.CodeUnavailable, errors.New("the wallet is not available, try again later"))
	}
	return nil
}
