// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/service"
)

// pinHolder answers the PIN calls of a stack wallet.
type pinHolder struct {
	fakeHolder
	lockErr   error
	unlockErr error
	seen      []*backendv1.UnlockWalletRequest
}

func (f *pinHolder) GetWalletLock(_ context.Context, req *connect.Request[backendv1.GetWalletLockRequest],
) (*connect.Response[backendv1.GetWalletLockResponse], error) {
	if f.lockErr != nil {
		return nil, f.lockErr
	}
	if req.Msg.GetWalletId() != citizen().WalletID {
		return nil, errors.New("another wallet")
	}
	return connect.NewResponse(&backendv1.GetWalletLockResponse{State: backendv1.WalletLock_WALLET_LOCK_NEEDS_PIN}), nil
}

func (f *pinHolder) UnlockWallet(_ context.Context, req *connect.Request[backendv1.UnlockWalletRequest],
) (*connect.Response[backendv1.UnlockWalletResponse], error) {
	f.seen = append(f.seen, req.Msg)
	if f.unlockErr != nil {
		return nil, f.unlockErr
	}
	return connect.NewResponse(&backendv1.UnlockWalletResponse{}), nil
}

// TestPinGoesToTheStackWalletOnly passes the PIN of the citizen to the
// wallet of the session and keeps the sentence of a refusal. Two PINs
// of the first use that differ never reach the stack. A stack that does
// not answer gives unavailable, and a browser wallet has no PIN.
func TestPinGoesToTheStackWalletOnly(t *testing.T) {
	holder := &pinHolder{}
	svc := build(t, func(o *service.Options) { o.Holder = holder })
	if state, err := svc.WalletLock(ctx()); err != nil || state != backendv1.WalletLock_WALLET_LOCK_NEEDS_PIN {
		t.Fatalf("lock = %v %v", state, err)
	}
	if err := svc.Unlock(ctx(), "482915", "482916", true); !errors.Is(err, service.ErrPinMismatch) || len(holder.seen) != 0 {
		t.Fatalf("mismatch = %v, calls %d", err, len(holder.seen))
	}
	if err := svc.Unlock(ctx(), "482915", "482915", true); err != nil || holder.seen[0].GetPin() != "482915" ||
		holder.seen[0].GetWalletId() != citizen().WalletID {
		t.Fatalf("unlock = %v %v", err, holder.seen)
	}
	holder.unlockErr = connect.NewError(connect.CodeInvalidArgument, errors.New("the PIN does not match"))
	if err := svc.Unlock(ctx(), "000000", "", false); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("wrong PIN = %v", err)
	}
	holder.unlockErr = errors.New("down")
	if err := svc.Unlock(ctx(), "000000", "", false); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("down = %v", err)
	}
	holder.lockErr = errors.New("down")
	if _, err := svc.WalletLock(ctx()); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("lock down = %v", err)
	}
	browser := build(t, func(o *service.Options) { o.Holder = nil })
	if _, err := browser.WalletLock(ctx()); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("browser lock = %v", err)
	}
	if err := browser.Unlock(ctx(), "123456", "", false); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("browser unlock = %v", err)
	}
}
