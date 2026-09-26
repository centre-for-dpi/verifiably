// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

// GetWalletLock answers the lock state of the fake stack wallet.
func (f *fakeHolder) GetWalletLock(context.Context, *connect.Request[backendv1.GetWalletLockRequest],
) (*connect.Response[backendv1.GetWalletLockResponse], error) {
	if f.lock == backendv1.WalletLock_WALLET_LOCK_UNSPECIFIED {
		return nil, errors.New("down")
	}
	return connect.NewResponse(&backendv1.GetWalletLockResponse{State: f.lock}), nil
}

// UnlockWallet sets the PIN of a wallet with none, and opens a wallet
// whose PIN matches, as the Inji adapter does.
func (f *fakeHolder) UnlockWallet(_ context.Context, req *connect.Request[backendv1.UnlockWalletRequest],
) (*connect.Response[backendv1.UnlockWalletResponse], error) {
	f.typed = append(f.typed, req.Msg.GetPin())
	switch {
	case f.lock == backendv1.WalletLock_WALLET_LOCK_NEEDS_NEW_PIN:
		f.pin = req.Msg.GetPin()
	case req.Msg.GetPin() != f.pin:
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the PIN does not match"))
	}
	f.lock = backendv1.WalletLock_WALLET_LOCK_OPEN
	return connect.NewResponse(&backendv1.UnlockWalletResponse{}), nil
}

// pinStack is the Inji holder pair whose adapter lists the PIN of the
// stack wallet, the claim in Inji Web, and the PDF.
func pinStack(t *testing.T, lock backendv1.WalletLock) *harness {
	t.Helper()
	h := setupStack(t, backendv1.Feature_FEATURE_WALLET_CLAIM_IN_STACK, backendv1.Feature_FEATURE_WALLET_DOCUMENT,
		backendv1.Feature_FEATURE_WALLET_PIN)
	h.holder.lock = lock
	return h
}

// TestHolderSetsThePinOnFirstUse is P6-I7c in the wallet: the home page
// of a holder with no stack wallet yet asks for a new PIN instead of the
// stack list. The PIN step takes the PIN twice, refuses two that
// differ, and passes the PIN to the stack wallet. The home page then
// lists the stack credentials, and the Inji Web card names the PIN.
func TestHolderSetsThePinOnFirstUse(t *testing.T) {
	h := pinStack(t, backendv1.WalletLock_WALLET_LOCK_NEEDS_NEW_PIN)
	home := h.get(t, "/wallet/").Body.String()
	for _, want := range []string{`id="wallet-pin"`, "Set the PIN of your Inji wallet", `href="/wallet/pin"`, `id="wallet-paste-save"`} {
		if !strings.Contains(home, want) {
			t.Fatalf("the home page misses %s\n%s", want, home)
		}
	}
	if strings.Contains(home, "Farmer Credential") {
		t.Fatal("a locked stack wallet listed its credentials")
	}
	step := h.get(t, "/wallet/pin").Body.String()
	for _, want := range []string{
		"Set your wallet PIN", `id="pin"`, `id="pin_confirm"`, `inputmode="numeric"`, `type="password"`,
		`autocomplete="new-password"`, "You choose this PIN.", "This service does not keep it.",
	} {
		if !strings.Contains(step, want) {
			t.Fatalf("the PIN step misses %s\n%s", want, step)
		}
	}
	mismatch := h.post(t, "/wallet/pin", url.Values{"pin": {"482915"}, "pin_confirm": {"482916"}})
	if mismatch.Code != http.StatusOK || !strings.Contains(mismatch.Body.String(), `id="pin_confirm-error"`) ||
		!strings.Contains(mismatch.Body.String(), "The two PINs differ.") || len(h.holder.typed) != 0 {
		t.Fatalf("two PINs that differ: %d %s", mismatch.Code, mismatch.Body.String())
	}
	done := h.post(t, "/wallet/pin", url.Values{"pin": {"482915"}, "pin_confirm": {"482915"}})
	if done.Code != http.StatusSeeOther || done.Header().Get("Location") != "/wallet/" || h.holder.pin != "482915" {
		t.Fatalf("the PIN step: %d %v pin %q", done.Code, done.Header(), h.holder.pin)
	}
	open := h.get(t, "/wallet/").Body.String()
	if !strings.Contains(open, "Farmer Credential") || strings.Contains(open, `id="wallet-pin"`) ||
		!strings.Contains(open, "It asks for the PIN you set here.") {
		t.Fatalf("the open wallet\n%s", open)
	}
	if rec := h.get(t, "/wallet/pin"); rec.Code != http.StatusSeeOther {
		t.Fatalf("the PIN step of an open wallet: %d", rec.Code)
	}
}

// TestHolderEntersThePin asks for the PIN at a new session, shows a
// wrong PIN beside the field, and opens the wallet with the right one.
func TestHolderEntersThePin(t *testing.T) {
	h := pinStack(t, backendv1.WalletLock_WALLET_LOCK_NEEDS_PIN)
	h.holder.pin = "135790"
	home := h.get(t, "/wallet/").Body.String()
	if !strings.Contains(home, "Enter the PIN of your Inji wallet") {
		t.Fatalf("the home page\n%s", home)
	}
	step := h.get(t, "/wallet/pin").Body.String()
	if !strings.Contains(step, "Enter your wallet PIN") || strings.Contains(step, `id="pin_confirm"`) ||
		!strings.Contains(step, `autocomplete="current-password"`) {
		t.Fatalf("the PIN step\n%s", step)
	}
	wrong := h.post(t, "/wallet/pin", url.Values{"pin": {"000000"}})
	if wrong.Code != http.StatusOK || !strings.Contains(wrong.Body.String(), "The PIN does not match.") ||
		!strings.Contains(wrong.Body.String(), `aria-invalid="true"`) {
		t.Fatalf("a wrong PIN: %d %s", wrong.Code, wrong.Body.String())
	}
	if rec := h.post(t, "/wallet/pin", url.Values{"pin": {"135790"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("the right PIN: %d", rec.Code)
	}
}

// TestLockedOutWallet names the lock and the way out, with no form.
func TestLockedOutWallet(t *testing.T) {
	h := pinStack(t, backendv1.WalletLock_WALLET_LOCK_LOCKED_OUT)
	for _, path := range []string{"/wallet/", "/wallet/pin"} {
		body := h.get(t, path).Body.String()
		if !strings.Contains(body, "Too many wrong PINs locked your Inji wallet.") || strings.Contains(body, `id="pin"`) {
			t.Fatalf("%s\n%s", path, body)
		}
	}
}

// TestPinStepOnlyWithFeature hides the PIN step from a stack that keeps
// no PIN, and the home page asks for none.
func TestPinStepOnlyWithFeature(t *testing.T) {
	h := setupStack(t, backendv1.Feature_FEATURE_WALLET_CLAIM_IN_STACK)
	if rec := h.get(t, "/wallet/pin"); rec.Code != http.StatusNotFound {
		t.Fatalf("GET without the feature: %d", rec.Code)
	}
	if rec := h.post(t, "/wallet/pin", url.Values{"pin": {"123456"}}); rec.Code != http.StatusNotFound {
		t.Fatalf("POST without the feature: %d", rec.Code)
	}
	if body := h.get(t, "/wallet/").Body.String(); strings.Contains(body, `id="wallet-pin"`) {
		t.Fatal("the home page asks for a PIN without the feature")
	}
}

// TestPinStateUnknown keeps the home page when the stack does not say
// whether the wallet is locked: the home page lists what it can.
func TestPinStateUnknown(t *testing.T) {
	h := pinStack(t, backendv1.WalletLock_WALLET_LOCK_UNSPECIFIED)
	body := h.get(t, "/wallet/").Body.String()
	if strings.Contains(body, `id="wallet-pin"`) || !strings.Contains(body, "Farmer Credential") {
		t.Fatalf("home\n%s", body)
	}
	if rec := h.get(t, "/wallet/pin"); !strings.Contains(rec.Body.String(), "The wallet is not available.") {
		t.Fatalf("the PIN step: %d %s", rec.Code, rec.Body.String())
	}
}
