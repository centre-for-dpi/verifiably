// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/service"
)

// TestWalletKeyRpcsAreUnimplemented keeps the keys page and the decline
// of the stack wallet off until the adapter lists their features.
func TestWalletKeyRpcsAreUnimplemented(t *testing.T) {
	svc, ctx := new(service.Service), context.Background()
	calls := map[string]func() error{
		"ListKeys": func() error {
			_, err := svc.ListKeys(ctx, connect.NewRequest(&backendv1.ListKeysRequest{}))
			return err
		},
		"CreateKey": func() error {
			_, err := svc.CreateKey(ctx, connect.NewRequest(&backendv1.CreateKeyRequest{}))
			return err
		},
		"ListDids": func() error {
			_, err := svc.ListDids(ctx, connect.NewRequest(&backendv1.ListDidsRequest{}))
			return err
		},
		"CreateDid": func() error {
			_, err := svc.CreateDid(ctx, connect.NewRequest(&backendv1.CreateDidRequest{}))
			return err
		},
		"SetDefaultDid": func() error {
			_, err := svc.SetDefaultDid(ctx, connect.NewRequest(&backendv1.SetDefaultDidRequest{}))
			return err
		},
		"RejectOffer": func() error {
			_, err := svc.RejectOffer(ctx, connect.NewRequest(&backendv1.RejectOfferRequest{}))
			return err
		},
		"ListEvents": func() error {
			_, err := svc.ListEvents(ctx, connect.NewRequest(&backendv1.ListEventsRequest{}))
			return err
		},
		"GetCredentialDocument": func() error {
			_, err := svc.GetCredentialDocument(ctx, connect.NewRequest(&backendv1.GetCredentialDocumentRequest{}))
			return err
		},
		"GetWalletLock": func() error {
			_, err := svc.GetWalletLock(ctx, connect.NewRequest(&backendv1.GetWalletLockRequest{}))
			return err
		},
		"UnlockWallet": func() error {
			_, err := svc.UnlockWallet(ctx, connect.NewRequest(&backendv1.UnlockWalletRequest{}))
			return err
		},
	}
	for name, call := range calls {
		if connect.CodeOf(call()) != connect.CodeUnimplemented {
			t.Errorf("%s: want unimplemented", name)
		}
	}
}
