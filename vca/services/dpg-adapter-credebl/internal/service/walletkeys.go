// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

// walletKeysMessage says why the wallet key, default DID, decline, and
// event RPCs answer Unimplemented. The adapter lists none of
// FEATURE_WALLET_KEYS, FEATURE_WALLET_DEFAULT_DID,
// FEATURE_WALLET_REJECT_OFFER, and FEATURE_WALLET_EVENTS, so no holder
// page offers them for this stack. The agent makes the key of a DID
// itself, binds no credential to a default DID, and has no decline
// call.
const walletKeysMessage = "this adapter does not manage the keys, the default DID, the offers, or the event log of a wallet"

// ListKeys answers Unimplemented. See walletKeysMessage.
func (s *Service) ListKeys(context.Context, *connect.Request[backendv1.ListKeysRequest]) (*connect.Response[backendv1.ListKeysResponse], error) {
	return nil, unimplemented(walletKeysMessage)
}

// CreateKey answers Unimplemented. See walletKeysMessage.
func (s *Service) CreateKey(context.Context, *connect.Request[backendv1.CreateKeyRequest]) (*connect.Response[backendv1.CreateKeyResponse], error) {
	return nil, unimplemented(walletKeysMessage)
}

// SetDefaultDid answers Unimplemented. See walletKeysMessage.
func (s *Service) SetDefaultDid(context.Context, *connect.Request[backendv1.SetDefaultDidRequest]) (*connect.Response[backendv1.SetDefaultDidResponse], error) {
	return nil, unimplemented(walletKeysMessage)
}

// RejectOffer answers Unimplemented. See walletKeysMessage.
func (s *Service) RejectOffer(context.Context, *connect.Request[backendv1.RejectOfferRequest]) (*connect.Response[backendv1.RejectOfferResponse], error) {
	return nil, unimplemented(walletKeysMessage)
}

// ListEvents answers Unimplemented. See walletKeysMessage.
func (s *Service) ListEvents(context.Context, *connect.Request[backendv1.ListEventsRequest]) (*connect.Response[backendv1.ListEventsResponse], error) {
	return nil, unimplemented(walletKeysMessage)
}

// GetCredentialDocument answers Unimplemented. The adapter lists no
// FEATURE_WALLET_DOCUMENT, so no holder page offers a document.
func (s *Service) GetCredentialDocument(context.Context, *connect.Request[backendv1.GetCredentialDocumentRequest]) (*connect.Response[backendv1.GetCredentialDocumentResponse], error) {
	return nil, unimplemented("this adapter renders no document of a held credential")
}

// GetWalletLock answers Unimplemented. The adapter drives no wallet
// with a PIN, so it lists no FEATURE_WALLET_PIN.
func (s *Service) GetWalletLock(context.Context, *connect.Request[backendv1.GetWalletLockRequest]) (*connect.Response[backendv1.GetWalletLockResponse], error) {
	return nil, unimplemented("this adapter drives no wallet with a PIN")
}

// UnlockWallet answers Unimplemented for the same reason.
func (s *Service) UnlockWallet(context.Context, *connect.Request[backendv1.UnlockWalletRequest]) (*connect.Response[backendv1.UnlockWalletResponse], error) {
	return nil, unimplemented("this adapter drives no wallet with a PIN")
}
