// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/inji"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// The holder role drives Mimoto, the backend of Inji Web, with the
// session of its token login (P6-I7a decision, docs/dpg-adapter-inji.md).
// The adapter keeps one record per holder: the Mimoto wallet id and its
// PIN, and the session cookie of the last login. The store keeps them in
// a file of mode 0600 (ADR-020 decision 4 keeps the holder key in the
// DPG wallet).

// holderMessage says what to use instead of the holder role.
const holderMessage = "this Inji deployment names no Mimoto URL, so it serves no wallet; " +
	"use the wallet portal, an external OID4VCI wallet, or the document channel"

// mimotoWalletName is the name of the wallet the adapter makes.
const mimotoWalletName = "VCA wallet"

// mimotoHolder is the stored state of one holder.
type mimotoHolder struct {
	// WalletID is the id of the Mimoto wallet.
	WalletID string `json:"wallet_id"`
	// PIN unlocks the wallet key in each session.
	PIN string `json:"pin"`
	// Cookie carries the session of the last login.
	Cookie string `json:"cookie,omitempty"`
}

// subjectKey returns the store key of a holder. The pairwise subject is
// a hash already; the key hashes it once more, so a key holds no slash.
func subjectKey(subject string) string {
	sum := sha256.Sum256([]byte(subject))
	return "mimoto/subject/" + hex.EncodeToString(sum[:])
}

// walletKey returns the store key of the session of a wallet.
func walletKey(walletID string) string {
	sum := sha256.Sum256([]byte(walletID))
	return "mimoto/wallet/" + hex.EncodeToString(sum[:])
}

// Register logs in to Mimoto with the ID token of the holder login and
// opens the wallet of the holder. The first login makes the wallet with
// a random PIN of six digits. Every login unlocks it for the session.
func (s *Service) Register(
	ctx context.Context, req *connect.Request[backendv1.RegisterRequest],
) (*connect.Response[backendv1.RegisterResponse], error) {
	if s.mimoto == nil {
		return nil, unimplemented(holderMessage)
	}
	subject := strings.TrimSpace(req.Msg.GetPairwiseSubject())
	if subject == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the request needs a pairwise_subject"))
	}
	token := strings.TrimSpace(req.Msg.GetIdToken())
	if token == "" {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("the request carries no ID token, and Mimoto opens a wallet with the ID token of the login"))
	}
	cookie, err := s.mimoto.TokenLogin(ctx, s.mimotoProvider, token)
	if errors.Is(err, inji.ErrMimotoSession) {
		return nil, connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("the Mimoto token login refused the ID token; the operator configures its provider: %w", err))
	}
	if err != nil {
		return nil, failed("log in to Mimoto", err)
	}
	h, err := s.loadHolder(ctx, subjectKey(subject))
	switch {
	case errors.Is(err, store.ErrNotFound):
		h.PIN = randomPIN()
		if h.WalletID, err = s.mimoto.CreateWallet(ctx, cookie, mimotoWalletName, h.PIN); err != nil {
			return nil, holderFailed("make the Mimoto wallet", err)
		}
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := s.mimoto.Unlock(ctx, cookie, h.WalletID, h.PIN); err != nil {
		return nil, holderFailed("unlock the Mimoto wallet", err)
	}
	h.Cookie = cookie
	if err := s.saveHolder(ctx, subjectKey(subject), h); err != nil {
		return nil, err
	}
	if err := s.saveHolder(ctx, walletKey(h.WalletID), h); err != nil {
		return nil, err
	}
	return connect.NewResponse(&backendv1.RegisterResponse{WalletId: h.WalletID}), nil
}

// ListCredentials lists the credentials of the Mimoto wallet by name.
// Mimoto returns no credential bytes, so a credential carries none.
func (s *Service) ListCredentials(
	ctx context.Context, req *connect.Request[backendv1.ListCredentialsRequest],
) (*connect.Response[backendv1.ListCredentialsResponse], error) {
	h, err := s.holderSession(ctx, req.Msg.GetWalletId())
	if err != nil {
		return nil, err
	}
	held, err := s.mimoto.Credentials(ctx, h.Cookie, h.WalletID)
	if err != nil {
		return nil, holderFailed("list the Mimoto credentials", err)
	}
	start := 0
	if n, perr := strconv.Atoi(req.Msg.GetPage().GetPageToken()); perr == nil && n > 0 {
		start = min(n, len(held))
	}
	size := int(req.Msg.GetPage().GetPageSize())
	if size <= 0 || size > s.pageSizeMax {
		size = s.pageSizeMax
	}
	end := min(start+size, len(held))
	page := &commonv1.PageResult{TotalSize: int64(len(held))}
	if end < len(held) {
		page.NextPageToken = strconv.Itoa(end)
	}
	out := make([]*backendv1.WalletCredential, 0, end-start)
	for _, c := range held[start:end] {
		out = append(out, &backendv1.WalletCredential{Id: c.ID, Type: c.Type, Issuer: c.Issuer})
	}
	return connect.NewResponse(&backendv1.ListCredentialsResponse{Credentials: out, Page: page}), nil
}

// AcceptOffer is not available. Mimoto downloads a credential only
// through an authorization code flow of its own client in the browser,
// so the holder claims in Inji Web.
func (s *Service) AcceptOffer(
	context.Context, *connect.Request[backendv1.AcceptOfferRequest],
) (*connect.Response[backendv1.AcceptOfferResponse], error) {
	if s.mimoto == nil {
		return nil, unimplemented(holderMessage)
	}
	where := "Inji Web"
	if s.injiWebURL != "" {
		where += " at " + s.injiWebURL
	}
	return nil, unimplemented("Mimoto downloads a credential in the browser; claim it in " + where +
		", and it shows in this wallet")
}

// Present answers an OID4VP request with credentials of the Mimoto
// wallet. Mimoto builds the presentation and posts it to the verifier.
func (s *Service) Present(
	ctx context.Context, req *connect.Request[backendv1.PresentRequest],
) (*connect.Response[backendv1.PresentResponse], error) {
	h, err := s.holderSession(ctx, req.Msg.GetWalletId())
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Msg.GetRequestUri()) == "" || len(req.Msg.GetCredentialIds()) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the request needs a request_uri and at least one credential id"))
	}
	sent, err := s.mimoto.Present(ctx, h.Cookie, h.WalletID,
		inji.AuthorizationRequestURL(req.Msg.GetRequestUri()), req.Msg.GetCredentialIds())
	if err != nil {
		return nil, holderFailed("present through Mimoto", err)
	}
	return connect.NewResponse(&backendv1.PresentResponse{
		Accepted: true, SharedClaims: req.Msg.GetDisclosedClaims(),
		VerifierState: sent.PresentationID, RedirectUri: sent.RedirectURI,
	}), nil
}

// DeleteCredential removes one credential from the Mimoto wallet.
func (s *Service) DeleteCredential(
	ctx context.Context, req *connect.Request[backendv1.DeleteCredentialRequest],
) (*connect.Response[backendv1.DeleteCredentialResponse], error) {
	h, err := s.holderSession(ctx, req.Msg.GetWalletId())
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Msg.GetCredentialId()) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the request needs a credential_id"))
	}
	if err := s.mimoto.Delete(ctx, h.Cookie, h.WalletID, req.Msg.GetCredentialId()); err != nil {
		return nil, holderFailed("delete the Mimoto credential", err)
	}
	return connect.NewResponse(&backendv1.DeleteCredentialResponse{}), nil
}

// GetCredentialDocument returns the PDF that Mimoto renders of one
// credential.
func (s *Service) GetCredentialDocument(
	ctx context.Context, req *connect.Request[backendv1.GetCredentialDocumentRequest],
) (*connect.Response[backendv1.GetCredentialDocumentResponse], error) {
	h, err := s.holderSession(ctx, req.Msg.GetWalletId())
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Msg.GetCredentialId()) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the request needs a credential_id"))
	}
	content, media, err := s.mimoto.Document(ctx, h.Cookie, h.WalletID, req.Msg.GetCredentialId())
	if err != nil {
		return nil, holderFailed("read the Mimoto PDF", err)
	}
	return connect.NewResponse(&backendv1.GetCredentialDocumentResponse{Content: content, MediaType: media}), nil
}

// holderSession returns the stored session of one wallet.
func (s *Service) holderSession(ctx context.Context, walletID string) (mimotoHolder, error) {
	if s.mimoto == nil {
		return mimotoHolder{}, unimplemented(holderMessage)
	}
	if strings.TrimSpace(walletID) == "" {
		return mimotoHolder{}, connect.NewError(connect.CodeInvalidArgument, errors.New("the request needs a wallet_id"))
	}
	h, err := s.loadHolder(ctx, walletKey(walletID))
	if errors.Is(err, store.ErrNotFound) {
		return mimotoHolder{}, connect.NewError(connect.CodeNotFound, errors.New("this adapter opened no such wallet; sign in again"))
	}
	if err != nil {
		return mimotoHolder{}, connect.NewError(connect.CodeInternal, err)
	}
	return h, nil
}

// loadHolder reads one stored holder record.
func (s *Service) loadHolder(ctx context.Context, key string) (mimotoHolder, error) {
	raw, err := s.store.Get(ctx, key)
	if err != nil {
		return mimotoHolder{}, err
	}
	var h mimotoHolder
	if err := json.Unmarshal(raw, &h); err != nil {
		return mimotoHolder{}, fmt.Errorf("service: the holder record does not parse: %w", err)
	}
	return h, nil
}

// saveHolder writes one holder record.
func (s *Service) saveHolder(ctx context.Context, key string, h mimotoHolder) error {
	raw, err := json.Marshal(h)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	if err := s.store.Put(ctx, key, raw); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	return nil
}

// holderFailed maps a Mimoto error onto a Connect error. A refused token
// or an ended session asks the holder to sign in again.
func holderFailed(action string, err error) *connect.Error {
	if errors.Is(err, inji.ErrMimotoSession) {
		return connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("%s: the Mimoto session ended or Mimoto refused the login, sign in again: %w", action, err))
	}
	return failed(action, err)
}

// randomPIN returns six random digits.
func randomPIN() string {
	// crypto/rand cannot fail on a platform that Go supports.
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%06d", n.Int64())
}
