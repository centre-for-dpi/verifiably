// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
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
// The adapter keeps one record per holder: the handle it gives
// wallet-auth, the id of the Mimoto wallet, the session cookie of the
// last login, and whether the holder opened the wallet in that session.
// The holder sets the PIN of the Mimoto wallet on first use in the VCA
// wallet and enters it in each session. The adapter never stores the
// PIN (P6-I7c), so the holder types the same PIN in Inji Web.

// holderMessage says what to use instead of the holder role.
const holderMessage = "this Inji deployment names no Mimoto URL, so it serves no wallet; " +
	"use the wallet portal, an external OID4VCI wallet, or the document channel"

// mimotoWalletName is the name of the wallet the adapter makes.
const mimotoWalletName = "VCA wallet"

// lockedMessage asks the holder for the PIN.
const lockedMessage = "the wallet is locked; enter the PIN of your wallet"

// mimotoHolder is the stored state of one holder. It holds no PIN.
type mimotoHolder struct {
	// Handle is the wallet id that wallet-auth keeps.
	Handle string `json:"handle,omitempty"`
	// WalletID is the id of the Mimoto wallet, or empty before the
	// holder sets a PIN.
	WalletID string `json:"wallet_id,omitempty"`
	// Cookie carries the session of the last login and its CSRF token.
	Cookie string `json:"cookie,omitempty"`
	// Unlocked reports that the holder opened the wallet in the session
	// of Cookie.
	Unlocked bool `json:"unlocked,omitempty"`
}

// subjectKey returns the store key of a holder. The pairwise subject is
// a hash already; the key hashes it once more, so a key holds no slash.
func subjectKey(subject string) string {
	sum := sha256.Sum256([]byte(subject))
	return "mimoto/subject/" + hex.EncodeToString(sum[:])
}

// walletKey returns the store key of the record of a wallet handle.
func walletKey(handle string) string {
	sum := sha256.Sum256([]byte(handle))
	return "mimoto/wallet/" + hex.EncodeToString(sum[:])
}

// handleOf returns the wallet id of a new holder: stable per subject,
// and no Mimoto id, because the holder may have no wallet yet.
func handleOf(subject string) string {
	sum := sha256.Sum256([]byte("vca-mimoto-handle|" + subject))
	return "vca-" + hex.EncodeToString(sum[:16])
}

// Register logs in to Mimoto with the ID token of the holder login and
// finds the wallet of the holder. It makes no wallet and unlocks none:
// the holder sets or enters the PIN through UnlockWallet. A record of
// an earlier release keeps its wallet id and loses its PIN.
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
	wallets, cookie, err := s.mimoto.Wallets(ctx, cookie)
	if err != nil {
		return nil, holderFailed("list the Mimoto wallets", err)
	}
	h, err := s.loadHolder(ctx, subjectKey(subject))
	switch {
	case errors.Is(err, store.ErrNotFound):
		h = mimotoHolder{Handle: handleOf(subject)}
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, err)
	case h.Handle == "":
		// An earlier release gave the Mimoto wallet id to wallet-auth.
		h.Handle = h.WalletID
	}
	h.WalletID = pickWallet(wallets, h.WalletID).ID
	h.Cookie, h.Unlocked = cookie, false
	if err := s.saveHolder(ctx, subject, h); err != nil {
		return nil, err
	}
	return connect.NewResponse(&backendv1.RegisterResponse{WalletId: h.Handle}), nil
}

// pickWallet returns the known wallet when the list holds it, else the
// first wallet, else none.
func pickWallet(list []inji.Wallet, known string) inji.Wallet {
	for _, w := range list {
		if w.ID == known {
			return w
		}
	}
	if len(list) > 0 {
		return list[0]
	}
	return inji.Wallet{}
}

// GetWalletLock reports whether the holder must set or enter the PIN.
// It reads the wallets again, so a wallet the holder made in Inji Web
// shows at once.
func (s *Service) GetWalletLock(
	ctx context.Context, req *connect.Request[backendv1.GetWalletLockRequest],
) (*connect.Response[backendv1.GetWalletLockResponse], error) {
	h, err := s.holderRecord(ctx, req.Msg.GetWalletId())
	if err != nil {
		return nil, err
	}
	wallets, cookie, err := s.mimoto.Wallets(ctx, h.Cookie)
	if err != nil {
		return nil, holderFailed("list the Mimoto wallets", err)
	}
	wallet := pickWallet(wallets, h.WalletID)
	state := backendv1.WalletLock_WALLET_LOCK_NEEDS_PIN
	switch {
	case wallet.ID == "":
		state = backendv1.WalletLock_WALLET_LOCK_NEEDS_NEW_PIN
	case wallet.Locked():
		state = backendv1.WalletLock_WALLET_LOCK_LOCKED_OUT
	case h.Unlocked && wallet.ID == h.WalletID:
		state = backendv1.WalletLock_WALLET_LOCK_OPEN
	}
	if wallet.ID != h.WalletID || cookie != h.Cookie {
		h.Unlocked = h.Unlocked && wallet.ID == h.WalletID
		h.WalletID, h.Cookie = wallet.ID, cookie
		if err := s.saveHandle(ctx, h); err != nil {
			return nil, err
		}
	}
	return connect.NewResponse(&backendv1.GetWalletLockResponse{State: state}), nil
}

// UnlockWallet opens the wallet with the PIN the holder typed. A holder
// with no wallet sets the PIN here: the adapter makes the wallet with it
// first. The PIN goes to Mimoto and nowhere else.
func (s *Service) UnlockWallet(
	ctx context.Context, req *connect.Request[backendv1.UnlockWalletRequest],
) (*connect.Response[backendv1.UnlockWalletResponse], error) {
	h, err := s.holderRecord(ctx, req.Msg.GetWalletId())
	if err != nil {
		return nil, err
	}
	pin := req.Msg.GetPin()
	if !pinRule.MatchString(pin) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the PIN has six digits"))
	}
	if h.WalletID == "" {
		wallets, cookie, lerr := s.mimoto.Wallets(ctx, h.Cookie)
		if lerr != nil {
			return nil, holderFailed("list the Mimoto wallets", lerr)
		}
		h.Cookie, h.WalletID = cookie, pickWallet(wallets, "").ID
	}
	if h.WalletID == "" {
		if h.WalletID, err = s.mimoto.CreateWallet(ctx, h.Cookie, mimotoWalletName, pin); err != nil {
			return nil, holderFailed("make the Mimoto wallet", err)
		}
	}
	if err := s.mimoto.Unlock(ctx, h.Cookie, h.WalletID, pin); err != nil {
		return nil, pinFailed(err)
	}
	h.Unlocked = true
	if err := s.saveHandle(ctx, h); err != nil {
		return nil, err
	}
	return connect.NewResponse(&backendv1.UnlockWalletResponse{}), nil
}

// pinRule is the PIN rule of Mimoto 0.21.0
// (mosip.inji.user.wallet.pin.validation.regex).
var pinRule = regexp.MustCompile(`^\d{6}$`)

// pinFailed maps a refused unlock onto a Connect error that the wallet
// page shows.
func pinFailed(err error) *connect.Error {
	switch {
	case errors.Is(err, inji.ErrMimotoLastAttempt):
		return connect.NewError(connect.CodeInvalidArgument,
			errors.New("the PIN does not match; one more wrong PIN locks the wallet"))
	case errors.Is(err, inji.ErrMimotoPIN):
		return connect.NewError(connect.CodeInvalidArgument, errors.New("the PIN does not match"))
	case errors.Is(err, inji.ErrMimotoLockedOut):
		return connect.NewError(connect.CodeFailedPrecondition,
			errors.New("too many wrong PINs locked the wallet; wait an hour, or reset the PIN in Inji Web"))
	}
	return holderFailed("unlock the Mimoto wallet", err)
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
		return nil, s.walletFailed(ctx, h, "list the Mimoto credentials", err)
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
		return nil, s.walletFailed(ctx, h, "present through Mimoto", err)
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
		return nil, s.walletFailed(ctx, h, "delete the Mimoto credential", err)
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
		return nil, s.walletFailed(ctx, h, "read the Mimoto PDF", err)
	}
	return connect.NewResponse(&backendv1.GetCredentialDocumentResponse{Content: content, MediaType: media}), nil
}

// holderRecord returns the stored record of one wallet handle.
func (s *Service) holderRecord(ctx context.Context, handle string) (mimotoHolder, error) {
	if s.mimoto == nil {
		return mimotoHolder{}, unimplemented(holderMessage)
	}
	if strings.TrimSpace(handle) == "" {
		return mimotoHolder{}, connect.NewError(connect.CodeInvalidArgument, errors.New("the request needs a wallet_id"))
	}
	h, err := s.loadHolder(ctx, walletKey(handle))
	if errors.Is(err, store.ErrNotFound) {
		return mimotoHolder{}, connect.NewError(connect.CodeNotFound, errors.New("this adapter opened no such wallet; sign in again"))
	}
	if err != nil {
		return mimotoHolder{}, connect.NewError(connect.CodeInternal, err)
	}
	if h.Handle == "" {
		h.Handle = handle
	}
	return h, nil
}

// holderSession returns the record of a wallet that the holder opened
// with the PIN in this session.
func (s *Service) holderSession(ctx context.Context, handle string) (mimotoHolder, error) {
	h, err := s.holderRecord(ctx, handle)
	if err != nil {
		return mimotoHolder{}, err
	}
	if !h.Unlocked || h.WalletID == "" {
		return mimotoHolder{}, connect.NewError(connect.CodeFailedPrecondition, errors.New(lockedMessage))
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

// saveHolder writes the record of a holder under its subject and its
// handle. The record holds no PIN, so a record of an earlier release
// loses its PIN here.
func (s *Service) saveHolder(ctx context.Context, subject string, h mimotoHolder) error {
	if err := s.putHolder(ctx, subjectKey(subject), h); err != nil {
		return err
	}
	return s.saveHandle(ctx, h)
}

// saveHandle writes the record of a holder under its handle.
func (s *Service) saveHandle(ctx context.Context, h mimotoHolder) error {
	return s.putHolder(ctx, walletKey(h.Handle), h)
}

// putHolder writes one holder record.
func (s *Service) putHolder(ctx context.Context, key string, h mimotoHolder) error {
	raw, err := json.Marshal(h)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	if err := s.store.Put(ctx, key, raw); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	return nil
}

// walletFailed maps the error of a call with the wallet key. A session
// that lost the key marks the record locked, so the wallet asks for the
// PIN again.
func (s *Service) walletFailed(ctx context.Context, h mimotoHolder, action string, err error) *connect.Error {
	if errors.Is(err, inji.ErrMimotoWalletLocked) {
		h.Unlocked = false
		if serr := s.saveHandle(ctx, h); serr != nil {
			return connect.NewError(connect.CodeInternal, serr)
		}
	}
	return holderFailed(action, err)
}

// holderFailed maps a Mimoto error onto a Connect error. A refused token
// or an ended session asks the holder to sign in again, and a session
// without the wallet key asks for the PIN.
func holderFailed(action string, err error) *connect.Error {
	if errors.Is(err, inji.ErrMimotoWalletLocked) {
		return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("%s: %s: %w", action, lockedMessage, err))
	}
	if errors.Is(err, inji.ErrMimotoSession) {
		return connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("%s: the Mimoto session ended or Mimoto refused the login, sign in again: %w", action, err))
	}
	return failed(action, err)
}
