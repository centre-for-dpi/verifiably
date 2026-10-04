// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/sdjwt"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/waltid"
	"github.com/centre-for-dpi/vc-adapters/services/internal/disclosure"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// walletDomain is the mail domain of the accounts the adapter creates.
// The domain is reserved, so no message ever leaves the deployment.
const walletDomain = "@wallet.invalid"

// AccountFor returns the wallet-api account of one pairwise subject.
// The values come from the subject alone, so a restart finds the same
// wallet and the citizen keeps the credentials they hold (ADR-020).
func AccountFor(pairwiseSubject string) waltid.Account {
	name := storeSafe(pairwiseSubject)
	secret := sha256.Sum256([]byte("vca-wallet-password|" + pairwiseSubject))
	return waltid.Account{
		Name:     "VCA holder " + name[:8],
		Email:    name + walletDomain,
		Password: hex.EncodeToString(secret[:]),
	}
}

// Register creates or opens the wallet of one citizen.
func (s *Service) Register(
	ctx context.Context, req *connect.Request[backendv1.RegisterRequest],
) (*connect.Response[backendv1.RegisterResponse], error) {
	if !s.client.HasWallet() {
		return nil, unimplemented("this adapter has no wallet URL, so it serves no holder role")
	}
	subject := strings.TrimSpace(req.Msg.GetPairwiseSubject())
	if subject == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the request needs a pairwise_subject"))
	}
	session, err := s.client.Login(ctx, AccountFor(subject))
	if err != nil {
		return nil, failed("open the wallet", err)
	}
	if err := s.saveSession(ctx, session); err != nil {
		return nil, err
	}
	return connect.NewResponse(&backendv1.RegisterResponse{WalletId: session.WalletID}), nil
}

// saveSession stores the wallet session so a later call can use it.
func (s *Service) saveSession(ctx context.Context, session waltid.WalletSession) error {
	raw, err := json.Marshal(session)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	if err := s.store.Put(ctx, walletKey(session.WalletID), raw); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	return nil
}

// session returns the stored session of one wallet.
func (s *Service) session(ctx context.Context, walletID string) (waltid.WalletSession, error) {
	if strings.TrimSpace(walletID) == "" {
		return waltid.WalletSession{}, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the request needs a wallet_id"))
	}
	raw, err := s.store.Get(ctx, walletKey(walletID))
	if errors.Is(err, store.ErrNotFound) {
		return waltid.WalletSession{}, connect.NewError(connect.CodeNotFound,
			fmt.Errorf("the wallet %q has no open session; call Register first", walletID))
	}
	if err != nil {
		return waltid.WalletSession{}, connect.NewError(connect.CodeInternal, err)
	}
	var session waltid.WalletSession
	if err := json.Unmarshal(raw, &session); err != nil {
		return waltid.WalletSession{}, connect.NewError(connect.CodeInternal, err)
	}
	return session, nil
}

// ListCredentials returns one page of the credentials in a wallet.
func (s *Service) ListCredentials(
	ctx context.Context, req *connect.Request[backendv1.ListCredentialsRequest],
) (*connect.Response[backendv1.ListCredentialsResponse], error) {
	if !s.client.HasWallet() {
		return nil, unimplemented("this adapter has no wallet URL, so it serves no holder role")
	}
	session, err := s.session(ctx, req.Msg.GetWalletId())
	if err != nil {
		return nil, err
	}
	held, lerr := s.client.ListCredentials(ctx, session)
	if lerr != nil {
		return nil, failed("list the credentials", lerr)
	}
	items := make([]*backendv1.WalletCredential, 0, len(held))
	for _, h := range held {
		items = append(items, walletCredential(h))
	}
	page, next := s.page(items, req.Msg.GetPage())
	return connect.NewResponse(&backendv1.ListCredentialsResponse{
		Credentials: page,
		Page: &commonv1.PageResult{
			NextPageToken: next,
			TotalSize:     int64(len(items)),
		},
	}), nil
}

// page cuts one page out of the items and returns the next token.
func (s *Service) page(items []*backendv1.WalletCredential, p *commonv1.Pagination) ([]*backendv1.WalletCredential, string) {
	size := int(p.GetPageSize())
	if size <= 0 || size > s.pageSizeMax {
		size = s.pageSizeMax
	}
	start := 0
	if token := p.GetPageToken(); token != "" {
		if n, err := parseToken(token); err == nil {
			start = n
		}
	}
	if start >= len(items) {
		return nil, ""
	}
	end := start + size
	if end >= len(items) {
		return items[start:], ""
	}
	return items[start:end], formatToken(end)
}

// parseToken reads a page token.
func parseToken(token string) (int, error) {
	var n int
	_, err := fmt.Sscanf(token, "%d", &n)
	if err != nil || n < 0 {
		return 0, errors.New("service: bad page token")
	}
	return n, nil
}

// formatToken writes a page token.
func formatToken(n int) string { return fmt.Sprintf("%d", n) }

// walletCredential maps one held credential onto the contract message.
func walletCredential(h waltid.HeldCredential) *backendv1.WalletCredential {
	out := &backendv1.WalletCredential{
		Id: h.ID,
		Credential: &commonv1.Credential{
			Format:  contractFormat(h.Format),
			Payload: []byte(h.Full()),
		},
	}
	if t, err := time.Parse(time.RFC3339, h.AddedOn); err == nil {
		out.ReceivedAt = timestamp(t)
	}
	out.Type, out.Issuer = typeAndIssuer(h.ParsedDocument)
	return out
}

// typeAndIssuer reads the type name and the issuer of a parsed document.
func typeAndIssuer(raw json.RawMessage) (string, string) {
	if len(raw) == 0 {
		return "", ""
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", ""
	}
	if inner, ok := doc["vc"].(map[string]any); ok {
		doc = inner
	}
	name := ""
	switch types := doc["type"].(type) {
	case []any:
		for _, t := range types {
			if s, ok := t.(string); ok && s != "VerifiableCredential" {
				name = s
			}
		}
	case string:
		name = types
	}
	if name == "" {
		if vct, ok := doc["vct"].(string); ok {
			name = vct
		}
	}
	issuer := ""
	switch v := doc["issuer"].(type) {
	case string:
		issuer = v
	case map[string]any:
		if id, ok := v["id"].(string); ok {
			issuer = id
		}
	}
	if issuer == "" {
		if iss, ok := doc["iss"].(string); ok {
			issuer = iss
		}
	}
	return name, issuer
}

// AcceptOffer claims one credential offer into the wallet.
func (s *Service) AcceptOffer(
	ctx context.Context, req *connect.Request[backendv1.AcceptOfferRequest],
) (*connect.Response[backendv1.AcceptOfferResponse], error) {
	if !s.client.HasWallet() {
		return nil, unimplemented("this adapter has no wallet URL, so it serves no holder role")
	}
	session, err := s.session(ctx, req.Msg.GetWalletId())
	if err != nil {
		return nil, err
	}
	offerURI := strings.TrimSpace(req.Msg.GetOfferUri())
	if offerURI == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the request needs an offer_uri"))
	}
	before, berr := s.client.ListCredentials(ctx, session)
	if berr != nil {
		return nil, failed("list the credentials", berr)
	}
	// The wallet reads the offer first. A bad offer fails here with the
	// text of walt.id, which the citizen can act on.
	resolved, rerr := s.client.ResolveOffer(ctx, session, offerURI)
	if rerr != nil {
		return nil, failed("read the offer", rerr)
	}
	// The wallet-api of 0.18.2 redeems a pre-authorized code only; it
	// takes no access token of the issuer. A sign in grant for an offer
	// without such a code cannot reach the wallet (P6-W4).
	if req.Msg.GetAuthorizationGrant() != "" && !preAuthorized(resolved) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New(
			"the walt.id wallet claims offers with a pre-authorized code only; ask the issuer for such an offer"))
	}
	if aerr := s.client.AcceptOffer(ctx, session, offerURI, strings.TrimSpace(req.Msg.GetPin())); aerr != nil {
		return nil, failed("claim the offer", aerr)
	}
	after, aerr := s.client.ListCredentials(ctx, session)
	if aerr != nil {
		return nil, failed("list the credentials", aerr)
	}
	claimed := newCredential(before, after)
	if claimed == nil {
		return nil, connect.NewError(connect.CodeInternal,
			errors.New("the wallet claimed the offer but holds no new credential"))
	}
	return connect.NewResponse(&backendv1.AcceptOfferResponse{Credential: walletCredential(*claimed)}), nil
}

// preAuthorized reports whether a resolved offer carries a pre-authorized
// code grant.
func preAuthorized(offer json.RawMessage) bool {
	var body struct {
		Grants map[string]json.RawMessage `json:"grants"`
	}
	if err := json.Unmarshal(offer, &body); err != nil {
		return false
	}
	_, ok := body.Grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
	return ok
}

// newCredential returns the credential that the wallet gained. walt.id
// does not echo the identifier of the claimed credential, so the adapter
// compares the wallet before and after the claim.
func newCredential(before, after []waltid.HeldCredential) *waltid.HeldCredential {
	known := make(map[string]bool, len(before))
	for _, h := range before {
		known[h.ID] = true
	}
	for i := len(after) - 1; i >= 0; i-- {
		if !known[after[i].ID] {
			return &after[i]
		}
	}
	return nil
}

// Present answers one OID4VP request from the wallet.
func (s *Service) Present(
	ctx context.Context, req *connect.Request[backendv1.PresentRequest],
) (*connect.Response[backendv1.PresentResponse], error) {
	if !s.client.HasWallet() {
		return nil, unimplemented("this adapter has no wallet URL, so it serves no holder role")
	}
	session, err := s.session(ctx, req.Msg.GetWalletId())
	if err != nil {
		return nil, err
	}
	ids := req.Msg.GetCredentialIds()
	if len(ids) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the request needs at least one credential id"))
	}
	held, lerr := s.client.ListCredentials(ctx, session)
	if lerr != nil {
		return nil, failed("list the credentials", lerr)
	}
	disclosures, sent, err := presentation(held, ids, req.Msg.GetDisclosedClaims())
	if err != nil {
		return nil, err
	}
	if missing := disclosure.Missing(sent, req.Msg.GetDisclosedClaims()); len(missing) > 0 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New(disclosure.Refusal(missing)))
	}
	result, perr := s.client.Present(ctx, session, req.Msg.GetRequestUri(), ids, disclosures)
	if perr != nil {
		return nil, failed("present the credentials", perr)
	}
	return connect.NewResponse(&backendv1.PresentResponse{
		Accepted:     true,
		SharedClaims: sent,
		RedirectUri:  result.RedirectURI,
	}), nil
}

// presentation returns the disclosure map of usePresentationRequest and
// the claim names the verifier then reads (ADR-081 decision 5). walt.id
// 0.18.2 appends the strings of the map to the SD-JWT document, so the
// map holds the encoded disclosures of the ticked claims. An SD-JWT
// still shows each claim outside a disclosure. Any other format goes
// whole.
func presentation(held []waltid.HeldCredential, ids, ticked []string) (map[string][]string, []string, error) {
	byID := map[string]waltid.HeldCredential{}
	for _, h := range held {
		byID[h.ID] = h
	}
	disclosures := map[string][]string{}
	var sent []string
	add := func(names ...string) {
		for _, n := range names {
			if !slices.Contains(sent, n) {
				sent = append(sent, n)
			}
		}
	}
	for _, id := range ids {
		h, ok := byID[id]
		if !ok {
			return nil, nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("the wallet holds no credential %q", id))
		}
		if !sdJwtFormat(h.Format) {
			add(wholeClaims(h)...)
			continue
		}
		parsed, err := sdjwt.Parse(h.Full())
		if err != nil {
			return nil, nil, connect.NewError(connect.CodeInternal, fmt.Errorf("the wallet holds a broken SD-JWT %q: %w", id, err))
		}
		add(plainClaims(parsed.IssuerJWT)...)
		keep := []string{}
		for _, d := range parsed.Disclosures {
			if d.Name != "" && len(disclosure.Missing([]string{d.Name}, ticked)) == 0 {
				keep = append(keep, d.Encoded)
				add(d.Name)
			}
		}
		disclosures[id] = keep
	}
	if len(disclosures) == 0 {
		disclosures = nil
	}
	slices.Sort(sent)
	return disclosures, sent, nil
}

// sdJwtFormat reports a format whose claims a holder discloses one by
// one.
func sdJwtFormat(f string) bool {
	switch waltid.Format(f) {
	case waltid.FormatVcSdJwt, waltid.FormatDcSdJwt:
		return true
	}
	return false
}

// plainClaims returns the payload claims of an SD-JWT that no
// disclosure hides.
func plainClaims(jwt string) []string {
	parsed, err := vc.FixedClaims([]byte(jwt + "~"))
	if err != nil {
		return nil
	}
	return parsed
}

// wholeClaims returns the subject claims of a credential that goes
// whole, or the path for the whole credential when the wallet names
// none.
func wholeClaims(h waltid.HeldCredential) []string {
	var doc map[string]any
	if json.Unmarshal(h.ParsedDocument, &doc) == nil {
		if claims := vc.FromObject(doc).Claims; len(claims) > 0 {
			out := make([]string, 0, len(claims))
			for name := range claims {
				out = append(out, name)
			}
			return out
		}
	}
	if parsed, err := vc.FixedClaims([]byte(h.Document)); err == nil && len(parsed) > 0 {
		return parsed
	}
	return []string{disclosure.Whole}
}

// DeleteCredential removes one credential from the wallet.
func (s *Service) DeleteCredential(
	ctx context.Context, req *connect.Request[backendv1.DeleteCredentialRequest],
) (*connect.Response[backendv1.DeleteCredentialResponse], error) {
	if !s.client.HasWallet() {
		return nil, unimplemented("this adapter has no wallet URL, so it serves no holder role")
	}
	session, err := s.session(ctx, req.Msg.GetWalletId())
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Msg.GetCredentialId()) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the request needs a credential_id"))
	}
	if derr := s.client.DeleteCredential(ctx, session, req.Msg.GetCredentialId()); derr != nil {
		return nil, failed("delete the credential", derr)
	}
	return connect.NewResponse(&backendv1.DeleteCredentialResponse{}), nil
}
