// SPDX-License-Identifier: Apache-2.0

// Package service serves vca.walletportal.v1.WalletPortalService
// (ADR-021). The service holds no credential of its own. It delegates
// every wallet action to the holder backend of the DPG
// (ADR-021 decision 3). A deployment with no DPG wallet keeps the
// credentials in the browser (ADR-021 decision 4).
//
// Every RPC needs the session of ADR-020. The session middleware puts
// the citizen on the context.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1/walletportalv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/cards"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/detect"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/ports"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/present"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/session"
)

// DefaultPageSizeMax caps the page size of a list RPC.
const DefaultPageSizeMax = 50

// DefaultMaxPasteBytes caps a scanned or pasted text.
const DefaultMaxPasteBytes = 64 << 10

// DefaultPendingTTL is how long an offer or a presentation stays
// readable.
const DefaultPendingTTL = 15 * time.Minute

// Options configure the service.
type Options struct {
	// Holder is the holder backend of the DPG. A nil client selects the
	// browser storage of ADR-021 decision 4.
	Holder backendv1connect.HolderBackendServiceClient
	// Catalogue reads the published credential types. Nil turns the
	// discovery page and the claimable page off.
	Catalogue ports.Catalogue
	// Eligible answers yes or no per schema. Nil answers no.
	Eligible ports.Eligibility
	// Salt hides the citizen subject from the eligibility hook.
	Salt string
	// Cards builds the card of one credential. It is required.
	Cards *cards.Builder
	// Trust asks the trust registry about an issuer or a verifier.
	Trust cards.TrustLookup
	// Store keeps the pending offers and presentations. It is required.
	Store store.KeyValue
	// Fetch reads an OID4VP request object. Nil blocks a request URI.
	Fetch present.Fetcher
	// Post sends the direct_post answer. Nil blocks a submit.
	Post present.Poster
	// RequestHosts is the host allowlist of a request URI.
	RequestHosts []string
	// PageSizeMax caps the page size. Zero means DefaultPageSizeMax.
	PageSizeMax int
	// MaxPasteBytes caps a pasted text. Zero means
	// DefaultMaxPasteBytes.
	MaxPasteBytes int64
	// PendingTTL is the life of an offer or a presentation. Zero means
	// DefaultPendingTTL.
	PendingTTL time.Duration
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
	// NewID returns a record id. Nil makes a random id.
	NewID func() string
}

// Service answers the wallet portal RPCs.
type Service struct {
	walletportalv1connect.UnimplementedWalletPortalServiceHandler
	opts Options
}

// New builds the service.
func New(opts Options) (*Service, error) {
	if opts.Cards == nil {
		return nil, errors.New("service: a card builder is required")
	}
	if opts.Store == nil {
		return nil, errors.New("service: a store is required")
	}
	if opts.PageSizeMax <= 0 {
		opts.PageSizeMax = DefaultPageSizeMax
	}
	if opts.MaxPasteBytes <= 0 {
		opts.MaxPasteBytes = DefaultMaxPasteBytes
	}
	if opts.PendingTTL <= 0 {
		opts.PendingTTL = DefaultPendingTTL
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.NewID == nil {
		opts.NewID = newID
	}
	if opts.Eligible == nil {
		opts.Eligible = ports.StaticEligibility(false)
	}
	return &Service{opts: opts}, nil
}

// Ready reports whether the service can take traffic.
func (s *Service) Ready() bool { return s != nil }

// BrowserStorage reports whether the deployment keeps the credentials
// in the browser (ADR-021 decision 4).
func (s *Service) BrowserStorage() bool { return s.opts.Holder == nil }

// ListDiscoverable returns the schemas that issuers publish
// (ADR-021 decision 1).
func (s *Service) ListDiscoverable(ctx context.Context,
	req *connect.Request[walletportalv1.ListDiscoverableRequest],
) (*connect.Response[walletportalv1.ListDiscoverableResponse], error) {
	if _, err := session.Require(ctx); err != nil {
		return nil, err
	}
	items, err := s.offerings(ctx)
	if err != nil {
		return nil, err
	}
	page, next := s.page(items, req.Msg.GetPage())
	return connect.NewResponse(&walletportalv1.ListDiscoverableResponse{
		Offerings: page,
		Page:      &commonv1.PageResult{NextPageToken: next, TotalSize: int64(len(items))},
	}), nil
}

// ListClaimable returns the schemas the citizen can get, with the yes
// or no answer of the eligibility hook (ADR-021 decision 2).
func (s *Service) ListClaimable(ctx context.Context,
	req *connect.Request[walletportalv1.ListClaimableRequest],
) (*connect.Response[walletportalv1.ListClaimableResponse], error) {
	citizen, err := session.Require(ctx)
	if err != nil {
		return nil, err
	}
	items, err := s.offerings(ctx)
	if err != nil {
		return nil, err
	}
	page, next := s.page(items, req.Msg.GetPage())
	ref := ports.SubjectRef(s.opts.Salt, citizen.Subject)
	out := make([]*walletportalv1.ListClaimableResponse_Item, 0, len(page))
	for _, offering := range page {
		eligible, err := s.opts.Eligible(ctx, ref, offering)
		if err != nil {
			return nil, connect.NewError(connect.CodeUnavailable,
				errors.New("the eligibility check is not available"))
		}
		out = append(out, &walletportalv1.ListClaimableResponse_Item{Offering: offering, Eligible: eligible})
	}
	return connect.NewResponse(&walletportalv1.ListClaimableResponse{
		Items: out,
		Page:  &commonv1.PageResult{NextPageToken: next, TotalSize: int64(len(items))},
	}), nil
}

// offerings reads the catalogue.
func (s *Service) offerings(ctx context.Context) ([]*walletportalv1.Offering, error) {
	if s.opts.Catalogue == nil {
		return nil, connect.NewError(connect.CodeUnavailable,
			errors.New("this deployment has no credential catalogue"))
	}
	items, err := s.opts.Catalogue.Offerings(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("the catalogue is not available"))
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].GetSchema().GetType() < items[j].GetSchema().GetType()
	})
	return items, nil
}

// page returns one page of the offerings and the next page token.
func (s *Service) page(items []*walletportalv1.Offering, p *commonv1.Pagination,
) ([]*walletportalv1.Offering, string) {
	size := int(p.GetPageSize())
	if size <= 0 || size > s.opts.PageSizeMax {
		size = s.opts.PageSizeMax
	}
	start, err := strconv.Atoi(p.GetPageToken())
	if err != nil || start < 0 || start > len(items) {
		start = 0
	}
	end := start + size
	if end >= len(items) {
		return items[start:], ""
	}
	return items[start:end], strconv.Itoa(end)
}

// Claim starts the authorization code flow for one schema
// (ADR-021 decision 3). The holder backend does the flow.
func (s *Service) Claim(ctx context.Context, req *connect.Request[walletportalv1.ClaimRequest],
) (*connect.Response[walletportalv1.ClaimResponse], error) {
	citizen, err := session.Require(ctx)
	if err != nil {
		return nil, err
	}
	msg := req.Msg
	if msg.GetCredentialIssuer() == "" || msg.GetSchemaId() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("name the issuer and the credential"))
	}
	offerURI, err := authCodeOffer(msg.GetCredentialIssuer(), msg.GetSchemaId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if s.opts.Holder == nil {
		id := s.opts.NewID()
		rec := record{ID: id, URI: offerURI, Issuer: msg.GetCredentialIssuer(),
			Types: []string{msg.GetSchemaId()}}
		if err := s.put(ctx, KindOffer, citizen.WalletKey(), rec); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		return connect.NewResponse(&walletportalv1.ClaimResponse{OfferId: id}), nil
	}
	card, err := s.accept(ctx, citizen, offerURI, "")
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&walletportalv1.ClaimResponse{Card: card}), nil
}

// authCodeOffer builds an OID4VCI credential offer that names the
// authorization code grant.
func authCodeOffer(issuer, configurationID string) (string, error) {
	offer := map[string]any{
		"credential_issuer":            issuer,
		"credential_configuration_ids": []string{configurationID},
		"grants":                       map[string]any{"authorization_code": map[string]any{}},
	}
	raw, err := json.Marshal(offer)
	if err != nil {
		return "", fmt.Errorf("service: build the offer: %w", err)
	}
	return detect.SchemeOffer + "://?credential_offer=" + url.QueryEscape(string(raw)), nil
}

// Scan reads the text of a scanned QR code.
func (s *Service) Scan(ctx context.Context, req *connect.Request[walletportalv1.ScanRequest],
) (*connect.Response[walletportalv1.ScanResponse], error) {
	found, err := s.read(ctx, req.Msg.GetText())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&walletportalv1.ScanResponse{Detected: found}), nil
}

// Paste reads pasted text.
func (s *Service) Paste(ctx context.Context, req *connect.Request[walletportalv1.PasteRequest],
) (*connect.Response[walletportalv1.PasteResponse], error) {
	found, err := s.read(ctx, req.Msg.GetText())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&walletportalv1.PasteResponse{Detected: found}), nil
}

// read classifies one text and keeps what the next step needs.
func (s *Service) read(ctx context.Context, text string) (*walletportalv1.Detected, error) {
	citizen, err := session.Require(ctx)
	if err != nil {
		return nil, err
	}
	got, err := detect.Text(text, s.opts.MaxPasteBytes)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	id := s.opts.NewID()
	switch got.Kind {
	case detect.Offer:
		rec := record{ID: id, URI: got.Offer.URI, Issuer: got.Offer.CredentialIssuer,
			Types: got.Offer.ConfigurationIDs, NeedsPIN: got.Offer.NeedsPIN}
		if err := s.put(ctx, KindOffer, citizen.WalletKey(), rec); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		trust := present.TrustOf(ctx, s.opts.Trust, got.Offer.CredentialIssuer)
		return &walletportalv1.Detected{
			Kind:    walletportalv1.Detected_KIND_CREDENTIAL_OFFER,
			OfferId: id,
			Offer: &walletportalv1.OfferSummary{
				CredentialIssuer: got.Offer.CredentialIssuer,
				IssuerName:       trust.Name,
				Trust:            trust.Outcome,
				Types:            got.Offer.ConfigurationIDs,
				NeedsPin:         got.Offer.NeedsPIN,
			},
		}, nil
	case detect.Request:
		rec := record{ID: id, URI: got.RequestURI}
		if err := s.put(ctx, KindPresentation, citizen.WalletKey(), rec); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		return &walletportalv1.Detected{
			Kind:           walletportalv1.Detected_KIND_PRESENTATION_REQUEST,
			PresentationId: id,
		}, nil
	case detect.Credential:
		rec := record{ID: id, Payload: got.Credential, Format: got.Format}
		if err := s.put(ctx, KindHeld, citizen.WalletKey(), rec); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		return &walletportalv1.Detected{Kind: walletportalv1.Detected_KIND_CREDENTIAL, OfferId: id}, nil
	}
	return &walletportalv1.Detected{
		Kind: walletportalv1.Detected_KIND_UNKNOWN,
		Error: &commonv1.Error{
			Code: "VCA-421", Message: detect.Explain(got),
			NextStep: "Scan the code again, or ask the issuer for a new one.",
		},
	}, nil
}

// Accept claims a pending offer into the wallet
// (ADR-021 decision 3).
func (s *Service) Accept(ctx context.Context, req *connect.Request[walletportalv1.AcceptRequest],
) (*connect.Response[walletportalv1.AcceptResponse], error) {
	citizen, err := session.Require(ctx)
	if err != nil {
		return nil, err
	}
	rec, err := s.get(ctx, KindOffer, citizen.WalletKey(), req.Msg.GetOfferId())
	if err != nil {
		return nil, recordError(err)
	}
	card, err := s.accept(ctx, citizen, rec.URI, req.Msg.GetPin())
	if err != nil {
		return nil, err
	}
	_ = s.drop(ctx, KindOffer, citizen.WalletKey(), rec.ID)
	return connect.NewResponse(&walletportalv1.AcceptResponse{Card: card}), nil
}

// accept calls the holder backend of the DPG.
func (s *Service) accept(ctx context.Context, citizen session.Citizen, offerURI, pin string,
) (*walletportalv1.Card, error) {
	if s.opts.Holder == nil {
		return nil, connect.NewError(connect.CodeUnimplemented,
			errors.New("this deployment keeps the credentials in your browser"))
	}
	resp, err := s.opts.Holder.AcceptOffer(ctx, connect.NewRequest(&backendv1.AcceptOfferRequest{
		WalletId: citizen.WalletID, OfferUri: offerURI, Pin: pin,
	}))
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable,
			errors.New("the issuer did not give the credential, try again later"))
	}
	return s.opts.Cards.Card(ctx, resp.Msg.GetCredential()), nil
}

// Reject discards a pending offer.
func (s *Service) Reject(ctx context.Context, req *connect.Request[walletportalv1.RejectRequest],
) (*connect.Response[walletportalv1.RejectResponse], error) {
	citizen, err := session.Require(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.drop(ctx, KindOffer, citizen.WalletKey(), req.Msg.GetOfferId()); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return connect.NewResponse(&walletportalv1.RejectResponse{}), nil
}

// Delete removes one credential from the wallet.
func (s *Service) Delete(ctx context.Context, req *connect.Request[walletportalv1.DeleteRequest],
) (*connect.Response[walletportalv1.DeleteResponse], error) {
	citizen, err := session.Require(ctx)
	if err != nil {
		return nil, err
	}
	id := req.Msg.GetId()
	if id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("name the credential"))
	}
	if s.opts.Holder == nil {
		if err := s.drop(ctx, KindHeld, citizen.WalletKey(), id); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		return connect.NewResponse(&walletportalv1.DeleteResponse{}), nil
	}
	_, err = s.opts.Holder.DeleteCredential(ctx, connect.NewRequest(&backendv1.DeleteCredentialRequest{
		WalletId: citizen.WalletID, CredentialId: id,
	}))
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable,
			errors.New("the wallet did not remove the credential, try again later"))
	}
	_ = s.drop(ctx, KindHeld, citizen.WalletKey(), id)
	return connect.NewResponse(&walletportalv1.DeleteResponse{}), nil
}

// ListMine returns the cards of the wallet (ADR-021 decision 6).
func (s *Service) ListMine(ctx context.Context, req *connect.Request[walletportalv1.ListMineRequest],
) (*connect.Response[walletportalv1.ListMineResponse], error) {
	citizen, err := session.Require(ctx)
	if err != nil {
		return nil, err
	}
	list, err := s.held(ctx, citizen, req.Msg.GetPage())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&walletportalv1.ListMineResponse{
		Cards: list, Page: &commonv1.PageResult{TotalSize: int64(len(list))},
	}), nil
}

// held returns the cards of the citizen. In browser storage mode the
// server sees only the credentials the citizen pasted in this session,
// because it cannot read the ciphertext blobs.
func (s *Service) held(ctx context.Context, citizen session.Citizen, page *commonv1.Pagination,
) ([]*walletportalv1.Card, error) {
	if s.opts.Holder == nil {
		records, err := s.list(ctx, KindHeld, citizen.WalletKey())
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		out := make([]*walletportalv1.Card, 0, len(records))
		for _, rec := range records {
			out = append(out, s.opts.Cards.Card(ctx, &backendv1.WalletCredential{
				Id:         rec.ID,
				Credential: &commonv1.Credential{Format: rec.Format, Payload: rec.Payload},
			}))
		}
		return out, nil
	}
	size := page.GetPageSize()
	if size <= 0 || int(size) > s.opts.PageSizeMax {
		size = int32(s.opts.PageSizeMax)
	}
	resp, err := s.opts.Holder.ListCredentials(ctx, connect.NewRequest(&backendv1.ListCredentialsRequest{
		WalletId: citizen.WalletID,
		Page:     &commonv1.Pagination{PageSize: size, PageToken: page.GetPageToken()},
	}))
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable,
			errors.New("the wallet is not available, try again later"))
	}
	return s.opts.Cards.Cards(ctx, resp.Msg.GetCredentials()), nil
}

// PresentStart reads an OID4VP request and builds the consent screen
// (ADR-021 decision 5).
func (s *Service) PresentStart(ctx context.Context,
	req *connect.Request[walletportalv1.PresentStartRequest],
) (*connect.Response[walletportalv1.PresentStartResponse], error) {
	citizen, err := session.Require(ctx)
	if err != nil {
		return nil, err
	}
	id, parsed, err := s.request(ctx, citizen, req.Msg.GetPresentationId())
	if err != nil {
		return nil, err
	}
	held, err := s.held(ctx, citizen, nil)
	if err != nil {
		return nil, err
	}
	trust := present.TrustOf(ctx, s.opts.Trust, parsed.ClientID)
	return connect.NewResponse(&walletportalv1.PresentStartResponse{
		PresentationId: id,
		Verifier:       parsed.ClientID,
		VerifierName:   trust.Name,
		Trust:          trust.Outcome,
		Requested:      present.Consent(parsed, held),
		Purpose:        parsed.Purpose,
	}), nil
}

// request reads the presentation request of an id or a URI. It stores
// the request under an id, so PresentConfirm finds it again.
func (s *Service) request(ctx context.Context, citizen session.Citizen, idOrURI string,
) (string, present.Request, error) {
	if strings.TrimSpace(idOrURI) == "" {
		return "", present.Request{}, connect.NewError(connect.CodeInvalidArgument,
			errors.New("name the presentation request"))
	}
	id := idOrURI
	uri := idOrURI
	rec, err := s.get(ctx, KindPresentation, citizen.WalletKey(), idOrURI)
	switch {
	case err == nil:
		uri = rec.URI
	case errors.Is(err, ErrExpired):
		return "", present.Request{}, recordError(err)
	default:
		id = s.opts.NewID()
	}
	parsed, err := present.Parse(uri)
	if err != nil {
		return "", present.Request{}, connect.NewError(connect.CodeInvalidArgument, err)
	}
	full, err := present.Fetch(ctx, parsed, s.opts.RequestHosts, s.opts.Fetch)
	if err != nil {
		return "", present.Request{}, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if rec.ID == "" {
		if err := s.put(ctx, KindPresentation, citizen.WalletKey(), record{ID: id, URI: uri}); err != nil {
			return "", present.Request{}, connect.NewError(connect.CodeInternal, err)
		}
	}
	return id, full, nil
}

// PresentConfirm sends the presentation after the citizen consented.
func (s *Service) PresentConfirm(ctx context.Context,
	req *connect.Request[walletportalv1.PresentConfirmRequest],
) (*connect.Response[walletportalv1.PresentConfirmResponse], error) {
	citizen, err := session.Require(ctx)
	if err != nil {
		return nil, err
	}
	_, parsed, err := s.request(ctx, citizen, req.Msg.GetPresentationId())
	if err != nil {
		return nil, err
	}
	chosen, disclosed := selections(req.Msg)
	if len(chosen) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("choose one credential first"))
	}
	if s.opts.Holder != nil {
		return s.presentWithBackend(ctx, citizen, parsed, chosen, disclosed)
	}
	return s.presentDirect(ctx, citizen, parsed, chosen, disclosed)
}

// selections returns the chosen card ids and the disclosed claim paths
// in query id order.
func selections(msg *walletportalv1.PresentConfirmRequest) ([]string, []string) {
	ids := make([]string, 0, len(msg.GetSelectedCards()))
	queries := make([]string, 0, len(msg.GetSelectedCards()))
	for query := range msg.GetSelectedCards() {
		queries = append(queries, query)
	}
	sort.Strings(queries)
	var paths []string
	for _, query := range queries {
		ids = append(ids, msg.GetSelectedCards()[query])
		paths = append(paths, msg.GetDisclosed()[query].GetPaths()...)
	}
	return ids, paths
}

// presentWithBackend asks the holder backend to answer the request.
func (s *Service) presentWithBackend(ctx context.Context, citizen session.Citizen,
	parsed present.Request, chosen, disclosed []string,
) (*connect.Response[walletportalv1.PresentConfirmResponse], error) {
	uri := parsed.RequestURI
	if uri == "" {
		uri = parsed.ResponseURI
	}
	resp, err := s.opts.Holder.Present(ctx, connect.NewRequest(&backendv1.PresentRequest{
		WalletId: citizen.WalletID, RequestUri: uri,
		CredentialIds: chosen, DisclosedClaims: disclosed,
	}))
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable,
			errors.New("the verifier did not take the credential, try again later"))
	}
	message := "The verifier did not accept the credential."
	if resp.Msg.GetAccepted() {
		message = "You sent the credential. The verifier has your answer."
	}
	return connect.NewResponse(&walletportalv1.PresentConfirmResponse{
		Accepted:    resp.Msg.GetAccepted(),
		RedirectUri: resp.Msg.GetRedirectUri(),
		Message:     message,
	}), nil
}

// presentDirect builds the vp_token from a credential the citizen
// pasted and posts it with direct_post (ADR-021 decision 5).
func (s *Service) presentDirect(ctx context.Context, citizen session.Citizen,
	parsed present.Request, chosen, disclosed []string,
) (*connect.Response[walletportalv1.PresentConfirmResponse], error) {
	rec, err := s.get(ctx, KindHeld, citizen.WalletKey(), chosen[0])
	if err != nil {
		return nil, recordError(err)
	}
	token := string(rec.Payload)
	if rec.Format == commonv1.Format_FORMAT_DC_SD_JWT || rec.Format == commonv1.Format_FORMAT_VC_SD_JWT {
		token, err = present.Disclosed(string(rec.Payload), disclosed)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}
	result, err := present.Submit(ctx, parsed, token, s.opts.Post)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New(result.Message))
	}
	return connect.NewResponse(&walletportalv1.PresentConfirmResponse{
		Accepted: result.Accepted, RedirectUri: result.RedirectURI, Message: result.Message,
	}), nil
}

// recordError maps a record problem to a Connect error.
func recordError(err error) error {
	switch {
	case errors.Is(err, ErrExpired):
		return connect.NewError(connect.CodeDeadlineExceeded,
			errors.New("this step timed out, scan the code again"))
	case errors.Is(err, ErrNoRecord):
		return connect.NewError(connect.CodeNotFound, errors.New("the wallet does not know this step"))
	}
	return connect.NewError(connect.CodeInternal, err)
}
