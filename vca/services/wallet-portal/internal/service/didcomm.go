// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/detect"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/present"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/session"
)

// The DIDComm wallet of the stack (P6-C7, ADR-062). The wallet reads a
// scanned invitation itself and keeps it. The stack wallet receives it
// only when the holder accepts. A decline sends nothing, because the
// agent of the stack has no decline call.

// KindInvitation is a DIDComm invitation the citizen has not answered.
const KindInvitation = "didcomm"

// What an invitation carries.
const (
	carriesOffer      = "offer"
	carriesRequest    = "request"
	carriesConnection = "connection"
)

// errNoDidcomm reports a wallet whose stack speaks no DIDComm.
var errNoDidcomm = connect.NewError(connect.CodeFailedPrecondition,
	errors.New("the wallet of this deployment speaks no DIDComm; open the invitation in a DIDComm wallet"))

// didcomm reports whether the wallet of the stack speaks DIDComm.
func (s *Service) didcomm(ctx context.Context) bool {
	return s.opts.Holder != nil && s.opts.Didcomm != nil && s.opts.Didcomm(ctx)
}

// Didcomm reports whether the wallet of the stack speaks DIDComm, for
// the pages.
func (s *Service) Didcomm(ctx context.Context) bool { return s.didcomm(ctx) }

// invitationOf returns the invitation of a scan. A wallet of the stack
// that speaks DIDComm keeps it for the answer of the citizen.
func (s *Service) invitationOf(ctx context.Context, citizen session.Citizen, id string, got detect.DidcommInvitation,
) (*walletportalv1.DidcommInvitation, error) {
	out := &walletportalv1.DidcommInvitation{
		Uri: got.URI, Label: got.Label, CarriesOffer: got.CarriesOffer, CarriesRequest: got.CarriesRequest,
		Name: got.Name, Requested: got.Requested,
	}
	for _, v := range got.Offered {
		out.Offered = append(out.Offered, &walletportalv1.NamedValue{Name: v.Name, Value: v.Value})
	}
	if !s.didcomm(ctx) {
		return out, nil
	}
	carries := carriesConnection
	switch {
	case got.CarriesOffer:
		carries = carriesOffer
	case got.CarriesRequest:
		carries = carriesRequest
	}
	rec := record{ID: id, URI: got.URI, Label: got.Label, Asked: got.Requested, Carries: carries}
	if err := s.put(ctx, KindInvitation, citizen.WalletKey(), rec); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out.InvitationId = id
	return out, nil
}

// AnswerInvitation accepts or declines a pending invitation.
func (s *Service) AnswerInvitation(ctx context.Context, req *connect.Request[walletportalv1.AnswerInvitationRequest],
) (*connect.Response[walletportalv1.AnswerInvitationResponse], error) {
	citizen, err := session.Require(ctx)
	if err != nil {
		return nil, err
	}
	if !s.didcomm(ctx) {
		return nil, errNoDidcomm
	}
	rec, err := s.get(ctx, KindInvitation, citizen.WalletKey(), req.Msg.GetInvitationId())
	if err != nil {
		return nil, recordError(err)
	}
	ignored := s.drop(ctx, KindInvitation, citizen.WalletKey(), rec.ID)
	_ = ignored
	if req.Msg.GetDecline() {
		return connect.NewResponse(&walletportalv1.AnswerInvitationResponse{
			Message: "The wallet forgot the invitation and sent nothing.",
		}), nil
	}
	out := &walletportalv1.AnswerInvitationResponse{}
	switch rec.Carries {
	case carriesOffer:
		out.Card, err = s.takeOffer(ctx, citizen, &backendv1.AcceptOfferRequest{OfferUri: rec.URI})
		out.Message = "The credential is in your wallet."
	case carriesRequest:
		out.Record, out.Message, err = s.answerRequest(ctx, citizen, rec.Label, rec.Asked, &backendv1.PresentRequest{RequestUri: rec.URI})
	default:
		out.ConnectionLabel, err = s.connect(ctx, citizen, rec.URI)
		out.Message = "The wallet is now connected."
	}
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(out), nil
}

// takeOffer has the stack wallet accept an offer and returns its card.
func (s *Service) takeOffer(ctx context.Context, citizen session.Citizen, msg *backendv1.AcceptOfferRequest,
) (*walletportalv1.Card, error) {
	msg.WalletId = citizen.WalletID
	resp, err := s.opts.Holder.AcceptOffer(ctx, connect.NewRequest(msg))
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("the issuer did not give the credential: "+backendMessage(err)))
	}
	return s.opts.Cards.Card(ctx, resp.Msg.GetCredential()), nil
}

// answerRequest has the stack wallet answer a proof request and keeps
// the record of the answer. party names the verifier.
func (s *Service) answerRequest(ctx context.Context, citizen session.Citizen, party string, asked []string, msg *backendv1.PresentRequest,
) (*walletportalv1.PresentationRecord, string, error) {
	msg.WalletId = citizen.WalletID
	parsed := present.Request{ClientID: party}
	resp, err := s.opts.Holder.Present(ctx, connect.NewRequest(msg))
	if err != nil {
		s.remember(ctx, citizen, parsed, asked, walletportalv1.PresentationRecord_RESULT_FAILED)
		return nil, "", connect.NewError(connect.CodeUnavailable, errors.New("the verifier did not take the proof: "+backendMessage(err)))
	}
	shared := resp.Msg.GetSharedClaims()
	if len(shared) == 0 {
		shared = asked
	}
	if !resp.Msg.GetAccepted() {
		return s.remember(ctx, citizen, parsed, shared, walletportalv1.PresentationRecord_RESULT_REJECTED),
			"The verifier did not accept the proof.", nil
	}
	return s.remember(ctx, citizen, parsed, shared, walletportalv1.PresentationRecord_RESULT_ACCEPTED),
		"You sent the proof. The verifier has your answer.", nil
}

// connect has the stack wallet open an invitation that makes a
// connection only.
func (s *Service) connect(ctx context.Context, citizen session.Citizen, uri string) (string, error) {
	resp, err := s.opts.Holder.OpenInvitation(ctx, connect.NewRequest(&backendv1.OpenInvitationRequest{
		WalletId: citizen.WalletID, InvitationUri: uri,
	}))
	if err != nil {
		return "", connect.NewError(connect.CodeUnavailable, errors.New("the wallet did not connect: "+backendMessage(err)))
	}
	return resp.Msg.GetConnection().GetLabel(), nil
}

// backendMessage returns the sentence of a backend error.
func backendMessage(err error) string {
	var ce *connect.Error
	if errors.As(err, &ce) {
		return ce.Message()
	}
	return err.Error()
}

// ListInbox lists what waits for the citizen over a connection.
func (s *Service) ListInbox(ctx context.Context, _ *connect.Request[walletportalv1.ListInboxRequest],
) (*connect.Response[walletportalv1.ListInboxResponse], error) {
	citizen, err := session.Require(ctx)
	if err != nil {
		return nil, err
	}
	if !s.didcomm(ctx) {
		return nil, errNoDidcomm
	}
	resp, err := s.opts.Holder.ListInbox(ctx, connect.NewRequest(&backendv1.ListInboxRequest{WalletId: citizen.WalletID}))
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("the wallet did not list what waits, try again later"))
	}
	out := &walletportalv1.ListInboxResponse{}
	for _, item := range resp.Msg.GetItems() {
		entry := &walletportalv1.InboxEntry{
			Id: item.GetId(), Kind: walletportalv1.InboxEntry_Kind(item.GetKind()), From: item.GetConnectionLabel(),
			ReceivedAt: item.GetReceivedAt(), Name: item.GetName(), Requested: item.GetRequested(),
		}
		for _, v := range item.GetOffered() {
			entry.Offered = append(entry.Offered, &walletportalv1.NamedValue{Name: v.GetName(), Value: v.GetValue()})
		}
		out.Entries = append(out.Entries, entry)
	}
	return connect.NewResponse(out), nil
}

// AnswerInbox accepts one offer or one proof request of the inbox.
func (s *Service) AnswerInbox(ctx context.Context, req *connect.Request[walletportalv1.AnswerInboxRequest],
) (*connect.Response[walletportalv1.AnswerInboxResponse], error) {
	citizen, err := session.Require(ctx)
	if err != nil {
		return nil, err
	}
	if !s.didcomm(ctx) {
		return nil, errNoDidcomm
	}
	out := &walletportalv1.AnswerInboxResponse{}
	switch req.Msg.GetKind() {
	case walletportalv1.InboxEntry_KIND_OFFER:
		out.Card, err = s.takeOffer(ctx, citizen, &backendv1.AcceptOfferRequest{InboxId: req.Msg.GetId()})
		out.Message = "The credential is in your wallet."
	case walletportalv1.InboxEntry_KIND_PROOF_REQUEST:
		party, asked := s.inboxEntry(ctx, citizen, req.Msg.GetId())
		out.Record, out.Message, err = s.answerRequest(ctx, citizen, party, asked, &backendv1.PresentRequest{InboxId: req.Msg.GetId()})
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("name the kind of the entry"))
	}
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(out), nil
}

// inboxEntry returns who sent an inbox entry and what it asks for, or
// nothing when the inbox does not list it.
func (s *Service) inboxEntry(ctx context.Context, citizen session.Citizen, id string) (string, []string) {
	resp, err := s.opts.Holder.ListInbox(ctx, connect.NewRequest(&backendv1.ListInboxRequest{WalletId: citizen.WalletID}))
	if err != nil {
		return "", nil
	}
	for _, item := range resp.Msg.GetItems() {
		if item.GetId() == id {
			return item.GetConnectionLabel(), item.GetRequested()
		}
	}
	return "", nil
}

// ListConnections lists the connections of the stack wallet.
func (s *Service) ListConnections(ctx context.Context, _ *connect.Request[walletportalv1.ListConnectionsRequest],
) (*connect.Response[walletportalv1.ListConnectionsResponse], error) {
	citizen, err := session.Require(ctx)
	if err != nil {
		return nil, err
	}
	if !s.didcomm(ctx) {
		return nil, errNoDidcomm
	}
	resp, err := s.opts.Holder.ListWalletConnections(ctx, connect.NewRequest(&backendv1.ListWalletConnectionsRequest{WalletId: citizen.WalletID}))
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("the wallet did not list its connections, try again later"))
	}
	out := &walletportalv1.ListConnectionsResponse{}
	for _, c := range resp.Msg.GetConnections() {
		out.Connections = append(out.Connections, &walletportalv1.Connection{
			Id: c.GetId(), Label: c.GetLabel(), State: c.GetState(), CreatedAt: c.GetCreatedAt(),
		})
	}
	return connect.NewResponse(out), nil
}
