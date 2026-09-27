// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/credebl"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// The holder wallet of ADR-062 (P6-C7). Each holder has a tenant wallet
// in the shared agent of the stack. The adapter maps the hashed pairwise
// subject onto the tenant and keeps nothing else of the holder.

// DefaultHolderLabel is the label a tenant wallet shows the other party
// of a connection.
const DefaultHolderLabel = "Wallet"

// DefaultPollInterval is the wait between two reads of an exchange.
const DefaultPollInterval = 500 * time.Millisecond

// DefaultPollAttempts is the number of reads before the adapter stops
// waiting for the other party.
const DefaultPollAttempts = 40

// WalletDidMethods are the DID methods CreateDid takes. The agent makes
// the key of a did:key itself.
var WalletDidMethods = []string{"did:key"}

// The prefixes of the credential ids of ListCredentials.
const (
	anonCredsPrefix = "anoncreds:"
	w3cPrefix       = "w3c:"
	sdJwtPrefix     = "sd-jwt:"
	mdocPrefix      = "mdoc:"
)

// The exchange states the holder reads (Credo 0.6.2).
const (
	stateOfferReceived   = "offer-received"
	stateRequestReceived = "request-received"
	stateDone            = "done"
	stateAbandoned       = "abandoned"
	stateDeclined        = "declined"
	stateCompleted       = "completed"
)

// holderMessage says what the holder role needs.
const holderMessage = "this adapter has no agent address and API key, so it serves no holder wallet; " +
	"use the wallet portal with the browser store or an external wallet"

// holderRecord is what the store keeps of a holder.
type holderRecord struct {
	// Tenant is the tenant id, which is the wallet id.
	Tenant string `json:"tenant"`
	// Did is the did:key Register made.
	Did string `json:"did"`
}

// holderKey is the store key of a holder: a hash of the subject, which
// is itself a hash.
func holderKey(subject string) string {
	sum := sha256.Sum256([]byte("credebl-holder|" + subject))
	return "holder/" + hex.EncodeToString(sum[:])
}

// walletKey is the store key that marks a tenant of a holder.
func walletKey(tenant string) string { return "wallet/" + tenant }

// holderRole reports whether the adapter serves the holder role.
func (s *Service) holderRole() bool { return s.agent != nil }

// wallet checks the role and the wallet id. The id must name a tenant
// that Register made, never the tenant of an organisation in the same
// agent.
func (s *Service) wallet(ctx context.Context, id string) (string, error) {
	if !s.holderRole() {
		return "", unimplemented(holderMessage)
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return "", connect.NewError(connect.CodeInvalidArgument, errors.New("the request needs a wallet_id"))
	}
	if _, err := s.store.Get(ctx, walletKey(id)); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", connect.NewError(connect.CodeNotFound, fmt.Errorf("the wallet %q is not a holder wallet of this adapter; call Register first", id))
		}
		return "", connect.NewError(connect.CodeInternal, err)
	}
	return id, nil
}

// Register opens the tenant wallet of a holder, and makes it with a
// did:key at the first login (ADR-062 decision 2).
func (s *Service) Register(
	ctx context.Context, req *connect.Request[backendv1.RegisterRequest],
) (*connect.Response[backendv1.RegisterResponse], error) {
	if !s.holderRole() {
		return nil, unimplemented(holderMessage)
	}
	subject := strings.TrimSpace(req.Msg.GetPairwiseSubject())
	if subject == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the request needs a pairwise_subject"))
	}
	key := holderKey(subject)
	s.registerMu.Lock()
	defer s.registerMu.Unlock()
	rec, found, err := s.storedHolder(ctx, key)
	if err != nil {
		return nil, err
	}
	if found {
		return connect.NewResponse(&backendv1.RegisterResponse{WalletId: rec.Tenant, HolderDid: rec.Did}), nil
	}
	tenant, err := s.agent.CreateTenant(ctx, s.holderLabel)
	if err != nil {
		return nil, failed("make the wallet", err)
	}
	did, err := s.agent.CreateDidKey(ctx, tenant)
	if err != nil {
		return nil, failed("make the DID of the wallet", err)
	}
	raw := anyval.Must(json.Marshal(holderRecord{Tenant: tenant, Did: did}))
	if err := s.store.Put(ctx, walletKey(tenant), []byte("1")); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	// A second adapter process may store the holder first. Its wallet
	// wins, and this tenant stays unused.
	switch cerr := s.store.CompareAndSwap(ctx, key, nil, raw); {
	case errors.Is(cerr, store.ErrConflict):
		return s.registered(ctx, key)
	case cerr != nil:
		return nil, connect.NewError(connect.CodeInternal, cerr)
	}
	return connect.NewResponse(&backendv1.RegisterResponse{WalletId: tenant, HolderDid: did}), nil
}

// registered opens the wallet that another adapter process stored for
// the holder first.
func (s *Service) registered(ctx context.Context, key string) (*connect.Response[backendv1.RegisterResponse], error) {
	rec, found, err := s.storedHolder(ctx, key)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, connect.NewError(connect.CodeInternal, errors.New("the wallet record of the holder went away"))
	}
	if err := s.store.Put(ctx, walletKey(rec.Tenant), []byte("1")); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&backendv1.RegisterResponse{WalletId: rec.Tenant, HolderDid: rec.Did}), nil
}

// storedHolder reads the record of a holder. A missing record gives
// false. A store that fails or a record the adapter cannot read gives
// Internal, so Register never overwrites a wallet it could not read.
func (s *Service) storedHolder(ctx context.Context, key string) (holderRecord, bool, error) {
	raw, err := s.store.Get(ctx, key)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return holderRecord{}, false, nil
	case err != nil:
		return holderRecord{}, false, connect.NewError(connect.CodeInternal, fmt.Errorf("read the wallet record: %w", err))
	}
	var rec holderRecord
	if json.Unmarshal(raw, &rec) != nil || rec.Tenant == "" {
		return holderRecord{}, false, connect.NewError(connect.CodeInternal, errors.New("the wallet record of the holder is damaged; restore it from a backup"))
	}
	return rec, true, nil
}

// anonCredsCredential returns the wallet credential of a finished
// AnonCreds exchange: the JSON view of ADR-061 decision 3 with the
// values of the preview. The agent cannot remove it.
func anonCredsCredential(rec credebl.AgentCredential) *backendv1.WalletCredential {
	meta := rec.AnonCreds()
	values := map[string]string{}
	for _, a := range rec.Attributes {
		values[a.Name] = a.Value
	}
	view := map[string]any{
		"type": []string{schemaName(meta.SchemaID)}, "credentialSubject": values,
		"credentialSchema": map[string]string{"id": meta.SchemaID}, "credentialDefinitionId": meta.CredDefID,
		"issuer": issuerOf(meta.CredDefID),
	}
	received := rec.UpdatedAt
	if received.IsZero() {
		received = rec.CreatedAt
	}
	return &backendv1.WalletCredential{
		Id:         anonCredsPrefix + rec.ID,
		Credential: &commonv1.Credential{Format: commonv1.Format_FORMAT_ANONCREDS, Payload: anyval.Must(json.Marshal(view))},
		Type:       schemaName(meta.SchemaID), Issuer: issuerOf(meta.CredDefID), ReceivedAt: timestamp(received), Permanent: true,
	}
}

// w3cCredential returns the wallet credential of a stored W3C
// credential: a JSON-LD object, or a JWT string.
func w3cCredential(rec credebl.AgentW3c) *backendv1.WalletCredential {
	raw := rec.Credential()
	out := &backendv1.WalletCredential{Id: w3cPrefix + rec.ID, ReceivedAt: timestamp(rec.CreatedAt)}
	var jwt string
	if json.Unmarshal(raw, &jwt) == nil {
		out.Credential = &commonv1.Credential{Format: commonv1.Format_FORMAT_JWT_VC_JSON, Payload: []byte(jwt)}
		return out
	}
	out.Credential = &commonv1.Credential{Format: commonv1.Format_FORMAT_LDP_VC, Payload: raw}
	var doc struct {
		Type   []string `json:"type"`
		Issuer any      `json:"issuer"`
	}
	if json.Unmarshal(raw, &doc) == nil {
		for _, t := range doc.Type {
			if t != "VerifiableCredential" {
				out.Type = t
			}
		}
		switch issuer := doc.Issuer.(type) {
		case string:
			out.Issuer = issuer
		case map[string]any:
			out.Issuer = anyval.As[string](issuer["id"])
		}
	}
	return out
}

// ListCredentials lists the credentials of a wallet, newest first: the
// AnonCreds credential of each finished exchange and each stored W3C
// credential (ADR-062 decision 5).
func (s *Service) ListCredentials(
	ctx context.Context, req *connect.Request[backendv1.ListCredentialsRequest],
) (*connect.Response[backendv1.ListCredentialsResponse], error) {
	tenant, err := s.wallet(ctx, req.Msg.GetWalletId())
	if err != nil {
		return nil, err
	}
	page, size, err := s.pageOf(req.Msg.GetPage())
	if err != nil {
		return nil, err
	}
	all, err := s.held(ctx, tenant)
	if err != nil {
		return nil, err
	}
	from := min((page-1)*size, len(all))
	to := min(from+size, len(all))
	return connect.NewResponse(&backendv1.ListCredentialsResponse{
		Credentials: all[from:to], Page: pageResult(page, size, len(all)),
	}), nil
}

// held returns every credential of a tenant, newest first.
func (s *Service) held(ctx context.Context, tenant string) ([]*backendv1.WalletCredential, error) {
	done, err := s.agent.Credentials(ctx, tenant, credebl.CredentialQuery{State: stateDone})
	if err != nil {
		return nil, failed("list the exchanges of the wallet", err)
	}
	stored, err := s.agent.W3cCredentials(ctx, tenant)
	if err != nil {
		return nil, failed("list the W3C credentials of the wallet", err)
	}
	sdJwt, err := s.agent.SdJwtCredentials(ctx, tenant)
	if err != nil {
		return nil, failed("list the SD-JWT credentials of the wallet", err)
	}
	mdoc, err := s.agent.MdocCredentials(ctx, tenant)
	if err != nil {
		return nil, failed("list the mdoc credentials of the wallet", err)
	}
	var out []*backendv1.WalletCredential
	for _, rec := range done {
		if rec.RecordOf("anoncreds") != "" && rec.AnonCreds() != nil {
			out = append(out, anonCredsCredential(rec))
		}
	}
	for _, rec := range stored {
		out = append(out, w3cCredential(rec))
	}
	for _, rec := range append(sdJwt, mdoc...) {
		out = append(out, storedCredential(rec))
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].GetReceivedAt().AsTime().After(out[j].GetReceivedAt().AsTime())
	})
	return out, nil
}

// isInvitation reports a DIDComm invitation URL: the didcomm scheme, or
// a URL with an out of band or a connection invitation.
func isInvitation(uri string) bool {
	u, err := url.Parse(strings.TrimSpace(uri))
	if err != nil {
		return false
	}
	if u.Scheme == "didcomm" {
		return true
	}
	q := u.Query()
	return (u.Scheme == "https" || u.Scheme == "http") && (q.Get("oob") != "" || q.Get("c_i") != "" || q.Get("d_m") != "")
}

// poll reads until done reports true, or until the attempts run out. It
// reports whether done reported true.
func (s *Service) poll(ctx context.Context, done func() (bool, error)) (bool, error) {
	for attempt := 0; attempt < s.pollAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return false, ctx.Err()
			case <-time.After(s.pollInterval):
			}
		}
		ok, err := done()
		if err != nil || ok {
			return ok, err
		}
	}
	return false, nil
}

// receive hands an invitation to the wallet and returns the thread of
// the message it carries that match accepts.
func (s *Service) receive(ctx context.Context, tenant, uri string, match func(credebl.Attached) bool, missing string) (string, error) {
	got, err := s.agent.ReceiveInvitation(ctx, tenant, strings.TrimSpace(uri), s.holderLabel)
	if err != nil {
		return "", failed("take the invitation", err)
	}
	for _, m := range got.Attached() {
		if match(m) {
			return m.ThreadID, nil
		}
	}
	return "", connect.NewError(connect.CodeInvalidArgument, errors.New(missing))
}

// AcceptOffer takes an offer into the wallet: a DIDComm offer from an
// invitation the holder scanned or from the inbox (ADR-062 decision 3),
// or an OID4VCI offer (decision 8). It waits for the credential.
func (s *Service) AcceptOffer(
	ctx context.Context, req *connect.Request[backendv1.AcceptOfferRequest],
) (*connect.Response[backendv1.AcceptOfferResponse], error) {
	tenant, err := s.wallet(ctx, req.Msg.GetWalletId())
	if err != nil {
		return nil, err
	}
	if uri := strings.TrimSpace(req.Msg.GetOfferUri()); req.Msg.GetInboxId() == "" && isOid4vciOffer(uri) {
		return s.claimOid4vci(ctx, tenant, uri, strings.TrimSpace(req.Msg.GetPin()))
	}
	record, err := s.offerRecord(ctx, tenant, req.Msg)
	if err != nil {
		return nil, err
	}
	if _, aerr := s.agent.AcceptOffer(ctx, tenant, record); aerr != nil {
		return nil, failed("accept the offer", aerr)
	}
	var last credebl.AgentCredential
	finished, err := s.poll(ctx, func() (bool, error) {
		rec, rerr := s.agent.Credential(ctx, tenant, record)
		last = rec
		return rec.State == stateDone || rec.State == stateAbandoned || rec.State == stateDeclined, rerr
	})
	switch {
	case err != nil:
		return nil, failed("read the exchange", err)
	case !finished:
		return nil, connect.NewError(connect.CodeDeadlineExceeded,
			errors.New("the issuer did not send the credential in time; it shows in the wallet when it comes"))
	case last.State != stateDone:
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("the issuer ended the exchange: %s", last.ErrorMessage))
	}
	cred, err := s.credentialOf(ctx, tenant, last)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&backendv1.AcceptOfferResponse{Credential: cred}), nil
}

// offerRecord returns the exchange of the offer to accept: the inbox
// entry, or the offer of an invitation once the wallet holds it.
func (s *Service) offerRecord(ctx context.Context, tenant string, msg *backendv1.AcceptOfferRequest) (string, error) {
	if id := strings.TrimSpace(msg.GetInboxId()); id != "" {
		rec, err := s.agent.Credential(ctx, tenant, id)
		if err != nil || rec.State != stateOfferReceived {
			return "", connect.NewError(connect.CodeNotFound, errors.New("the inbox holds no such offer"))
		}
		return rec.ID, nil
	}
	uri := strings.TrimSpace(msg.GetOfferUri())
	switch {
	case uri == "":
		return "", connect.NewError(connect.CodeInvalidArgument, errors.New("the request needs an offer_uri or an inbox_id"))
	case !isInvitation(uri):
		return "", connect.NewError(connect.CodeInvalidArgument,
			errors.New("the offer_uri is neither a DIDComm invitation nor an OID4VCI offer"))
	}
	thread, err := s.receive(ctx, tenant, uri, credebl.Attached.IsOffer, "the invitation carries no credential offer")
	if err != nil {
		return "", err
	}
	var found string
	ok, err := s.poll(ctx, func() (bool, error) {
		list, lerr := s.agent.Credentials(ctx, tenant, credebl.CredentialQuery{ThreadID: thread})
		for _, rec := range list {
			if rec.State == stateOfferReceived {
				found = rec.ID
			}
		}
		return found != "", lerr
	})
	switch {
	case err != nil:
		return "", failed("read the offer", err)
	case !ok:
		return "", connect.NewError(connect.CodeDeadlineExceeded, errors.New("the offer of the invitation did not reach the wallet in time"))
	}
	return found, nil
}

// credentialOf returns the wallet credential of a finished exchange.
func (s *Service) credentialOf(ctx context.Context, tenant string, rec credebl.AgentCredential) (*backendv1.WalletCredential, error) {
	if rec.RecordOf("anoncreds") != "" && rec.AnonCreds() != nil {
		return anonCredsCredential(rec), nil
	}
	id := rec.RecordOf("w3c")
	stored, err := s.agent.W3cCredentials(ctx, tenant)
	if err != nil {
		return nil, failed("read the W3C credentials of the wallet", err)
	}
	for _, w := range stored {
		if w.ID == id {
			return w3cCredential(w), nil
		}
	}
	return nil, connect.NewError(connect.CodeInternal, errors.New("the wallet finished the exchange but holds no credential of it"))
}

// Present answers a DIDComm proof request: from an invitation the
// holder scanned, or from the inbox (ADR-062 decision 3). The agent
// picks the credentials that answer it.
func (s *Service) Present(
	ctx context.Context, req *connect.Request[backendv1.PresentRequest],
) (*connect.Response[backendv1.PresentResponse], error) {
	tenant, err := s.wallet(ctx, req.Msg.GetWalletId())
	if err != nil {
		return nil, err
	}
	if uri, ok := oid4vpRequest(req.Msg.GetRequestUri()); req.Msg.GetInboxId() == "" && ok {
		return s.presentOid4vp(ctx, tenant, uri, req.Msg)
	}
	record, err := s.proofRecord(ctx, tenant, req.Msg)
	if err != nil {
		return nil, err
	}
	form, err := s.agent.ProofFormData(ctx, tenant, record)
	if err != nil {
		return nil, failed("read the proof request", err)
	}
	_, asked := form.Asked()
	if _, aerr := s.agent.AcceptProofRequest(ctx, tenant, record); aerr != nil {
		return nil, failed("answer the proof request", aerr)
	}
	var last credebl.AgentProof
	finished, err := s.poll(ctx, func() (bool, error) {
		rec, rerr := s.agent.Proof(ctx, tenant, record)
		last = rec
		return rec.State == stateDone || rec.State == stateAbandoned || rec.State == stateDeclined, rerr
	})
	switch {
	case err != nil:
		return nil, failed("read the proof exchange", err)
	case !finished:
		return nil, connect.NewError(connect.CodeDeadlineExceeded,
			errors.New("the wallet sent the proof, and the verifier did not answer in time"))
	}
	return connect.NewResponse(&backendv1.PresentResponse{
		Accepted: last.State == stateDone, SharedClaims: asked, VerifierState: last.State,
	}), nil
}

// proofRecord returns the exchange of the proof request to answer.
func (s *Service) proofRecord(ctx context.Context, tenant string, msg *backendv1.PresentRequest) (string, error) {
	if id := strings.TrimSpace(msg.GetInboxId()); id != "" {
		rec, err := s.agent.Proof(ctx, tenant, id)
		if err != nil || rec.State != stateRequestReceived {
			return "", connect.NewError(connect.CodeNotFound, errors.New("the inbox holds no such proof request"))
		}
		return rec.ID, nil
	}
	uri := strings.TrimSpace(msg.GetRequestUri())
	if !isInvitation(uri) {
		return "", connect.NewError(connect.CodeInvalidArgument,
			errors.New("the request_uri is neither a DIDComm invitation nor an OID4VP request"))
	}
	thread, err := s.receive(ctx, tenant, uri, credebl.Attached.IsProofRequest, "the invitation carries no proof request")
	if err != nil {
		return "", err
	}
	var found string
	ok, err := s.poll(ctx, func() (bool, error) {
		list, lerr := s.agent.Proofs(ctx, tenant, thread)
		for _, rec := range list {
			if rec.State == stateRequestReceived {
				found = rec.ID
			}
		}
		return found != "", lerr
	})
	switch {
	case err != nil:
		return "", failed("read the proof request", err)
	case !ok:
		return "", connect.NewError(connect.CodeDeadlineExceeded, errors.New("the proof request of the invitation did not reach the wallet in time"))
	}
	return found, nil
}

// DeleteCredential removes a W3C credential from the wallet. The agent
// cannot remove an AnonCreds credential (ADR-062 decision 5).
func (s *Service) DeleteCredential(
	ctx context.Context, req *connect.Request[backendv1.DeleteCredentialRequest],
) (*connect.Response[backendv1.DeleteCredentialResponse], error) {
	tenant, err := s.wallet(ctx, req.Msg.GetWalletId())
	if err != nil {
		return nil, err
	}
	id := strings.TrimSpace(req.Msg.GetCredentialId())
	if strings.HasPrefix(id, anonCredsPrefix) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("the agent of this stack cannot remove an AnonCreds credential"))
	}
	kind, record := heldKind(id)
	if kind == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the request needs a credential_id from ListCredentials"))
	}
	if err := s.agent.DeleteHeld(ctx, tenant, kind, record); err != nil {
		return nil, failed("remove the credential", err)
	}
	return connect.NewResponse(&backendv1.DeleteCredentialResponse{}), nil
}

// OpenInvitation takes an invitation that carries no message and waits
// for the connection.
func (s *Service) OpenInvitation(
	ctx context.Context, req *connect.Request[backendv1.OpenInvitationRequest],
) (*connect.Response[backendv1.OpenInvitationResponse], error) {
	tenant, err := s.wallet(ctx, req.Msg.GetWalletId())
	if err != nil {
		return nil, err
	}
	uri := strings.TrimSpace(req.Msg.GetInvitationUri())
	if !isInvitation(uri) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the text is not a DIDComm invitation"))
	}
	got, err := s.agent.ReceiveInvitation(ctx, tenant, uri, s.holderLabel)
	if err != nil {
		return nil, failed("take the invitation", err)
	}
	if got.Connection == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the invitation makes no connection"))
	}
	conn := *got.Connection
	if _, perr := s.poll(ctx, func() (bool, error) {
		rec, rerr := s.agent.Connection(ctx, tenant, conn.ID)
		if rerr == nil {
			conn.State = rec.State
		}
		return conn.State == stateCompleted, rerr
	}); perr != nil {
		return nil, failed("read the connection", perr)
	}
	return connect.NewResponse(&backendv1.OpenInvitationResponse{Connection: &backendv1.DidcommConnection{
		Id: conn.ID, Label: got.Label(), State: conn.State, CreatedAt: timestamp(conn.CreatedAt),
	}}), nil
}

// ListWalletConnections lists the connections of a wallet, newest
// first.
func (s *Service) ListWalletConnections(
	ctx context.Context, req *connect.Request[backendv1.ListWalletConnectionsRequest],
) (*connect.Response[backendv1.ListWalletConnectionsResponse], error) {
	tenant, err := s.wallet(ctx, req.Msg.GetWalletId())
	if err != nil {
		return nil, err
	}
	list, err := s.agent.Connections(ctx, tenant)
	if err != nil {
		return nil, failed("list the connections", err)
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].CreatedAt.After(list[j].CreatedAt) })
	out := make([]*backendv1.DidcommConnection, 0, len(list))
	for _, c := range list {
		out = append(out, &backendv1.DidcommConnection{Id: c.ID, Label: c.TheirLabel, State: c.State, CreatedAt: timestamp(c.CreatedAt)})
	}
	return connect.NewResponse(&backendv1.ListWalletConnectionsResponse{Connections: out}), nil
}

// ListInbox lists the offers and the proof requests that wait in a
// wallet, newest first, with what each carries.
func (s *Service) ListInbox(
	ctx context.Context, req *connect.Request[backendv1.ListInboxRequest],
) (*connect.Response[backendv1.ListInboxResponse], error) {
	tenant, err := s.wallet(ctx, req.Msg.GetWalletId())
	if err != nil {
		return nil, err
	}
	offers, err := s.agent.Credentials(ctx, tenant, credebl.CredentialQuery{State: stateOfferReceived})
	if err != nil {
		return nil, failed("list the offers", err)
	}
	proofs, err := s.agent.Proofs(ctx, tenant, "")
	if err != nil {
		return nil, failed("list the proof requests", err)
	}
	labels, err := s.connectionLabels(ctx, tenant)
	if err != nil {
		return nil, err
	}
	var items []*backendv1.InboxItem
	for _, o := range offers {
		item := &backendv1.InboxItem{Id: o.ID, Kind: backendv1.InboxItem_KIND_OFFER, ConnectionLabel: labels[o.ConnectionID], ReceivedAt: timestamp(o.CreatedAt)}
		if form, ferr := s.agent.CredentialFormData(ctx, tenant, o.ID); ferr == nil {
			for _, a := range form.OfferAttributes {
				item.Offered = append(item.Offered, &backendv1.OfferedValue{Name: a.Name, Value: a.Value})
			}
			if anon := form.Offer.AnonCreds; anon != nil {
				item.Name = schemaName(anon.SchemaID)
			}
		}
		items = append(items, item)
	}
	for _, p := range proofs {
		if p.State != stateRequestReceived {
			continue
		}
		item := &backendv1.InboxItem{Id: p.ID, Kind: backendv1.InboxItem_KIND_PROOF_REQUEST, ConnectionLabel: labels[p.ConnectionID], ReceivedAt: timestamp(p.CreatedAt)}
		if form, ferr := s.agent.ProofFormData(ctx, tenant, p.ID); ferr == nil {
			item.Name, item.Requested = form.Asked()
		}
		items = append(items, item)
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].GetReceivedAt().AsTime().After(items[j].GetReceivedAt().AsTime()) })
	return connect.NewResponse(&backendv1.ListInboxResponse{Items: items}), nil
}

// connectionLabels maps each connection of a wallet onto the label of
// the other party.
func (s *Service) connectionLabels(ctx context.Context, tenant string) (map[string]string, error) {
	list, err := s.agent.Connections(ctx, tenant)
	if err != nil {
		return nil, failed("list the connections", err)
	}
	out := make(map[string]string, len(list))
	for _, c := range list {
		out[c.ID] = c.TheirLabel
	}
	return out, nil
}

// ListDids lists the did:key identifiers of a wallet. The did:peer of
// each connection stays out.
func (s *Service) ListDids(
	ctx context.Context, req *connect.Request[backendv1.ListDidsRequest],
) (*connect.Response[backendv1.ListDidsResponse], error) {
	tenant, err := s.wallet(ctx, req.Msg.GetWalletId())
	if err != nil {
		return nil, err
	}
	list, err := s.agent.Dids(ctx, tenant)
	if err != nil {
		return nil, failed("list the DIDs", err)
	}
	var out []*backendv1.WalletDid
	for _, d := range list {
		if !strings.HasPrefix(d.Did, "did:key:") {
			continue
		}
		did := &backendv1.WalletDid{Did: d.Did, CreatedAt: timestamp(d.CreatedAt)}
		if len(d.Keys) > 0 {
			did.KeyId = d.Keys[0].KmsKeyID
		}
		out = append(out, did)
	}
	return connect.NewResponse(&backendv1.ListDidsResponse{Dids: out}), nil
}

// CreateDid makes a did:key in a wallet. The agent makes its key, so
// the request names no key.
func (s *Service) CreateDid(
	ctx context.Context, req *connect.Request[backendv1.CreateDidRequest],
) (*connect.Response[backendv1.CreateDidResponse], error) {
	tenant, err := s.wallet(ctx, req.Msg.GetWalletId())
	if err != nil {
		return nil, err
	}
	if req.Msg.GetMethod() != WalletDidMethods[0] || req.Msg.GetKeyId() != "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the wallet makes a did:key with a new key only"))
	}
	did, err := s.agent.CreateDidKey(ctx, tenant)
	if err != nil {
		return nil, failed("make the DID", err)
	}
	return connect.NewResponse(&backendv1.CreateDidResponse{Did: &backendv1.WalletDid{Did: did, Alias: req.Msg.GetAlias(), CreatedAt: timestamp(s.now())}}), nil
}
