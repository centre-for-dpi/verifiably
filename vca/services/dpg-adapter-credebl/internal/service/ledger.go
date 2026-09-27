// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/credebl"
)

// The state of an offer and the issued credentials come from the
// OID4VC issuance sessions of the agent (P6-C5). The capability answer
// lists FEATURE_ISSUANCE_STATUS and FEATURE_ISSUED_LEDGER.

// GetIssuanceStatus reads the issuance session of one offer. The offer
// id is the session id that CreateOffer returns.
func (s *Service) GetIssuanceStatus(
	ctx context.Context, req *connect.Request[backendv1.GetIssuanceStatusRequest],
) (*connect.Response[backendv1.GetIssuanceStatusResponse], error) {
	id := strings.TrimSpace(req.Msg.GetOfferId())
	if id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the request needs the offer id"))
	}
	if record, ok := strings.CutPrefix(id, DidcommOfferPrefix); ok {
		return s.didcommStatus(ctx, record)
	}
	session, err := s.client.OfferSession(ctx, id)
	if err != nil {
		return nil, failed("read the issuance session", err)
	}
	out := &backendv1.GetIssuanceStatusResponse{State: backendv1.GetIssuanceStatusResponse_STATE_PENDING}
	if session.ExpiresAt != nil {
		out.ExpiresAt = timestamppb.New(*session.ExpiresAt)
	}
	switch {
	case session.State == credebl.SessionCompleted:
		out.State = backendv1.GetIssuanceStatusResponse_STATE_ISSUED
		out.ClaimedAt = timestamp(session.UpdatedAt)
	case session.State == credebl.SessionError:
		out.State = backendv1.GetIssuanceStatusResponse_STATE_FAILED
		out.Error = session.ErrorMessage
	case session.ExpiresAt != nil && !s.now().Before(*session.ExpiresAt):
		out.State = backendv1.GetIssuanceStatusResponse_STATE_EXPIRED
	}
	return connect.NewResponse(out), nil
}

// ListIssuedCredentials lists the completed issuance sessions of one
// credential type, or one session, oldest first. A session matches the
// attributes when its offer carries each one with the same value. An
// entry carries no claim value.
func (s *Service) ListIssuedCredentials(
	ctx context.Context, req *connect.Request[backendv1.ListIssuedCredentialsRequest],
) (*connect.Response[backendv1.ListIssuedCredentialsResponse], error) {
	m := req.Msg
	typ, one := strings.TrimSpace(m.GetCredentialType()), strings.TrimSpace(m.GetCredentialId())
	if typ == "" && one == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the request needs a credential type or a credential id"))
	}
	start := 0
	if token := m.GetPage().GetPageToken(); token != "" {
		n, err := parseToken(token)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		start = n
	}
	sessions, err := s.client.OfferSessions(ctx)
	if err != nil {
		return nil, failed("list the issuance sessions", err)
	}
	var matched []*backendv1.LedgerEntry
	for _, session := range sessions {
		if session.State != credebl.SessionCompleted || (one != "" && session.ID != one) {
			continue
		}
		credType, ok := sessionType(session, typ, m.GetAttributes())
		if !ok {
			continue
		}
		entry := &backendv1.LedgerEntry{
			CredentialId: session.ID, CredentialType: credType, IssuedAt: timestamp(session.UpdatedAt),
		}
		if binding := statusBinding(session, credType); binding != nil {
			entry.Status, entry.StatusPurpose = binding, "revocation"
		}
		matched = append(matched, entry)
	}
	sort.SliceStable(matched, func(i, j int) bool {
		return matched[i].GetIssuedAt().AsTime().Before(matched[j].GetIssuedAt().AsTime())
	})
	size := int(m.GetPage().GetPageSize())
	if size <= 0 || size > s.pageSizeMax {
		size = s.pageSizeMax
	}
	out := &backendv1.ListIssuedCredentialsResponse{Page: &commonv1.PageResult{TotalSize: int64(len(matched))}}
	if start > len(matched) {
		start = len(matched)
	}
	end := start + size
	if end > len(matched) {
		end = len(matched)
	}
	out.Credentials = matched[start:end]
	if end < len(matched) {
		out.Page.NextPageToken = strconv.Itoa(end)
	}
	return connect.NewResponse(out), nil
}

// statusBinding returns the status list entry that the agent wrote into
// the credential of one type of a revocable session: an IETF Token
// Status List with the list of the agent, the index and the address a
// verifier fetches. The list belongs to the stack, so the entry sets
// dpg_list. A session with no entry gives nil (P6-C5b).
func statusBinding(session credebl.IssuanceSession, credType string) *backendv1.StatusListBinding {
	var listID string
	for _, info := range session.Metadata.StatusLists {
		if info.SupportedID == credType {
			listID = info.ListID
		}
	}
	for _, c := range session.Metadata.Credentials {
		if c.SupportedID != credType || listID == "" {
			continue
		}
		var entry credebl.StatusEntry
		if err := json.Unmarshal(c.Payload["status"], &entry); err != nil || entry.StatusList.URI == "" {
			return nil
		}
		return &backendv1.StatusListBinding{
			Kind:       backendv1.StatusListBinding_KIND_TOKEN,
			ListId:     listID,
			Index:      entry.StatusList.Index,
			PublishUrl: entry.StatusList.URI,
			DpgList:    true,
		}
	}
	return nil
}

// sessionType returns the credential type of the first credential of a
// session that has the type, or any type when typ is empty, and carries
// every attribute with its value.
func sessionType(session credebl.IssuanceSession, typ string, attributes map[string]string) (string, bool) {
	for _, c := range session.Metadata.Credentials {
		if typ != "" && c.SupportedID != typ && claimText(c.Payload["vct"]) != typ {
			continue
		}
		if !hasClaims(c.Payload, attributes) {
			continue
		}
		return c.SupportedID, true
	}
	return "", false
}

// hasClaims reports whether the payload carries each attribute with the
// value.
func hasClaims(payload map[string]json.RawMessage, attributes map[string]string) bool {
	for name, want := range attributes {
		raw, ok := payload[name]
		if !ok || claimText(raw) != want {
			return false
		}
	}
	return true
}

// claimText returns a claim value as text: a JSON string without its
// quotation marks, any other value as it stands.
func claimText(raw json.RawMessage) string {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return text
	}
	return strings.TrimSpace(string(raw))
}
