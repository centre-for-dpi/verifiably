// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/inji"
)

// revocationPurpose is the one status purpose the Certify configuration
// of the stack allows.
const revocationPurpose = "revocation"

// Revoke sets the revocation bit of one credential of the Certify
// ledger through the credential status API. Certify writes the status
// list credential in its next scheduled run.
//
// The request names the credential by its ledger id. A credential that
// carries a status entry of VCA has no such id; the status service that
// owns its list changes it (ADR-018, ADR-019).
func (s *Service) Revoke(
	ctx context.Context, req *connect.Request[backendv1.RevokeRequest],
) (*connect.Response[backendv1.RevokeResponse], error) {
	if s.certify == nil {
		return nil, unimplemented("this adapter has no Inji Certify URL, so it changes no credential status")
	}
	switch req.Msg.GetAction() {
	case backendv1.RevokeRequest_ACTION_SUSPEND, backendv1.RevokeRequest_ACTION_REINSTATE:
		return nil, unimplemented("the Certify configuration of the stack allows the revocation purpose only, " +
			"so the adapter does not suspend a credential")
	}
	id := strings.TrimSpace(req.Msg.GetCredentialId())
	if id == "" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New(
			"the credential has no id in the Certify ledger; the status service that owns its list changes it"))
	}
	entry, err := s.certify.UpdateStatus(ctx, id, revocationPurpose, true)
	if errors.Is(err, inji.ErrCredentialNotFound) {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("revoke %s: %w", id, err))
	}
	if err != nil {
		return nil, configError("revoke the credential", err)
	}
	at := entry.StatusTimestamp.Time
	if at.IsZero() {
		at = s.now().UTC()
	}
	return connect.NewResponse(&backendv1.RevokeResponse{RevokedAt: timestamp(at)}), nil
}

// ListIssuedCredentials searches the ledger of Inji Certify. Certify
// needs the issuer DID, the type list, and one indexed attribute. It
// returns every match at once, so the adapter pages the answer.
func (s *Service) ListIssuedCredentials(
	ctx context.Context, req *connect.Request[backendv1.ListIssuedCredentialsRequest],
) (*connect.Response[backendv1.ListIssuedCredentialsResponse], error) {
	if s.certify == nil {
		return nil, unimplemented("this adapter has no Inji Certify URL, so it reads no ledger")
	}
	m := req.Msg
	if strings.TrimSpace(m.GetCredentialType()) == "" || !hasAttribute(m.GetAttributes()) {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the Certify ledger search needs a credential type and one indexed attribute with a value"))
	}
	start := 0
	if token := m.GetPage().GetPageToken(); token != "" {
		n, err := parseToken(token)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		start = n
	}
	did, err := s.certify.ReadDIDDocument(ctx)
	if err != nil {
		return nil, failed("read the issuer DID document", err)
	}
	typ, err := s.ledgerType(ctx, m.GetCredentialType())
	if err != nil {
		return nil, err
	}
	entries, err := s.certify.SearchLedger(ctx, inji.LedgerSearch{
		IssuerID: did.ID, CredentialType: typ, CredentialID: m.GetCredentialId(), Attributes: m.GetAttributes(),
	})
	if err != nil {
		return nil, configError("search the ledger", err)
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Issued().Before(entries[j].Issued()) })
	size := int(m.GetPage().GetPageSize())
	if size <= 0 || size > s.pageSizeMax {
		size = s.pageSizeMax
	}
	out := &backendv1.ListIssuedCredentialsResponse{Page: &commonv1.PageResult{TotalSize: int64(len(entries))}}
	if start >= len(entries) {
		return connect.NewResponse(out), nil
	}
	end := start + size
	if end < len(entries) {
		out.Page.NextPageToken = fmt.Sprintf("%d", end)
	} else {
		end = len(entries)
	}
	for _, e := range entries[start:end] {
		out.Credentials = append(out.Credentials, ledgerEntry(e))
	}
	return connect.NewResponse(out), nil
}

// hasAttribute reports whether one attribute has a name and a value.
func hasAttribute(m map[string]string) bool {
	for k, v := range m {
		if strings.TrimSpace(k) != "" && strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

// ledgerType returns the type list the ledger stores for a credential
// type: a list stays as it is; a configuration id gives the types of its
// definition; a bare type name joins VerifiableCredential.
func (s *Service) ledgerType(ctx context.Context, typ string) (string, error) {
	if strings.Contains(typ, ",") {
		return inji.LedgerType(strings.Split(typ, ",")), nil
	}
	meta, err := s.certify.Metadata(ctx)
	if err != nil {
		return "", failed("read the issuer metadata", err)
	}
	if cfg, ok := meta.Configurations[typ]; ok && cfg.CredentialDefinition != nil && len(cfg.CredentialDefinition.Type) > 0 {
		return inji.LedgerType(cfg.CredentialDefinition.Type), nil
	}
	return inji.LedgerType([]string{typ, "VerifiableCredential"}), nil
}

// ledgerEntry maps one Certify answer onto the contract.
func ledgerEntry(e inji.LedgerEntry) *backendv1.LedgerEntry {
	out := &backendv1.LedgerEntry{
		CredentialId: e.CredentialID, CredentialType: e.CredentialType, StatusPurpose: e.StatusPurpose,
		IssuedAt: timestamp(e.Issued()), ExpiresAt: timestamp(e.ExpirationDate.Time),
		StatusChangedAt: timestamp(e.StatusTimestamp.Time),
	}
	if e.StatusListCredentialURL != "" {
		out.Status = &backendv1.StatusListBinding{
			Kind: backendv1.StatusListBinding_KIND_BITSTRING, ListId: e.StatusListCredentialURL,
			Index: e.StatusListIndex, PublishUrl: e.StatusListCredentialURL,
		}
	}
	return out
}
