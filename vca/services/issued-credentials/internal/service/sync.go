// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/record"
)

// The limits of one sync.
const (
	// SyncPageSize is the page size a sync asks the stack for.
	SyncPageSize = 100
	// SyncMaxPages bounds the pages of one sync.
	SyncMaxPages = 20
)

// SyncQuery selects entries of the stack ledger.
type SyncQuery struct {
	// CredentialType is a configuration id or a type name.
	CredentialType string
	// Attribute is an attribute the stack indexes.
	Attribute string
	// Value is the value of the attribute. The log keeps only its salted
	// reference, as the subject of each added record.
	Value string
}

// SyncRow is one ledger entry and what the sync did with it.
type SyncRow struct {
	// Entry is the ledger entry as the stack reported it.
	Entry *backendv1.LedgerEntry
	// RecordID is the record of the log that holds the entry.
	RecordID string
	// Added is true when this sync added the record.
	Added bool
}

// Sync reads the ledger of the stack and adds each entry the log lacks
// as a record of the stack (ADR-045 decision 1). The adapter must list
// FEATURE_ISSUED_LEDGER. An added record carries the ledger id, so the
// stack changes its status later. The audit log names the actor and the
// counts.
func (s *Service) Sync(ctx context.Context, q SyncQuery) (rows []SyncRow, err error) {
	defer func() {
		added := 0
		for _, r := range rows {
			if r.Added {
				added++
			}
		}
		detail := ""
		if err == nil {
			detail = msg.T("audit.issued.sync", strconv.Itoa(len(rows)), strconv.Itoa(added))
		}
		s.opts.Audit.Record(ctx, nil, ActionSync, "", detail, err)
	}()
	if s.opts.Stack == nil || !s.opts.Stack.Has(ctx, backendv1.Feature_FEATURE_ISSUED_LEDGER) {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("the DPG adapter of the pair lists no ledger of issued credentials"))
	}
	q.CredentialType, q.Attribute, q.Value = strings.TrimSpace(q.CredentialType), strings.TrimSpace(q.Attribute), strings.TrimSpace(q.Value)
	if q.CredentialType == "" || q.Attribute == "" || q.Value == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("a sync needs a credential type, an indexed attribute, and its value"))
	}
	entries, err := s.ledger(ctx, q)
	if err != nil {
		return nil, err
	}
	known := map[string]string{}
	for _, r := range s.opts.Store.All() {
		if r.DPGCredentialID != "" {
			known[r.DPGCredentialID] = r.ID
		}
	}
	name := s.opts.Stack.Name(ctx)
	for _, e := range entries {
		if id, ok := known[e.GetCredentialId()]; ok {
			rows = append(rows, SyncRow{Entry: e, RecordID: id})
			continue
		}
		stored, aerr := s.AppendRecord(s.ledgerRecord(q, name, e))
		if aerr != nil {
			return rows, appendError(aerr)
		}
		known[e.GetCredentialId()] = stored.ID
		rows = append(rows, SyncRow{Entry: e, RecordID: stored.ID, Added: true})
	}
	return rows, nil
}

// ledger reads every page of the stack ledger up to the limit.
func (s *Service) ledger(ctx context.Context, q SyncQuery) ([]*backendv1.LedgerEntry, error) {
	var out []*backendv1.LedgerEntry
	token := ""
	for range SyncMaxPages {
		res, err := s.opts.Stack.Ledger(ctx, &backendv1.ListIssuedCredentialsRequest{
			CredentialType: q.CredentialType, Attributes: map[string]string{q.Attribute: q.Value},
			Page: &commonv1.Pagination{PageSize: SyncPageSize, PageToken: token},
		})
		if err != nil {
			if connect.CodeOf(err) == connect.CodeInvalidArgument {
				return nil, connect.NewError(connect.CodeInvalidArgument, err)
			}
			return nil, unavailable("the DPG adapter", err)
		}
		out = append(out, res.GetCredentials()...)
		if token = res.GetPage().GetNextPageToken(); token == "" {
			break
		}
	}
	return out, nil
}

// ledgerRecord builds the record of one ledger entry. The schema is the
// credential type of the query, version 1, since the ledger names no
// schema of VCA.
func (s *Service) ledgerRecord(q SyncQuery, stackName string, e *backendv1.LedgerEntry) record.Record {
	issued := s.opts.Now()
	if e.GetIssuedAt() != nil {
		issued = e.GetIssuedAt().AsTime()
	}
	r := record.Record{
		ID:              record.NewID(issued, q.CredentialType, "ledger\x00"+e.GetCredentialId()),
		SchemaID:        q.CredentialType,
		SchemaVersion:   1,
		SubjectRef:      s.SubjectRef(q.Value),
		Status:          record.Active,
		DPG:             stackName,
		IssuedAt:        issued,
		DPGCredentialID: e.GetCredentialId(),
		Binding:         BindingOf(e.GetStatus()),
	}
	if e.GetExpiresAt() != nil {
		r.ValidUntil = e.GetExpiresAt().AsTime()
	}
	return r
}
