// SPDX-License-Identifier: Apache-2.0

// Package service implements vca.trust.v1.TrustService (ADR-011).
// It edits the store, republishes every enabled method after each edit,
// and answers TrustLookup from the signature checked cache.
package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"github.com/centre-for-dpi/vc-adapters/core/did"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/entry"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/etsi"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/keys"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/lookup"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/publish"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/store"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// DefaultPageSize is the page size when the request gives none.
const DefaultPageSize = 50

// Options configure the service.
type Options struct {
	Store      *store.Store
	Ring       *keys.Ring
	Publishers []publish.Publisher
	Cache      *lookup.Cache
	// Resolver resolves DIDs on UpsertEntry. Nil skips resolution.
	Resolver *did.Resolver
	BaseURL  string
	Issuer   publish.Issuer
	ListTTL  time.Duration
	// PageSizeMax caps the page size. Zero means DefaultPageSize.
	PageSizeMax int
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

// Service is the TrustService handler.
type Service struct {
	trustv1connect.UnimplementedTrustServiceHandler
	opts Options
	mu   sync.Mutex
	snap atomic.Pointer[publish.Snapshot]
}

// New builds the service. It publishes once so that the endpoints serve
// files from the start.
func New(opts Options) (*Service, error) {
	if opts.Store == nil || opts.Ring == nil || opts.Cache == nil || len(opts.Publishers) == 0 {
		return nil, errors.New("service: store, ring, cache, and one publisher are required")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.PageSizeMax <= 0 {
		opts.PageSizeMax = DefaultPageSize
	}
	if opts.ListTTL <= 0 {
		opts.ListTTL = 24 * time.Hour
	}
	s := &Service{opts: opts}
	if _, err := s.republish(); err != nil {
		return nil, err
	}
	return s, nil
}

// Snapshot returns the published files. It implements httpapi.Source.
func (s *Service) Snapshot() *publish.Snapshot { return s.snap.Load() }

// JWKSJSON returns the key set. It implements httpapi.Source.
func (s *Service) JWKSJSON() []byte { return s.opts.Ring.JWKSJSON() }

// Ready reports whether a publication exists.
func (s *Service) Ready() bool { return s.snap.Load() != nil }

// republish signs every enabled method and refreshes the cache.
func (s *Service) republish() ([]publish.Publication, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	in := publish.Input{
		Entries:  s.opts.Store.List(),
		Sequence: s.opts.Store.Revision(),
		Now:      s.opts.Now(),
		TTL:      s.opts.ListTTL,
		BaseURL:  s.opts.BaseURL,
		Issuer:   s.opts.Issuer,
		Signer:   s.opts.Ring.Active(),
	}
	pubs := make([]publish.Publication, 0, len(s.opts.Publishers))
	for _, p := range s.opts.Publishers {
		pub, err := p.Publish(in)
		if err != nil {
			return nil, fmt.Errorf("service: publish %s: %w", p.Method(), err)
		}
		pubs = append(pubs, pub)
	}
	snap, err := publish.NewSnapshot(pubs...)
	if err != nil {
		return nil, err
	}
	if err := s.opts.Cache.Refresh(snap); err != nil {
		return nil, fmt.Errorf("service: check published lists: %w", err)
	}
	s.snap.Store(snap)
	return pubs, nil
}

// UpsertEntry validates, resolves the DID, stores, and republishes.
func (s *Service) UpsertEntry(ctx context.Context, req *connect.Request[trustv1.UpsertEntryRequest]) (*connect.Response[trustv1.UpsertEntryResponse], error) {
	e, err := entry.FromProto(req.Msg.GetEntry())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if e.DID != "" && s.opts.Resolver != nil {
		if _, err := s.opts.Resolver.Resolve(ctx, e.DID); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("service: the DID %s does not resolve: %w", e.DID, err))
		}
	}
	stored, _, err := s.opts.Store.Upsert(e, s.opts.Now())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if _, err := s.republish(); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&trustv1.UpsertEntryResponse{Entry: entry.ToProto(stored)}), nil
}

// GetEntry returns one entry.
func (s *Service) GetEntry(_ context.Context, req *connect.Request[trustv1.GetEntryRequest]) (*connect.Response[trustv1.GetEntryResponse], error) {
	id, err := entry.IDFromProto(req.Msg.GetIdentifier())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	e, ok := s.opts.Store.Get(id)
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("service: no entry for %s", id))
	}
	return connect.NewResponse(&trustv1.GetEntryResponse{Entry: entry.ToProto(e)}), nil
}

// ListEntries returns a page of entries with optional filters.
// The page token is the offset of the page as a decimal number.
func (s *Service) ListEntries(_ context.Context, req *connect.Request[trustv1.ListEntriesRequest]) (*connect.Response[trustv1.ListEntriesResponse], error) {
	msg := req.Msg
	size := int(msg.GetPage().GetPageSize())
	if size <= 0 {
		size = DefaultPageSize
	}
	if size > s.opts.PageSizeMax {
		size = s.opts.PageSizeMax
	}
	offset := 0
	if tok := msg.GetPage().GetPageToken(); tok != "" {
		n, err := strconv.Atoi(tok)
		if err != nil || n < 0 {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("service: page token %q is not valid", tok))
		}
		offset = n
	}
	var role entry.Role
	if msg.GetRole() != commonv1.Role_ROLE_UNSPECIFIED {
		r, err := entry.RoleFromProto(msg.GetRole())
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		role = r
	}
	var status entry.Status
	if msg.GetStatus() != trustv1.Status_STATUS_UNSPECIFIED {
		st, err := entry.StatusFromProto(msg.GetStatus())
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		status = st
	}
	var matched []entry.Entry
	for _, e := range s.opts.Store.List() {
		if (role != "" && e.Role != role) || (status != "" && e.Status != status) {
			continue
		}
		if t := msg.GetCredentialType(); t != "" && !e.Covers(t) {
			continue
		}
		matched = append(matched, e)
	}
	resp := &trustv1.ListEntriesResponse{Page: &commonv1.PageResult{TotalSize: int64(len(matched))}}
	if offset > len(matched) {
		offset = len(matched)
	}
	end := offset + size
	if end < len(matched) {
		resp.Page.NextPageToken = strconv.Itoa(end)
	} else {
		end = len(matched)
	}
	for _, e := range matched[offset:end] {
		resp.Entries = append(resp.Entries, entry.ToProto(e))
	}
	return connect.NewResponse(resp), nil
}

// DeleteEntry removes one entry and republishes.
func (s *Service) DeleteEntry(_ context.Context, req *connect.Request[trustv1.DeleteEntryRequest]) (*connect.Response[trustv1.DeleteEntryResponse], error) {
	id, err := entry.IDFromProto(req.Msg.GetIdentifier())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	found, err := s.opts.Store.Delete(id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if !found {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("service: no entry for %s", id))
	}
	if _, err := s.republish(); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&trustv1.DeleteEntryResponse{}), nil
}

// Publish forces a new publication of one method or of every method.
func (s *Service) Publish(_ context.Context, req *connect.Request[trustv1.PublishRequest]) (*connect.Response[trustv1.PublishResponse], error) {
	want := methodName(req.Msg.GetMethod())
	if req.Msg.GetMethod() != trustv1.Method_METHOD_UNSPECIFIED && !s.enabled(want) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("service: the method %s is not enabled", want))
	}
	pubs, err := s.republish()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	resp := &trustv1.PublishResponse{}
	for _, p := range pubs {
		if want != "" && p.Method != want {
			continue
		}
		resp.Publications = append(resp.Publications, &trustv1.PublishResponse_Publication{
			Method:      methodProto(p.Method),
			Url:         p.URL,
			EntryCount:  int32(p.EntryCount),
			PublishedAt: timestamppb.New(p.PublishedAt),
			KeyId:       p.KeyID,
		})
	}
	return connect.NewResponse(resp), nil
}

// TrustLookup answers from the cache with provenance.
func (s *Service) TrustLookup(_ context.Context, req *connect.Request[trustv1.TrustLookupRequest]) (*connect.Response[trustv1.TrustLookupResponse], error) {
	id, err := entry.IDFromProto(req.Msg.GetIdentifier())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	role, err := entry.RoleFromProto(req.Msg.GetRole())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	at := s.opts.Now()
	if req.Msg.GetAt() != nil {
		at = req.Msg.GetAt().AsTime()
	}
	r := s.opts.Cache.Lookup(id, role, req.Msg.GetCredentialType(), at)
	resp := &trustv1.TrustLookupResponse{Outcome: outcomeProto(r.Outcome), Reason: r.Reason}
	if r.Entry != nil {
		resp.Entry = entry.ToProto(*r.Entry)
	}
	if r.Method != "" {
		resp.Provenance = &trustv1.TrustLookupResponse_Provenance{
			Method:    methodProto(r.Method),
			ListUrl:   r.ListURL,
			KeyId:     r.KeyID,
			CheckedAt: timestamppb.New(r.CheckedAt),
			Cached:    true,
		}
	}
	return connect.NewResponse(resp), nil
}

// ImportEtsi reads a TS 119 612 XML list and stores its entities.
func (s *Service) ImportEtsi(_ context.Context, req *connect.Request[trustv1.ImportEtsiRequest]) (*connect.Response[trustv1.ImportEtsiResponse], error) {
	tl, err := etsi.ParseTrustedList(req.Msg.GetXml())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	now := s.opts.Now()
	entries, skipped := etsi.Import(tl, now)
	resp := &trustv1.ImportEtsiResponse{}
	for _, sk := range skipped {
		resp.Skipped = append(resp.Skipped, sk.String())
	}
	for _, e := range entries {
		if _, exists := s.opts.Store.Get(e.ID()); exists {
			resp.Updated++
		} else {
			resp.Created++
		}
		if req.Msg.GetDryRun() {
			continue
		}
		if _, _, err := s.opts.Store.Upsert(e, now); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
	}
	if !req.Msg.GetDryRun() && len(entries) > 0 {
		if _, err := s.republish(); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
	}
	return connect.NewResponse(resp), nil
}

func (s *Service) enabled(method string) bool {
	for _, p := range s.opts.Publishers {
		if p.Method() == method {
			return true
		}
	}
	return false
}

func methodName(m trustv1.Method) string {
	switch m {
	case trustv1.Method_METHOD_ETSI:
		return publish.MethodEtsi
	case trustv1.Method_METHOD_DEDI:
		return publish.MethodDedi
	}
	return ""
}

func methodProto(name string) trustv1.Method {
	switch name {
	case publish.MethodEtsi:
		return trustv1.Method_METHOD_ETSI
	case publish.MethodDedi:
		return trustv1.Method_METHOD_DEDI
	}
	return trustv1.Method_METHOD_UNSPECIFIED
}

func outcomeProto(o lookup.Outcome) trustv1.TrustLookupResponse_Outcome {
	switch o {
	case lookup.Trusted:
		return trustv1.TrustLookupResponse_OUTCOME_TRUSTED
	case lookup.Untrusted:
		return trustv1.TrustLookupResponse_OUTCOME_UNTRUSTED
	case lookup.Unknown:
		return trustv1.TrustLookupResponse_OUTCOME_UNKNOWN
	}
	return trustv1.TrustLookupResponse_OUTCOME_UNAVAILABLE
}
