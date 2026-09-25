// SPDX-License-Identifier: Apache-2.0

// Package service implements vca.trust.v1.TrustService (ADR-011).
// It edits the store, republishes every enabled method after each edit,
// and answers TrustLookup from the signature checked cache.
package service

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/did"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	sharedstore "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/entry"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/etsi"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/federation"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/keys"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/lookup"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/publish"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/store"
)

// DefaultPageSize is the page size when the request gives none.
const DefaultPageSize = 50

// Options configure the service.
type Options struct {
	Store      *store.Store
	Ring       *keys.Ring
	Publishers []publish.Publisher
	Cache      *lookup.Cache
	// Federation holds the external registries. Nil builds one in
	// memory that reaches public https hosts only.
	Federation *federation.Federation
	// Resolver resolves DIDs on UpsertEntry. Nil skips resolution.
	Resolver *did.Resolver
	BaseURL  string
	Issuer   publish.Issuer
	ListTTL  time.Duration
	// PageSizeMax caps the page size. Zero means DefaultPageSize.
	PageSizeMax int
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
	// Audit keeps one event for each trust change and each registry
	// change (ADR-039 decision 1). Nil keeps the events in memory.
	Audit *auditlog.Log
}

// Name is the service name that every audit event carries.
const Name = "trust-registry"

// The audit actions of the service.
const (
	ActionUpsertEntry    = "trust.UpsertEntry"
	ActionDeleteEntry    = "trust.DeleteEntry"
	ActionImportEtsi     = "trust.ImportEtsi"
	ActionAddRegistry    = "trust.AddRegistry"
	ActionRemoveRegistry = "trust.RemoveRegistry"
	ActionSyncRegistry   = "trust.SyncRegistry"
)

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
	if opts.Audit == nil {
		// A memory store with a clock cannot fail to open.
		opts.Audit = anyval.Must(auditlog.New(sharedstore.Memory(), opts.Now))
	}
	if opts.Federation == nil {
		fed, err := federation.New(federation.Options{Now: opts.Now})
		if err != nil {
			return nil, err
		}
		opts.Federation = fed
	}
	s := &Service{opts: opts}
	if _, err := s.republish(); err != nil {
		return nil, err
	}
	return s, nil
}

// Audit returns the audit store of the service.
func (s *Service) Audit() *auditlog.Log { return s.opts.Audit }

// Snapshot returns the published files. It implements httpapi.Source.
func (s *Service) Snapshot() *publish.Snapshot { return s.snap.Load() }

// JWKSJSON returns the key set. It implements httpapi.Source.
func (s *Service) JWKSJSON() []byte { return s.opts.Ring.JWKSJSON() }

// Ready reports whether a publication exists.
func (s *Service) Ready() bool { return s.snap.Load() != nil }

// republish signs every enabled method and refreshes the cache. The
// lists never carry a pending entry.
func (s *Service) republish() ([]publish.Publication, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	in := publish.Input{
		Entries:  entry.Published(s.opts.Store.List()),
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
// The audit log records the change, also when it fails.
func (s *Service) UpsertEntry(ctx context.Context, req *connect.Request[trustv1.UpsertEntryRequest]) (res *connect.Response[trustv1.UpsertEntryResponse], err error) {
	target, detail := entryTarget(req.Msg.GetEntry().GetIdentifier()), ""
	defer func() { s.opts.Audit.Record(ctx, req.Header(), ActionUpsertEntry, target, detail, err) }()
	e, err := entry.FromProto(req.Msg.GetEntry())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if werr := s.opts.Federation.CheckWritable(e.ID()); werr != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, werr)
	}
	if e.DID != "" && s.opts.Resolver != nil {
		if _, serr := s.opts.Resolver.Resolve(ctx, e.DID); serr != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("service: the DID %s does not resolve: %w", e.DID, serr))
		}
	}
	stored, _, err := s.opts.Store.Upsert(e, s.opts.Now())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if _, perr := s.republish(); perr != nil {
		return nil, connect.NewError(connect.CodeInternal, perr)
	}
	detail = msg.T("audit.trust.entry", string(stored.Status))
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

// DeleteEntry removes one entry and republishes. The audit log records
// the change, also when it fails.
func (s *Service) DeleteEntry(ctx context.Context, req *connect.Request[trustv1.DeleteEntryRequest]) (res *connect.Response[trustv1.DeleteEntryResponse], err error) {
	defer func() {
		s.opts.Audit.Record(ctx, req.Header(), ActionDeleteEntry, entryTarget(req.Msg.GetIdentifier()), "", err)
	}()
	id, err := entry.IDFromProto(req.Msg.GetIdentifier())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if werr := s.opts.Federation.CheckWritable(id); werr != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, werr)
	}
	found, err := s.opts.Store.Delete(id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if !found {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("service: no entry for %s", id))
	}
	if _, perr := s.republish(); perr != nil {
		return nil, connect.NewError(connect.CodeInternal, perr)
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
			EntryCount:  toInt32(int64(p.EntryCount)),
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
	// The local lists answer first. When they do not name the entity, the
	// copies of the external registries answer, with their provenance.
	if r.Outcome != lookup.Trusted && r.Outcome != lookup.Untrusted {
		if ext, ok := s.opts.Federation.Lookup(id, role, req.Msg.GetCredentialType(), at); ok {
			return connect.NewResponse(externalAnswer(ext)), nil
		}
	}
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

// externalAnswer is the lookup answer of an external registry.
func externalAnswer(ext federation.Result) *trustv1.TrustLookupResponse {
	resp := &trustv1.TrustLookupResponse{
		Outcome: outcomeProto(lookup.Outcome(ext.Outcome)),
		Reason:  ext.Reason,
		Provenance: &trustv1.TrustLookupResponse_Provenance{
			Method:       lookupMethod(ext.Method),
			ListUrl:      ext.ListURL,
			KeyId:        ext.SignedBy,
			CheckedAt:    timestamppb.New(ext.CheckedAt),
			Cached:       true,
			RegistryId:   ext.Registry.ID,
			RegistryName: ext.Registry.Name,
		},
	}
	if ext.Entry != nil {
		resp.Entry = entry.ToProto(*ext.Entry)
	}
	return resp
}

// ImportEtsi reads a TS 119 612 XML list and stores its entities. The
// audit log records an import that is not a dry run.
func (s *Service) ImportEtsi(ctx context.Context, req *connect.Request[trustv1.ImportEtsiRequest]) (res *connect.Response[trustv1.ImportEtsiResponse], err error) {
	defer func() {
		if req.Msg.GetDryRun() {
			return
		}
		detail := ""
		if err == nil {
			detail = msg.T("audit.trust.import", strconv.Itoa(int(res.Msg.GetCreated())), strconv.Itoa(int(res.Msg.GetUpdated())))
		}
		s.opts.Audit.Record(ctx, req.Header(), ActionImportEtsi, "", detail, err)
	}()
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
		if err := s.opts.Federation.CheckWritable(e.ID()); err != nil {
			resp.Skipped = append(resp.Skipped, err.Error())
			continue
		}
		if _, exists := s.opts.Store.Get(e.ID()); exists {
			resp.Updated++
		} else {
			resp.Created++
		}
		if req.Msg.GetDryRun() {
			continue
		}
		if _, _, uerr := s.opts.Store.Upsert(e, now); uerr != nil {
			return nil, connect.NewError(connect.CodeInternal, uerr)
		}
	}
	if !req.Msg.GetDryRun() && len(entries) > 0 {
		if _, perr := s.republish(); perr != nil {
			return nil, connect.NewError(connect.CodeInternal, perr)
		}
	}
	return connect.NewResponse(resp), nil
}

// entryTarget returns the id of an entry for the audit log, or "" when
// the identifier is not valid.
func entryTarget(id *trustv1.TrustEntry_Identifier) string {
	out, err := entry.IDFromProto(id)
	if err != nil {
		return ""
	}
	return out
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

// toInt32 converts n to int32. A value out of range clamps to the limit.
func toInt32(n int64) int32 {
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	if n < math.MinInt32 {
		return math.MinInt32
	}
	return int32(n)
}
