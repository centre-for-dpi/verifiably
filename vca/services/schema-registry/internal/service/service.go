// SPDX-License-Identifier: Apache-2.0

// Package service implements vca.schema.v1.SchemaService (ADR-013).
// Every state change goes through the store. Publish registers the
// version with the DPG through the injected issuer backend client
// (ADR-013 decision 3). The read RPCs build their documents with the
// metadata package.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1/schemav1connect"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/metadata"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/record"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/store"
)

// DefaultPageSize is the page size when the request gives none.
const DefaultPageSize = 50

// MaxQueryLength caps the Search query.
const MaxQueryLength = 200

// Options configure the service.
type Options struct {
	Store *store.Store
	// Backend registers published versions with the DPG. Nil skips the
	// registration and keeps the derived configuration ids.
	Backend backendv1connect.IssuerBackendServiceClient
	// Metadata carries the deployment values of the public documents.
	Metadata metadata.Options
	// PageSizeMax caps the page size. Zero means DefaultPageSize.
	PageSizeMax int
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

// Service is the SchemaService handler. It also satisfies the client
// interface, so the portal can call it in process.
type Service struct {
	schemav1connect.UnimplementedSchemaServiceHandler
	opts Options
}

var _ schemav1connect.SchemaServiceClient = (*Service)(nil)

// New builds the service.
func New(opts Options) (*Service, error) {
	if opts.Store == nil {
		return nil, errors.New("service: a store is required")
	}
	if opts.PageSizeMax <= 0 {
		opts.PageSizeMax = DefaultPageSize
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Service{opts: opts}, nil
}

// Ready reports whether the service can take traffic.
func (s *Service) Ready() bool { return s.opts.Store != nil }

// Store returns the store, so the HTTP handlers can read it.
func (s *Service) Store() *store.Store { return s.opts.Store }

// MetadataOptions returns the metadata options with the current time.
func (s *Service) MetadataOptions() metadata.Options {
	o := s.opts.Metadata
	o.Now = s.opts.Now()
	return o
}

// Create stores version 1 of a new schema.
func (s *Service) Create(_ context.Context, req *connect.Request[schemav1.CreateRequest]) (*connect.Response[schemav1.CreateResponse], error) {
	r, err := fromProto(req.Msg.GetSchema())
	if err != nil {
		return nil, err
	}
	stored, err := s.opts.Store.Create(r, s.opts.Now())
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&schemav1.CreateResponse{Schema: record.ToProto(stored)}), nil
}

// Update stores the next draft version of a schema.
func (s *Service) Update(_ context.Context, req *connect.Request[schemav1.UpdateRequest]) (*connect.Response[schemav1.UpdateResponse], error) {
	id := req.Msg.GetSchema().GetId()
	if !record.ValidID(id) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("service: the schema id is not valid"))
	}
	r, err := fromProto(req.Msg.GetSchema())
	if err != nil {
		return nil, err
	}
	stored, err := s.opts.Store.AddVersion(id, r, s.opts.Now())
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&schemav1.UpdateResponse{Schema: record.ToProto(stored)}), nil
}

// fromProto reads a schema message and checks its context extensions
// and its claim mappings. Every problem gives InvalidArgument.
func fromProto(m *schemav1.Schema) (record.Record, error) {
	r, err := record.FromProto(m)
	if err != nil {
		return record.Record{}, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if problems := metadata.CheckMapping(r); len(problems) > 0 {
		texts := make([]string, 0, len(problems))
		for _, p := range problems {
			texts = append(texts, p.Text)
		}
		return record.Record{}, connect.NewError(connect.CodeInvalidArgument, errors.New(strings.Join(texts, " ")))
	}
	return r, nil
}

// Publish moves one draft to published and registers it with the DPG.
func (s *Service) Publish(ctx context.Context, req *connect.Request[schemav1.PublishRequest]) (*connect.Response[schemav1.PublishResponse], error) {
	r, err := s.selectVersion(req.Msg.GetId(), int(req.Msg.GetVersion()), record.StateDraft)
	if err != nil {
		return nil, err
	}
	ids, err := s.register(ctx, r)
	if err != nil {
		return nil, err
	}
	now := s.opts.Now()
	stored, err := s.opts.Store.Transition(r.ID, r.Version, func(cur record.Record) (record.Record, error) {
		return cur.Publish(now, ids)
	})
	if err != nil {
		return nil, storeError(err)
	}
	resp := &schemav1.PublishResponse{Schema: record.ToProto(stored)}
	if len(stored.Formats) > 0 {
		resp.ConfigurationId = ids[stored.Formats[0]]
	}
	return connect.NewResponse(resp), nil
}

// register calls the issuer backend once per format and returns the
// configuration id of each format.
func (s *Service) register(ctx context.Context, r record.Record) (map[string]string, error) {
	ids := map[string]string{}
	display, ignored := json.Marshal(metadata.Display(r.Display))
	_ = ignored
	for _, f := range r.Formats {
		id := record.ConfigurationID(r.Type, f)
		if s.opts.Backend != nil {
			resp, err := s.opts.Backend.RegisterCredentialConfiguration(ctx, connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{
				Configuration: &backendv1.CredentialConfiguration{
					Id: id, Format: record.FormatToProto(f), Type: r.Type, JsonSchema: r.JSONSchema,
					Display: string(display), SdClaims: append([]string(nil), r.SDClaims...),
					Contexts: append([]string(nil), r.Contexts...),
				},
			}))
			if err != nil {
				return nil, connect.NewError(connect.CodeUnavailable, fmt.Errorf("service: the issuer backend did not register %s: %w", id, err))
			}
			if got := resp.Msg.GetId(); got != "" {
				id = got
			}
		}
		ids[f] = id
	}
	return ids, nil
}

// Retire moves one or every published version to retired.
func (s *Service) Retire(_ context.Context, req *connect.Request[schemav1.RetireRequest]) (*connect.Response[schemav1.RetireResponse], error) {
	id := req.Msg.GetId()
	var targets []record.Record
	if v := int(req.Msg.GetVersion()); v != 0 {
		r, err := s.selectVersion(id, v, record.StatePublished)
		if err != nil {
			return nil, err
		}
		targets = []record.Record{r}
	} else {
		for _, r := range s.opts.Store.Versions(id) {
			if r.State == record.StatePublished {
				targets = append(targets, r)
			}
		}
		if len(targets) == 0 {
			return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("service: %s has no published version", id))
		}
	}
	now := s.opts.Now()
	resp := &schemav1.RetireResponse{}
	for _, r := range targets {
		stored, err := s.opts.Store.Transition(r.ID, r.Version, func(cur record.Record) (record.Record, error) {
			return cur.Retire(now)
		})
		if err != nil {
			return nil, storeError(err)
		}
		resp.Schemas = append(resp.Schemas, record.ToProto(stored))
	}
	return connect.NewResponse(resp), nil
}

// DeleteDraft removes one draft version. Version zero selects the latest
// draft. A published or a retired version gives FailedPrecondition.
func (s *Service) DeleteDraft(_ context.Context, req *connect.Request[schemav1.DeleteDraftRequest]) (*connect.Response[schemav1.DeleteDraftResponse], error) {
	id, version := req.Msg.GetId(), int(req.Msg.GetVersion())
	if version == 0 {
		r, err := s.selectVersion(id, 0, record.StateDraft)
		if err != nil {
			return nil, err
		}
		version = r.Version
	}
	removed, gone, err := s.opts.Store.Remove(id, version, record.Record.CanDelete)
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&schemav1.DeleteDraftResponse{Schema: record.ToProto(removed), SchemaRemoved: gone}), nil
}

// selectVersion returns the version in state want. Version zero selects
// the latest version in that state.
func (s *Service) selectVersion(id string, version int, want record.State) (record.Record, error) {
	versions := s.opts.Store.Versions(id)
	if len(versions) == 0 {
		return record.Record{}, connect.NewError(connect.CodeNotFound, fmt.Errorf("service: no schema %s", id))
	}
	if version == 0 {
		for i := len(versions) - 1; i >= 0; i-- {
			if versions[i].State == want {
				return versions[i], nil
			}
		}
		return record.Record{}, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("service: %s has no %s version", id, want))
	}
	for _, r := range versions {
		if r.Version == version {
			if r.State != want {
				return record.Record{}, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("service: version %d of %s is %s, not %s", version, id, r.State, want))
			}
			return r, nil
		}
	}
	return record.Record{}, connect.NewError(connect.CodeNotFound, fmt.Errorf("service: no version %d of %s", version, id))
}

// Get returns one version.
func (s *Service) Get(_ context.Context, req *connect.Request[schemav1.GetRequest]) (*connect.Response[schemav1.GetResponse], error) {
	r, ok := s.opts.Store.Get(req.Msg.GetId(), int(req.Msg.GetVersion()))
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("service: no schema %s", req.Msg.GetId()))
	}
	return connect.NewResponse(&schemav1.GetResponse{Schema: record.ToProto(r)}), nil
}

// List returns the latest version of each schema with filters.
func (s *Service) List(_ context.Context, req *connect.Request[schemav1.ListRequest]) (*connect.Response[schemav1.ListResponse], error) {
	state := record.StateFromProto(req.Msg.GetState())
	format := ""
	if req.Msg.GetFormat() != commonv1.Format_FORMAT_UNSPECIFIED {
		f, err := record.FormatFromProto(req.Msg.GetFormat())
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		format = f
	}
	var matched []record.Record
	for _, r := range s.opts.Store.Latest() {
		if state != "" && r.State != state {
			continue
		}
		if format != "" && !r.Offers(format) {
			continue
		}
		if t := req.Msg.GetTenantId(); t != "" && r.TenantID != t {
			continue
		}
		matched = append(matched, r)
	}
	items, page, err := s.page(matched, req.Msg.GetPage())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&schemav1.ListResponse{Schemas: protoList(items), Page: page}), nil
}

// Search returns the latest versions whose texts match the query.
func (s *Service) Search(_ context.Context, req *connect.Request[schemav1.SearchRequest]) (*connect.Response[schemav1.SearchResponse], error) {
	q := strings.TrimSpace(req.Msg.GetQuery())
	if len(q) > MaxQueryLength {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("service: the query is longer than %d characters", MaxQueryLength))
	}
	var matched []record.Record
	for _, r := range s.opts.Store.Latest() {
		if r.Matches(q) {
			matched = append(matched, r)
		}
	}
	items, page, err := s.page(matched, req.Msg.GetPage())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&schemav1.SearchResponse{Schemas: protoList(items), Page: page}), nil
}

// ListPublic returns the newest published version of each schema.
func (s *Service) ListPublic(_ context.Context, req *connect.Request[schemav1.ListPublicRequest]) (*connect.Response[schemav1.ListPublicResponse], error) {
	items, page, err := s.page(s.opts.Store.LatestPublished(), req.Msg.GetPage())
	if err != nil {
		return nil, err
	}
	resp := &schemav1.ListPublicResponse{Page: page}
	for _, r := range items {
		resp.Schemas = append(resp.Schemas, record.ToPublicProto(r))
	}
	return connect.NewResponse(resp), nil
}

// GetIssuerMetadata returns the OID4VCI issuer metadata document.
func (s *Service) GetIssuerMetadata(context.Context, *connect.Request[schemav1.GetIssuerMetadataRequest]) (*connect.Response[schemav1.GetIssuerMetadataResponse], error) {
	opts := s.MetadataOptions()
	published := s.opts.Store.Published()
	doc, err := json.Marshal(metadata.IssuerMetadata(published, opts))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	resp := &schemav1.GetIssuerMetadataResponse{Metadata: string(doc), CredentialConfigurationsSupported: map[string]string{}, GeneratedAt: timestamppb.New(opts.Now)}
	for id, cfg := range metadata.Configurations(published, opts) {
		raw, err := json.Marshal(cfg)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		resp.CredentialConfigurationsSupported[id] = string(raw)
	}
	return connect.NewResponse(resp), nil
}

// GetVct returns the SD-JWT VC type metadata of one published schema.
func (s *Service) GetVct(_ context.Context, req *connect.Request[schemav1.GetVctRequest]) (*connect.Response[schemav1.GetVctResponse], error) {
	opts := s.MetadataOptions()
	r, ok := metadata.FindVct(s.opts.Store.Published(), req.Msg.GetVct(), opts)
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("service: no published schema has the vct %s", req.Msg.GetVct()))
	}
	doc, err := json.Marshal(metadata.TypeMetadata(r, opts))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&schemav1.GetVctResponse{TypeMetadata: string(doc), SchemaId: r.ID, Version: toInt32(int64(r.Version))}), nil
}

// ListVersions returns every version of one schema, newest first.
func (s *Service) ListVersions(_ context.Context, req *connect.Request[schemav1.ListVersionsRequest]) (*connect.Response[schemav1.ListVersionsResponse], error) {
	versions := s.opts.Store.Versions(req.Msg.GetId())
	if len(versions) == 0 {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("service: no schema %s", req.Msg.GetId()))
	}
	resp := &schemav1.ListVersionsResponse{}
	for i := len(versions) - 1; i >= 0; i-- {
		resp.Schemas = append(resp.Schemas, record.ToProto(versions[i]))
	}
	return connect.NewResponse(resp), nil
}

// page cuts one page out of items.
func (s *Service) page(items []record.Record, p *commonv1.Pagination) ([]record.Record, *commonv1.PageResult, error) {
	size := int(p.GetPageSize())
	if size <= 0 {
		size = DefaultPageSize
	}
	if size > s.opts.PageSizeMax {
		size = s.opts.PageSizeMax
	}
	offset := 0
	if tok := p.GetPageToken(); tok != "" {
		n, err := strconv.Atoi(tok)
		if err != nil || n < 0 {
			return nil, nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("service: page token %q is not valid", tok))
		}
		offset = n
	}
	result := &commonv1.PageResult{TotalSize: int64(len(items))}
	if offset > len(items) {
		offset = len(items)
	}
	end := offset + size
	if end < len(items) {
		result.NextPageToken = strconv.Itoa(end)
	} else {
		end = len(items)
	}
	return items[offset:end], result, nil
}

func protoList(items []record.Record) []*schemav1.Schema {
	out := make([]*schemav1.Schema, 0, len(items))
	for _, r := range items {
		out = append(out, record.ToProto(r))
	}
	return out
}

// storeError maps a store error to a Connect error.
func storeError(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return connect.NewError(connect.CodeNotFound, err)
	}
	if strings.HasPrefix(err.Error(), "record: ") {
		return connect.NewError(connect.CodeFailedPrecondition, err)
	}
	return connect.NewError(connect.CodeInternal, err)
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
