// SPDX-License-Identifier: Apache-2.0

// Package service implements vca.datasource.v1.DataSourceService
// (ADR-015 decisions 1 to 6). Every RPC reads the principal that the
// authz interceptor put on the context and checks the role rules of the
// source before it reads any row.
package service

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/mapping"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	datasourcev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1/datasourcev1connect"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/authz"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/csvsrc"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/httpsrc"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/reader"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/secrets"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/source"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/sqlsrc"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/table"
)

// Limits of the service.
const (
	// DefaultPageSize is the page size when the request gives none.
	DefaultPageSize = 50
	// MaxPreviewRows caps PreviewRows, as the proto says.
	MaxPreviewRows = 20
	// DefaultPreviewRows is the row count when the request gives none.
	DefaultPreviewRows = 10
	// SampleRows is the number of rows PreviewFields reads for types.
	SampleRows = 200
)

// SchemaProperties returns the property names of a schema version. The
// service uses it to report unmapped properties. Nil reports none.
type SchemaProperties func(ctx context.Context, schemaID string, version int) ([]string, error)

// Options configure the service.
type Options struct {
	Store  *store.Store
	Reader reader.Reader
	// Schema returns schema properties. Nil reports no unmapped property.
	Schema SchemaProperties
	// PageSizeMax caps the page size. Zero means DefaultPageSize.
	PageSizeMax int
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

// Service is the DataSourceService handler.
type Service struct {
	datasourcev1connect.UnimplementedDataSourceServiceHandler
	opts Options
}

// New builds the service.
func New(opts Options) (*Service, error) {
	if opts.Store == nil {
		return nil, errors.New("service: store is required")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.PageSizeMax <= 0 {
		opts.PageSizeMax = DefaultPageSize
	}
	return &Service{opts: opts}, nil
}

// Ready reports whether the service can take traffic.
func (s *Service) Ready() bool { return true }

// Create stores one source. It needs the admin or operator role.
func (s *Service) Create(ctx context.Context, req *connect.Request[datasourcev1.CreateRequest]) (*connect.Response[datasourcev1.CreateResponse], error) {
	p, err := s.editor(ctx)
	if err != nil {
		return nil, err
	}
	src := source.FromProto(req.Msg.GetSource())
	if src.TenantID == "" {
		src.TenantID = p.Tenant
	}
	if !s.sameTenant(p, src) {
		return nil, denied(authz.Admin)
	}
	stored, err := s.opts.Store.Create(src, s.opts.Now())
	if err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&datasourcev1.CreateResponse{Source: source.ToProto(stored)}), nil
}

// Update replaces one source. It needs the admin or operator role.
func (s *Service) Update(ctx context.Context, req *connect.Request[datasourcev1.UpdateRequest]) (*connect.Response[datasourcev1.UpdateResponse], error) {
	p, err := s.editor(ctx)
	if err != nil {
		return nil, err
	}
	src := source.FromProto(req.Msg.GetSource())
	old, err := s.visible(p, src.ID)
	if err != nil {
		return nil, err
	}
	if src.TenantID == "" {
		src.TenantID = old.TenantID
	}
	if !s.sameTenant(p, src) {
		return nil, denied(authz.Admin)
	}
	stored, err := s.opts.Store.Update(src, s.opts.Now())
	if err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&datasourcev1.UpdateResponse{Source: source.ToProto(stored)}), nil
}

// List returns the sources the principal may view, in pages.
func (s *Service) List(ctx context.Context, req *connect.Request[datasourcev1.ListRequest]) (*connect.Response[datasourcev1.ListResponse], error) {
	p, err := authz.Require(ctx)
	if err != nil {
		return nil, err
	}
	var all []source.Source
	for _, src := range s.opts.Store.List() {
		if req.Msg.GetTenantId() != "" && src.TenantID != req.Msg.GetTenantId() {
			continue
		}
		if !s.sameTenant(p, src) || !p.Allowed(src.Access.ViewFields) {
			continue
		}
		all = append(all, src)
	}
	start, end, next, err := page(req.Msg.GetPage(), len(all), s.opts.PageSizeMax)
	if err != nil {
		return nil, err
	}
	resp := &datasourcev1.ListResponse{Page: &commonv1.PageResult{NextPageToken: next, TotalSize: int64(len(all))}}
	for _, src := range all[start:end] {
		resp.Sources = append(resp.Sources, source.ToProto(src))
	}
	return connect.NewResponse(resp), nil
}

// Get returns one source.
func (s *Service) Get(ctx context.Context, req *connect.Request[datasourcev1.GetRequest]) (*connect.Response[datasourcev1.GetResponse], error) {
	p, err := authz.Require(ctx)
	if err != nil {
		return nil, err
	}
	src, err := s.visible(p, req.Msg.GetId())
	if err != nil {
		return nil, err
	}
	if err := s.allow(p, src.Access.ViewFields, "view fields"); err != nil {
		return nil, err
	}
	return connect.NewResponse(&datasourcev1.GetResponse{Source: source.ToProto(src)}), nil
}

// Delete removes one source and its mappings.
func (s *Service) Delete(ctx context.Context, req *connect.Request[datasourcev1.DeleteRequest]) (*connect.Response[datasourcev1.DeleteResponse], error) {
	p, err := s.editor(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := s.visible(p, req.Msg.GetId()); err != nil {
		return nil, err
	}
	if err := s.opts.Store.Delete(req.Msg.GetId()); err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&datasourcev1.DeleteResponse{}), nil
}

// PreviewFields returns the field names and inferred types of a source.
func (s *Service) PreviewFields(ctx context.Context, req *connect.Request[datasourcev1.PreviewFieldsRequest]) (*connect.Response[datasourcev1.PreviewFieldsResponse], error) {
	tb, err := s.read(ctx, req.Msg.GetSourceId(), func(a source.Access) []string { return a.ViewFields }, "view fields")
	if err != nil {
		return nil, err
	}
	resp := &datasourcev1.PreviewFieldsResponse{}
	for _, f := range table.Infer(tb, SampleRows, table.DefaultMasker) {
		resp.Fields = append(resp.Fields, &datasourcev1.Field{Name: f.Name, Type: string(f.Type), Example: f.Example})
	}
	return connect.NewResponse(resp), nil
}

// PreviewRows returns at most limit masked rows.
func (s *Service) PreviewRows(ctx context.Context, req *connect.Request[datasourcev1.PreviewRowsRequest]) (*connect.Response[datasourcev1.PreviewRowsResponse], error) {
	tb, err := s.read(ctx, req.Msg.GetSourceId(), func(a source.Access) []string { return a.PreviewRows }, "preview rows")
	if err != nil {
		return nil, err
	}
	limit := int(req.Msg.GetLimit())
	if limit <= 0 {
		limit = DefaultPreviewRows
	}
	if limit > MaxPreviewRows {
		limit = MaxPreviewRows
	}
	resp := &datasourcev1.PreviewRowsResponse{TotalRows: tb.Total}
	for _, row := range table.DefaultMasker.MaskRows(table.Limit(tb.Rows, limit)) {
		resp.Rows = append(resp.Rows, &datasourcev1.PreviewRowsResponse_Row{Values: row})
	}
	return connect.NewResponse(resp), nil
}

// SetFieldMap stores the mapping of a source and schema pair.
func (s *Service) SetFieldMap(ctx context.Context, req *connect.Request[datasourcev1.SetFieldMapRequest]) (*connect.Response[datasourcev1.SetFieldMapResponse], error) {
	p, err := s.editor(ctx)
	if err != nil {
		return nil, err
	}
	fm := FieldMapFromProto(req.Msg.GetFieldMap())
	src, err := s.visible(p, fm.SourceID)
	if err != nil {
		return nil, err
	}
	if err := s.allow(p, src.Access.ViewFields, "view fields"); err != nil {
		return nil, err
	}
	if fm.SchemaID == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("schema_id is empty"))
	}
	if err := s.opts.Store.SetFieldMap(fm); err != nil {
		return nil, toConnect(err)
	}
	resp := &datasourcev1.SetFieldMapResponse{FieldMap: FieldMapToProto(fm)}
	if s.opts.Schema != nil {
		props, err := s.opts.Schema(ctx, fm.SchemaID, fm.SchemaVersion)
		if err != nil {
			return nil, unavailable("schema service", err)
		}
		resp.UnmappedProperties = mapping.Unmapped(fm, props)
	}
	return connect.NewResponse(resp), nil
}

// GetFieldMap returns the mapping of a source and schema pair.
func (s *Service) GetFieldMap(ctx context.Context, req *connect.Request[datasourcev1.GetFieldMapRequest]) (*connect.Response[datasourcev1.GetFieldMapResponse], error) {
	p, err := authz.Require(ctx)
	if err != nil {
		return nil, err
	}
	src, err := s.visible(p, req.Msg.GetSourceId())
	if err != nil {
		return nil, err
	}
	if err := s.allow(p, src.Access.ViewFields, "view fields"); err != nil {
		return nil, err
	}
	fm, ok := s.opts.Store.GetFieldMap(src.ID, req.Msg.GetSchemaId())
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("no field map for source %s and schema %s", src.ID, req.Msg.GetSchemaId()))
	}
	return connect.NewResponse(&datasourcev1.GetFieldMapResponse{FieldMap: FieldMapToProto(fm)}), nil
}

// RunBulk checks the issue rule and then reports that the issuance
// service runs bulk jobs (ADR-015 decision 7 is outside this service).
func (s *Service) RunBulk(ctx context.Context, req *connect.Request[datasourcev1.RunBulkRequest], _ *connect.ServerStream[datasourcev1.RunBulkResponse]) error {
	p, err := authz.Require(ctx)
	if err != nil {
		return err
	}
	src, err := s.visible(p, req.Msg.GetSourceId())
	if err != nil {
		return err
	}
	if err := s.allow(p, src.Access.Issue, "issue"); err != nil {
		return err
	}
	return connect.NewError(connect.CodeUnimplemented, errors.New("bulk jobs run in the issuance service (ADR-015 decision 7)"))
}

// read loads the source, checks the rule that pick selects, and reads it.
func (s *Service) read(ctx context.Context, id string, pick func(source.Access) []string, action string) (table.Table, error) {
	p, err := authz.Require(ctx)
	if err != nil {
		return table.Table{}, err
	}
	src, err := s.visible(p, id)
	if err != nil {
		return table.Table{}, err
	}
	if serr := s.allow(p, pick(src.Access), action); serr != nil {
		return table.Table{}, serr
	}
	tb, err := s.opts.Reader.Read(ctx, src)
	if err != nil {
		return table.Table{}, toConnect(err)
	}
	return tb, nil
}

// editor returns the principal when it holds the admin or operator role.
func (s *Service) editor(ctx context.Context) (authz.Principal, error) {
	p, err := authz.Require(ctx)
	if err != nil {
		return p, err
	}
	if !p.HasRole(authz.Admin) && !p.HasRole(authz.Operator) {
		return p, denied(authz.Operator)
	}
	return p, nil
}

// visible returns the source with id when p may know it exists.
func (s *Service) visible(p authz.Principal, id string) (source.Source, error) {
	src, ok := s.opts.Store.Get(id)
	if !ok || !s.sameTenant(p, src) {
		return source.Source{}, connect.NewError(connect.CodeNotFound, fmt.Errorf("source %s not found", id))
	}
	return src, nil
}

// sameTenant reports whether p may see src. An admin sees every tenant.
// A principal with no tenant sees every source.
func (s *Service) sameTenant(p authz.Principal, src source.Source) bool {
	return p.Tenant == "" || src.TenantID == "" || p.Tenant == src.TenantID || p.HasRole(authz.Admin)
}

func (s *Service) allow(p authz.Principal, rule []string, action string) error {
	if p.Allowed(rule) {
		return nil
	}
	want := authz.Admin
	if len(rule) > 0 {
		want = rule[0]
	}
	return denied(want + " (" + action + ")")
}

// denied returns a VCA-302 permission error.
func denied(role string) error {
	err := connect.NewError(connect.CodePermissionDenied, errors.New("you do not have permission to do this"))
	attach(err, "VCA-302", "Ask an administrator for the "+role+" role.", map[string]string{"role": role})
	return err
}

// unavailable returns a VCA-401 error for a source the service cannot reach.
func unavailable(name string, cause error) error {
	err := connect.NewError(connect.CodeUnavailable, fmt.Errorf("the service cannot reach %s: %w", name, cause))
	attach(err, "VCA-401", "Wait one minute, then try again. If the problem stays, contact the operator.", map[string]string{"source": name})
	return err
}

// tooLarge returns a VCA-303 error.
func tooLarge(cause error) error {
	err := connect.NewError(connect.CodeResourceExhausted, fmt.Errorf("the request is too large: %w", cause))
	attach(err, "VCA-303", "Send a smaller request.", nil)
	return err
}

func attach(err *connect.Error, code, next string, params map[string]string) {
	detail, derr := connect.NewErrorDetail(&commonv1.Error{Code: code, Message: err.Message(), NextStep: next, Params: params})
	if derr == nil {
		err.AddDetail(detail)
	}
}

// toConnect maps a package error to a Connect error.
func toConnect(err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, source.ErrInvalid), errors.Is(err, mapping.ErrEmptyProperty), errors.Is(err, mapping.ErrDuplicateRule),
		errors.Is(err, mapping.ErrNoSourceField), errors.Is(err, mapping.ErrTooManyFields), errors.Is(err, mapping.ErrUnknownTransform),
		errors.Is(err, mapping.ErrMissingParam), errors.Is(err, csvsrc.ErrBadOptions), errors.Is(err, reader.ErrCSVRef),
		errors.Is(err, httpsrc.ErrMethod), errors.Is(err, sqlsrc.ErrNotSelect):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, csvsrc.ErrTooLarge), errors.Is(err, httpsrc.ErrTooLarge), errors.Is(err, sqlsrc.ErrTooMany):
		return tooLarge(err)
	case errors.Is(err, httpsrc.ErrScheme), errors.Is(err, httpsrc.ErrHost), errors.Is(err, httpsrc.ErrUserInfo),
		errors.Is(err, httpsrc.ErrPrivateIP), errors.Is(err, httpsrc.ErrNoAllowlist), errors.Is(err, httpsrc.ErrRedirect):
		return connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, secrets.ErrBadRef), errors.Is(err, secrets.ErrNotFound), errors.Is(err, secrets.ErrUnsupported),
		errors.Is(err, sqlsrc.ErrDriver), errors.Is(err, reader.ErrNoCSVDir), errors.Is(err, httpsrc.ErrBadMTLS):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, csvsrc.ErrBadCSV), errors.Is(err, csvsrc.ErrNotUTF8), errors.Is(err, httpsrc.ErrNotJSON), errors.Is(err, httpsrc.ErrRowsPath):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	}
	return unavailable("the source", err)
}

// page returns the slice bounds of a page and the next token.
func page(p *commonv1.Pagination, total, max int) (start, end int, next string, err error) {
	size := int(p.GetPageSize())
	if size <= 0 || size > max {
		size = max
	}
	if tok := p.GetPageToken(); tok != "" {
		n, err := strconv.Atoi(tok)
		if err != nil || n < 0 {
			return 0, 0, "", connect.NewError(connect.CodeInvalidArgument, errors.New("page_token is not valid"))
		}
		start = n
	}
	if start > total {
		start = total
	}
	end = start + size
	if end >= total {
		return start, total, "", nil
	}
	return start, end, strconv.Itoa(end), nil
}

// transformNames maps the proto enum to the core transform names.
var transformNames = map[datasourcev1.Transform]mapping.Transform{
	datasourcev1.Transform_TRANSFORM_UNSPECIFIED: mapping.Copy,
	datasourcev1.Transform_TRANSFORM_TRIM:        mapping.Trim,
	datasourcev1.Transform_TRANSFORM_DATE_FORMAT: mapping.DateFormat,
	datasourcev1.Transform_TRANSFORM_CONSTANT:    mapping.Constant,
	datasourcev1.Transform_TRANSFORM_CONCAT:      mapping.Concat,
	datasourcev1.Transform_TRANSFORM_UPPER:       mapping.Upper,
	datasourcev1.Transform_TRANSFORM_LOWER:       mapping.Lower,
}

// FieldMapFromProto converts a proto field map. An unknown transform
// keeps its number as a name, so Validate rejects it.
func FieldMapFromProto(p *datasourcev1.FieldMap) mapping.FieldMap {
	fm := mapping.FieldMap{SourceID: p.GetSourceId(), SchemaID: p.GetSchemaId(), SchemaVersion: int(p.GetSchemaVersion())}
	for _, r := range p.GetRules() {
		t, ok := transformNames[r.GetTransform()]
		if !ok {
			t = mapping.Transform(strconv.Itoa(int(r.GetTransform())))
		}
		fm.Rules = append(fm.Rules, mapping.Rule{Property: r.GetProperty(), SourceFields: r.GetSourceFields(), Transform: t, Params: r.GetParams()})
	}
	return fm
}

// FieldMapToProto converts a core field map.
func FieldMapToProto(fm mapping.FieldMap) *datasourcev1.FieldMap {
	p := &datasourcev1.FieldMap{SourceId: fm.SourceID, SchemaId: fm.SchemaID, SchemaVersion: toInt32(int64(fm.SchemaVersion))}
	for _, r := range fm.Rules {
		t := datasourcev1.Transform_TRANSFORM_UNSPECIFIED
		for k, v := range transformNames {
			if v == r.Transform {
				t = k
			}
		}
		p.Rules = append(p.Rules, &datasourcev1.FieldMap_Rule{Property: r.Property, SourceFields: r.SourceFields, Transform: t, Params: r.Params})
	}
	return p
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
