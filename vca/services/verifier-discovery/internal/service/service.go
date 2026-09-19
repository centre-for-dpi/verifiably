// SPDX-License-Identifier: Apache-2.0

// Package service implements vca.discovery.v1.DiscoveryService
// (ADR-022 decisions 1 to 5). The crawler fills the catalogue. The read
// RPCs page over it. The template RPCs store versions that never change.
package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1/discoveryv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/catalog"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/crawl"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/template"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// DefaultPageSize is the page size when a request gives none.
const DefaultPageSize = 50

// MaxQueryLength caps the free text filter.
const MaxQueryLength = 200

// Options configure the service.
type Options struct {
	// Store holds the catalogue and the templates.
	Store *store.Store
	// Crawler reads the issuers. Nil refuses the Crawl RPC.
	Crawler *crawl.Crawler
	// PageSizeMax caps the page size. Zero means DefaultPageSize.
	PageSizeMax int
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

// Service is the DiscoveryService handler. It also satisfies the client
// interface, so the portal calls it in process.
type Service struct {
	discoveryv1connect.UnimplementedDiscoveryServiceHandler
	opts Options
}

var _ discoveryv1connect.DiscoveryServiceClient = (*Service)(nil)

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

// Crawl reads the metadata of every selected issuer now.
func (s *Service) Crawl(ctx context.Context, req *connect.Request[discoveryv1.CrawlRequest]) (*connect.Response[discoveryv1.CrawlResponse], error) {
	if s.opts.Crawler == nil || !s.opts.Crawler.Enabled() {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("service: no trust registry is configured, so the crawl cannot run"))
	}
	res, err := s.opts.Crawler.Run(ctx, req.Msg.GetCredentialIssuers())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	return connect.NewResponse(&discoveryv1.CrawlResponse{
		Crawled:   int32(res.Crawled),
		Failed:    res.Failed,
		CrawledAt: timestamppb.New(res.At),
	}), nil
}

// ListIssuers returns the crawled issuers in pages.
func (s *Service) ListIssuers(ctx context.Context, req *connect.Request[discoveryv1.ListIssuersRequest]) (*connect.Response[discoveryv1.ListIssuersResponse], error) {
	issuers, err := s.opts.Store.ListIssuers(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	page, next, err := s.page(req.Msg.GetPage(), len(issuers))
	if err != nil {
		return nil, err
	}
	out := &discoveryv1.ListIssuersResponse{Page: &commonv1.PageResult{NextPageToken: next, TotalSize: int64(len(issuers))}}
	for _, issuer := range issuers[page.from:page.to] {
		out.Issuers = append(out.Issuers, issuer.ToProto())
	}
	return connect.NewResponse(out), nil
}

// ListCredentialTypes returns the credential types of the catalogue.
func (s *Service) ListCredentialTypes(ctx context.Context, req *connect.Request[discoveryv1.ListCredentialTypesRequest]) (*connect.Response[discoveryv1.ListCredentialTypesResponse], error) {
	query := strings.TrimSpace(req.Msg.GetQuery())
	if len(query) > MaxQueryLength {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("service: the query is longer than %d characters", MaxQueryLength))
	}
	issuers, err := s.opts.Store.ListIssuers(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	format := catalog.FormatName(req.Msg.GetFormat())
	wanted := strings.TrimRight(req.Msg.GetCredentialIssuer(), "/")
	var found []*discoveryv1.CredentialType
	for _, issuer := range issuers {
		if wanted != "" && strings.TrimRight(issuer.CredentialIssuer, "/") != wanted {
			continue
		}
		for _, t := range issuer.Types {
			if !Matches(t, format, query) {
				continue
			}
			found = append(found, t.ToProto(issuer.CredentialIssuer))
		}
	}
	sort.SliceStable(found, func(i, j int) bool { return found[i].GetType() < found[j].GetType() })
	page, next, err := s.page(req.Msg.GetPage(), len(found))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&discoveryv1.ListCredentialTypesResponse{
		Types: found[page.from:page.to],
		Page:  &commonv1.PageResult{NextPageToken: next, TotalSize: int64(len(found))},
	}), nil
}

// Matches reports whether a credential type passes the filters.
func Matches(t catalog.CredentialType, format, query string) bool {
	if format != "" && t.Format != format {
		return false
	}
	if query == "" {
		return true
	}
	query = strings.ToLower(query)
	if strings.Contains(strings.ToLower(t.Type), query) {
		return true
	}
	for _, d := range t.Display {
		if strings.Contains(strings.ToLower(d.Name), query) || strings.Contains(strings.ToLower(d.Description), query) {
			return true
		}
	}
	return false
}

// GetFields returns the claims of one credential type.
func (s *Service) GetFields(ctx context.Context, req *connect.Request[discoveryv1.GetFieldsRequest]) (*connect.Response[discoveryv1.GetFieldsResponse], error) {
	issuer, err := s.opts.Store.GetIssuer(ctx, req.Msg.GetCredentialIssuer())
	if errors.Is(err, store.ErrNotFound) {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	t, ok := issuer.Find(req.Msg.GetType())
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("service: the issuer %q offers no type %q", req.Msg.GetCredentialIssuer(), req.Msg.GetType()))
	}
	out := &discoveryv1.GetFieldsResponse{JsonSchema: t.JSONSchema}
	for _, f := range t.Fields {
		out.Fields = append(out.Fields, f.ToProto())
	}
	return connect.NewResponse(out), nil
}

// CreateTemplate stores version 1 of a template.
func (s *Service) CreateTemplate(ctx context.Context, req *connect.Request[discoveryv1.CreateTemplateRequest]) (*connect.Response[discoveryv1.CreateTemplateResponse], error) {
	t := template.FromProto(req.Msg.GetTemplate())
	if t.ID == "" {
		t.ID = template.IDFrom(t.DisplayName)
	}
	if !template.ValidID(t.ID) {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("service: the template id %q is not valid", t.ID))
	}
	if _, err := s.opts.Store.LatestVersion(ctx, t.ID); err == nil {
		return nil, connect.NewError(connect.CodeAlreadyExists, fmt.Errorf("service: the template %q exists, use VersionTemplate", t.ID))
	}
	stored, err := s.build(t, 1)
	if err != nil {
		return nil, err
	}
	if err := s.opts.Store.PutTemplate(ctx, stored); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&discoveryv1.CreateTemplateResponse{Template: stored.ToProto()}), nil
}

// VersionTemplate stores the next version of a template.
func (s *Service) VersionTemplate(ctx context.Context, req *connect.Request[discoveryv1.VersionTemplateRequest]) (*connect.Response[discoveryv1.VersionTemplateResponse], error) {
	t := template.FromProto(req.Msg.GetTemplate())
	if !template.ValidID(t.ID) {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("service: the template id %q is not valid", t.ID))
	}
	latest, err := s.opts.Store.LatestVersion(ctx, t.ID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	stored, err := s.build(t, latest+1)
	if err != nil {
		return nil, err
	}
	if err := s.opts.Store.PutTemplate(ctx, stored); err != nil {
		return nil, connect.NewError(connect.CodeAborted, err)
	}
	return connect.NewResponse(&discoveryv1.VersionTemplateResponse{Template: stored.ToProto()}), nil
}

// build validates a template and stamps the version and the time.
func (s *Service) build(t template.Template, version int32) (template.Template, error) {
	built, err := template.Build(t)
	if err != nil {
		return template.Template{}, connect.NewError(connect.CodeInvalidArgument, err)
	}
	built.Version = version
	built.CreatedAt = s.opts.Now()
	return built, nil
}

// ListTemplates returns the latest version of each template.
func (s *Service) ListTemplates(ctx context.Context, req *connect.Request[discoveryv1.ListTemplatesRequest]) (*connect.Response[discoveryv1.ListTemplatesResponse], error) {
	all, err := s.opts.Store.ListTemplates(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	tenant := strings.TrimSpace(req.Msg.GetTenantId())
	found := make([]template.Template, 0, len(all))
	for _, t := range all {
		if tenant != "" && t.TenantID != tenant {
			continue
		}
		found = append(found, t)
	}
	page, next, err := s.page(req.Msg.GetPage(), len(found))
	if err != nil {
		return nil, err
	}
	out := &discoveryv1.ListTemplatesResponse{Page: &commonv1.PageResult{NextPageToken: next, TotalSize: int64(len(found))}}
	for _, t := range found[page.from:page.to] {
		out.Templates = append(out.Templates, t.ToProto())
	}
	return connect.NewResponse(out), nil
}

// GetTemplate returns one template version.
func (s *Service) GetTemplate(ctx context.Context, req *connect.Request[discoveryv1.GetTemplateRequest]) (*connect.Response[discoveryv1.GetTemplateResponse], error) {
	t, err := s.opts.Store.GetTemplate(ctx, req.Msg.GetId(), req.Msg.GetVersion())
	if errors.Is(err, store.ErrNotFound) {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&discoveryv1.GetTemplateResponse{Template: t.ToProto()}), nil
}

// DeleteTemplate removes every version of a template.
func (s *Service) DeleteTemplate(ctx context.Context, req *connect.Request[discoveryv1.DeleteTemplateRequest]) (*connect.Response[discoveryv1.DeleteTemplateResponse], error) {
	removed, err := s.opts.Store.DeleteTemplate(ctx, req.Msg.GetId())
	if errors.Is(err, store.ErrNotFound) {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&discoveryv1.DeleteTemplateResponse{VersionsRemoved: int32(removed)}), nil
}

// Versions returns the version numbers of one template. The portal uses
// it for the history page.
func (s *Service) Versions(ctx context.Context, id string) ([]int32, error) {
	return s.opts.Store.Versions(ctx, id)
}

// Catalogue returns every crawled issuer. The catalogue endpoint uses it.
func (s *Service) Catalogue(ctx context.Context) ([]catalog.Issuer, error) {
	return s.opts.Store.ListIssuers(ctx)
}

// bounds is one page of a list.
type bounds struct{ from, to int }

// page reads the pagination of a request and returns the bounds and the
// token of the next page.
func (s *Service) page(p *commonv1.Pagination, total int) (bounds, string, error) {
	size := int(p.GetPageSize())
	if size <= 0 || size > s.opts.PageSizeMax {
		size = s.opts.PageSizeMax
	}
	from := 0
	if token := p.GetPageToken(); token != "" {
		n, err := strconv.Atoi(token)
		if err != nil || n < 0 {
			return bounds{}, "", connect.NewError(connect.CodeInvalidArgument, errors.New("service: the page token is not valid"))
		}
		from = n
	}
	if from > total {
		from = total
	}
	to := from + size
	if to > total {
		to = total
	}
	next := ""
	if to < total {
		next = strconv.Itoa(to)
	}
	return bounds{from: from, to: to}, next, nil
}
