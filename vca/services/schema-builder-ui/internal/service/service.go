// SPDX-License-Identifier: Apache-2.0

// Package service implements vca.schemabuilder.v1.SchemaBuilderService
// (ADR-014). PreviewCredential renders the three live view tabs with the
// pure preview function of vc-core (ADR-014 decisions 1 and 3). Import
// reads a JSON Schema document or a DPG catalogue entry and saves a draft
// version in the schema registry (ADR-014 decisions 5 and 6).
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/preview"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1/schemav1connect"
	schemabuilderv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schemabuilder/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/schemabuilder/v1/schemabuilderv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/draft"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/pdfcache"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/wire"
)

// MaxSampleBytes caps the sample document one preview request can carry.
const MaxSampleBytes = 64 * 1024

// MaxDocumentBytes caps the JSON Schema document one import can carry.
const MaxDocumentBytes = 256 * 1024

// Options configure the service.
type Options struct {
	// Registry stores the draft versions. Import needs it.
	Registry schemav1connect.SchemaServiceClient
	// Catalog reads the credential types of a DPG. Nil refuses a
	// catalogue import.
	Catalog backendv1connect.CatalogBackendServiceClient
	// PDF holds the rendered preview documents. Nil builds a new cache.
	PDF *pdfcache.Cache
	// Issuer is the issuer identifier the preview credential carries.
	Issuer string
}

// Service is the SchemaBuilderService handler. It also satisfies the
// client interface, so the pages can call it in process.
type Service struct {
	schemabuilderv1connect.UnimplementedSchemaBuilderServiceHandler
	opts Options
}

var _ schemabuilderv1connect.SchemaBuilderServiceClient = (*Service)(nil)

// New builds the service.
func New(opts Options) (*Service, error) {
	if opts.Registry == nil {
		return nil, errors.New("service: a SchemaService client is required")
	}
	if opts.PDF == nil {
		opts.PDF = pdfcache.New(0)
	}
	return &Service{opts: opts}, nil
}

// WithCatalog returns a copy of the service that reads the catalogue
// of another DPG adapter. The copy shares the registry and the PDF cache.
func (s *Service) WithCatalog(c backendv1connect.CatalogBackendServiceClient) *Service {
	cp := *s
	cp.opts.Catalog = c
	return &cp
}

// Ready reports whether the service can take traffic.
func (s *Service) Ready() bool { return s.opts.Registry != nil }

// Cache returns the PDF preview cache, so the wiring can register it.
func (s *Service) Cache() *pdfcache.Cache { return s.opts.PDF }

// Render renders one preview and stores the PDF document in the cache.
// The pages call it directly, so they do not go through Connect.
func (s *Service) Render(schema preview.Schema, sample map[string]any, opts preview.Options) (preview.Preview, error) {
	if opts.Issuer == "" {
		opts.Issuer = s.opts.Issuer
	}
	p, err := preview.PreviewCredential(schema, sample, opts)
	if err != nil {
		return preview.Preview{}, err
	}
	s.opts.PDF.Put(p.PDFRef, preview.PDF(p))
	return p, nil
}

// PreviewCredential renders the sample credential, the wallet card, and
// the PDF preview reference.
func (s *Service) PreviewCredential(_ context.Context, req *connect.Request[schemabuilderv1.PreviewCredentialRequest]) (*connect.Response[schemabuilderv1.PreviewCredentialResponse], error) {
	raw := req.Msg.GetSample()
	if len(raw) > MaxSampleBytes {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("service: the sample is longer than %d bytes", MaxSampleBytes))
	}
	sample := map[string]any{}
	if strings.TrimSpace(raw) != "" {
		if err := json.Unmarshal([]byte(raw), &sample); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("service: the sample is not a JSON object: %w", err))
		}
	}
	schema := wire.PreviewSchema(req.Msg.GetSchema())
	p, err := s.Render(schema, sample, preview.Options{
		Format: wire.FormatFromProto(req.Msg.GetFormat()),
		Locale: req.Msg.GetLocale(),
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return connect.NewResponse(Response(p)), nil
}

// Response maps a preview to the RPC message.
func Response(p preview.Preview) *schemabuilderv1.PreviewCredentialResponse {
	card := &schemabuilderv1.PreviewCredentialResponse_WalletCard{
		Title: p.Card.Title, Description: p.Card.Description, LogoUri: p.Card.LogoURI,
		BackgroundColor: p.Card.BackgroundColor, TextColor: p.Card.TextColor,
	}
	for _, row := range p.Card.Rows {
		card.Rows = append(card.Rows, &schemabuilderv1.PreviewCredentialResponse_Row{
			Label: row.Label, Value: row.Value, SelectivelyDisclosable: row.SelectivelyDisclosable,
		})
	}
	return &schemabuilderv1.PreviewCredentialResponse{
		CredentialJson: p.CredentialJSON,
		WalletCard:     card,
		PdfPreviewRef:  p.PDFRef,
		Problems:       append([]string(nil), p.Problems...),
	}
}

// SampleData builds sample values from a JSON Schema document.
func (s *Service) SampleData(_ context.Context, req *connect.Request[schemabuilderv1.SampleDataRequest]) (*connect.Response[schemabuilderv1.SampleDataResponse], error) {
	values, err := preview.SampleData(req.Msg.GetJsonSchema())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	raw, err := json.MarshalIndent(values, "", "  ")
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&schemabuilderv1.SampleDataResponse{Sample: string(raw)}), nil
}

// Import converts a source into a draft version in the registry.
func (s *Service) Import(ctx context.Context, req *connect.Request[schemabuilderv1.ImportRequest]) (*connect.Response[schemabuilderv1.ImportResponse], error) {
	d, warnings, err := s.Read(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	stored, err := s.Save(ctx, d)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&schemabuilderv1.ImportResponse{Schema: stored, Warnings: warnings}), nil
}

// Read builds a draft from an import request without saving it. The
// import page calls it, so the author can check the draft first.
func (s *Service) Read(ctx context.Context, req *schemabuilderv1.ImportRequest) (draft.Draft, []string, error) {
	switch src := req.GetSource().(type) {
	case *schemabuilderv1.ImportRequest_JsonSchema:
		if len(src.JsonSchema) > MaxDocumentBytes {
			return draft.Draft{}, nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("service: the document is longer than %d bytes", MaxDocumentBytes))
		}
		d, warnings, err := draft.FromDocument(src.JsonSchema)
		if err != nil {
			return draft.Draft{}, nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		if t := strings.TrimSpace(req.GetType()); t != "" {
			d.Type = t
		}
		if d.Type == "" {
			d.Type = d.Title
		}
		return d.Normalize(), warnings, nil
	case *schemabuilderv1.ImportRequest_CatalogEntryId:
		return s.fromCatalog(ctx, src.CatalogEntryId, req.GetType())
	}
	return draft.Draft{}, nil, connect.NewError(connect.CodeInvalidArgument, errors.New("service: the import names no source"))
}

// fromCatalog reads one DPG catalogue entry and builds a draft.
func (s *Service) fromCatalog(ctx context.Context, id, typ string) (draft.Draft, []string, error) {
	cfg, err := s.Entry(ctx, id)
	if err != nil {
		return draft.Draft{}, nil, err
	}
	if strings.TrimSpace(typ) == "" {
		typ = cfg.GetType()
	}
	d, warnings, err := draft.FromCatalog(typ, cfg.GetJsonSchema(), cfg.GetDisplay(), cfg.GetSdClaims(), wire.FormatFromProto(cfg.GetFormat()))
	if err != nil {
		return draft.Draft{}, nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return d, warnings, nil
}

// Entry returns one catalogue entry by id.
func (s *Service) Entry(ctx context.Context, id string) (*backendv1.CredentialConfiguration, error) {
	list, err := s.Catalog(ctx)
	if err != nil {
		return nil, err
	}
	for _, cfg := range list {
		if cfg.GetId() == id {
			return cfg, nil
		}
	}
	return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("service: the DPG catalogue has no entry %s", id))
}

// Catalog returns the credential types of the DPG.
func (s *Service) Catalog(ctx context.Context) ([]*backendv1.CredentialConfiguration, error) {
	if s.opts.Catalog == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("service: this deployment has no DPG catalogue"))
	}
	resp, err := s.opts.Catalog.ListCredentialTypes(ctx, connect.NewRequest(&backendv1.ListCredentialTypesRequest{}))
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, fmt.Errorf("service: the DPG catalogue did not answer: %w", err))
	}
	return resp.Msg.GetConfigurations(), nil
}

// Save stores the draft in the registry (ADR-014 decision 5). A draft
// with an id becomes the next version of that schema. A draft without an
// id becomes version 1 of a new schema. Publish stays a registry action,
// so the builder never touches the DPG.
func (s *Service) Save(ctx context.Context, d draft.Draft) (*schemav1.Schema, error) {
	d = d.Normalize()
	if problems := d.Problems(); len(problems) > 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("service: "+strings.Join(problems, " ")))
	}
	message := wire.SchemaProto(d)
	if d.ID == "" {
		resp, err := s.opts.Registry.Create(ctx, connect.NewRequest(&schemav1.CreateRequest{Schema: message}))
		if err != nil {
			return nil, saveError(err)
		}
		return resp.Msg.GetSchema(), nil
	}
	resp, err := s.opts.Registry.Update(ctx, connect.NewRequest(&schemav1.UpdateRequest{Schema: message}))
	if err != nil {
		return nil, saveError(err)
	}
	return resp.Msg.GetSchema(), nil
}

// saveError keeps a Connect error from the registry and wraps any other.
func saveError(err error) error {
	var cerr *connect.Error
	if errors.As(err, &cerr) {
		return cerr
	}
	return connect.NewError(connect.CodeUnavailable, fmt.Errorf("service: the schema registry did not answer: %w", err))
}
