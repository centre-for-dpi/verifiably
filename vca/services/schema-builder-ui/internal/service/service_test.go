// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/centre-for-dpi/vc-adapters/core/preview"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	schemabuilderv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schemabuilder/v1"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/draft"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/wire"
)

const document = `{"type":"object","title":"Diploma","properties":{"given_name":{"type":"string","title":"Given name"},"grade":{"type":"integer"}},"required":["given_name"]}`

func build(t *testing.T, registry *fake.Registry, catalog *fake.Catalog) *service.Service {
	t.Helper()
	opts := service.Options{Registry: registry, Issuer: "https://issuer.test"}
	if catalog != nil {
		opts.Catalog = catalog
	}
	svc, err := service.New(opts)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return svc
}

func TestNewNeedsRegistry(t *testing.T) {
	if _, err := service.New(service.Options{}); err == nil {
		t.Error("a service without a registry must fail")
	}
}

func TestReadyAndCache(t *testing.T) {
	svc := build(t, &fake.Registry{}, nil)
	if !svc.Ready() {
		t.Error("the service must be ready")
	}
	if svc.Cache() == nil {
		t.Error("the service must have a cache")
	}
}

func sampleDraft() draft.Draft {
	d, _, err := draft.FromDocument(document)
	if err != nil {
		panic(err)
	}
	d.Type = "Diploma"
	return d.Normalize()
}

func TestPreviewCredential(t *testing.T) {
	svc := build(t, &fake.Registry{}, nil)
	d := sampleDraft()
	resp, err := svc.PreviewCredential(context.Background(), connect.NewRequest(&schemabuilderv1.PreviewCredentialRequest{
		Schema: wire.SchemaProto(d),
		Sample: `{"given_name":"Ada","grade":1}`,
		Format: commonv1.Format_FORMAT_DC_SD_JWT,
		Locale: "en",
	}))
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	msg := resp.Msg
	if !strings.Contains(msg.GetCredentialJson(), "Ada") {
		t.Errorf("credential = %s", msg.GetCredentialJson())
	}
	if !strings.Contains(msg.GetCredentialJson(), "https://issuer.test") {
		t.Errorf("the issuer option must reach the credential: %s", msg.GetCredentialJson())
	}
	if msg.GetWalletCard().GetTitle() != "Diploma" {
		t.Errorf("card = %+v", msg.GetWalletCard())
	}
	if len(msg.GetWalletCard().GetRows()) != 2 {
		t.Errorf("rows = %+v", msg.GetWalletCard().GetRows())
	}
	if msg.GetPdfPreviewRef() == "" {
		t.Error("the preview must have a PDF reference")
	}
	if _, ok := svc.Cache().Get(msg.GetPdfPreviewRef()); !ok {
		t.Error("the PDF document must reach the cache")
	}
	if len(msg.GetProblems()) != 0 {
		t.Errorf("problems = %v", msg.GetProblems())
	}
}

func TestPreviewCredentialEmptySample(t *testing.T) {
	svc := build(t, &fake.Registry{}, nil)
	resp, err := svc.PreviewCredential(context.Background(), connect.NewRequest(&schemabuilderv1.PreviewCredentialRequest{
		Schema: wire.SchemaProto(sampleDraft()), Sample: "  ",
	}))
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if len(resp.Msg.GetProblems()) == 0 {
		t.Error("an empty sample must report the missing required claim")
	}
}

func TestPreviewCredentialRejectsBadInput(t *testing.T) {
	svc := build(t, &fake.Registry{}, nil)
	cases := []struct {
		name string
		req  *schemabuilderv1.PreviewCredentialRequest
	}{
		{"long sample", &schemabuilderv1.PreviewCredentialRequest{Sample: strings.Repeat("x", service.MaxSampleBytes+1)}},
		{"bad sample", &schemabuilderv1.PreviewCredentialRequest{Schema: wire.SchemaProto(sampleDraft()), Sample: "["}},
		{"bad schema", &schemabuilderv1.PreviewCredentialRequest{Schema: &schemav1.Schema{Type: "T", JsonSchema: "{"}, Sample: "{}"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := svc.PreviewCredential(context.Background(), connect.NewRequest(c.req))
			if connect.CodeOf(err) != connect.CodeInvalidArgument {
				t.Errorf("err = %v, want invalid argument", err)
			}
		})
	}
}

func TestRenderKeepsGivenIssuer(t *testing.T) {
	svc := build(t, &fake.Registry{}, nil)
	p, err := svc.Render(sampleDraft().PreviewSchema(), map[string]any{"given_name": "Ada"}, preview.Options{Issuer: "https://other.test"})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(p.CredentialJSON, "https://other.test") {
		t.Errorf("credential = %s", p.CredentialJSON)
	}
}

func TestSampleData(t *testing.T) {
	svc := build(t, &fake.Registry{}, nil)
	resp, err := svc.SampleData(context.Background(), connect.NewRequest(&schemabuilderv1.SampleDataRequest{JsonSchema: document}))
	if err != nil {
		t.Fatalf("sample: %v", err)
	}
	if !strings.Contains(resp.Msg.GetSample(), "given_name") {
		t.Errorf("sample = %s", resp.Msg.GetSample())
	}
	if _, err := svc.SampleData(context.Background(), connect.NewRequest(&schemabuilderv1.SampleDataRequest{JsonSchema: "{"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("err = %v, want invalid argument", err)
	}
}

func TestImportFromDocument(t *testing.T) {
	registry := &fake.Registry{}
	svc := build(t, registry, nil)
	resp, err := svc.Import(context.Background(), connect.NewRequest(&schemabuilderv1.ImportRequest{
		Source: &schemabuilderv1.ImportRequest_JsonSchema{JsonSchema: document},
		Type:   "DiplomaCredential",
	}))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if registry.Created != 1 {
		t.Errorf("created = %d", registry.Created)
	}
	if resp.Msg.GetSchema().GetType() != "DiplomaCredential" {
		t.Errorf("schema = %+v", resp.Msg.GetSchema())
	}
	if resp.Msg.GetSchema().GetId() == "" {
		t.Error("the stored draft must carry an id")
	}
}

func TestImportTypeFallsBackToTitle(t *testing.T) {
	svc := build(t, &fake.Registry{}, nil)
	d, _, err := svc.Read(context.Background(), &schemabuilderv1.ImportRequest{
		Source: &schemabuilderv1.ImportRequest_JsonSchema{JsonSchema: document},
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if d.Type != "Diploma" {
		t.Errorf("type = %q", d.Type)
	}
}

func TestReadRejectsBadSources(t *testing.T) {
	svc := build(t, &fake.Registry{}, nil)
	cases := []struct {
		name string
		req  *schemabuilderv1.ImportRequest
	}{
		{"no source", &schemabuilderv1.ImportRequest{}},
		{"long document", &schemabuilderv1.ImportRequest{Source: &schemabuilderv1.ImportRequest_JsonSchema{JsonSchema: strings.Repeat("x", service.MaxDocumentBytes+1)}}},
		{"broken document", &schemabuilderv1.ImportRequest{Source: &schemabuilderv1.ImportRequest_JsonSchema{JsonSchema: "{"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := svc.Read(context.Background(), c.req); connect.CodeOf(err) != connect.CodeInvalidArgument {
				t.Errorf("err = %v, want invalid argument", err)
			}
		})
	}
}

func entries() []*backendv1.CredentialConfiguration {
	return []*backendv1.CredentialConfiguration{{
		Id: "diploma_mso_mdoc", Format: commonv1.Format_FORMAT_MSO_MDOC, Type: "DiplomaCredential",
		JsonSchema: document, Display: `[{"Name":"Diploma card","Locale":"en"}]`, SdClaims: []string{"grade"},
	}}
}

func TestImportFromCatalog(t *testing.T) {
	registry := &fake.Registry{}
	catalog := &fake.Catalog{Entries: entries()}
	svc := build(t, registry, catalog)
	resp, err := svc.Import(context.Background(), connect.NewRequest(&schemabuilderv1.ImportRequest{
		Source: &schemabuilderv1.ImportRequest_CatalogEntryId{CatalogEntryId: "diploma_mso_mdoc"},
	}))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if registry.Created != 1 {
		t.Errorf("created = %d", registry.Created)
	}
	m := resp.Msg.GetSchema()
	if m.GetType() != "DiplomaCredential" {
		t.Errorf("type = %q", m.GetType())
	}
	if len(m.GetFormats()) != 1 || m.GetFormats()[0] != commonv1.Format_FORMAT_MSO_MDOC {
		t.Errorf("formats = %v", m.GetFormats())
	}
	if len(m.GetSdClaims()) != 1 || m.GetSdClaims()[0] != "grade" {
		t.Errorf("sd claims = %v", m.GetSdClaims())
	}
	if m.GetDisplay()[0].GetName() != "Diploma card" {
		t.Errorf("display = %+v", m.GetDisplay())
	}
}

func TestImportFromCatalogKeepsGivenType(t *testing.T) {
	svc := build(t, &fake.Registry{}, &fake.Catalog{Entries: entries()})
	d, _, err := svc.Read(context.Background(), &schemabuilderv1.ImportRequest{
		Source: &schemabuilderv1.ImportRequest_CatalogEntryId{CatalogEntryId: "diploma_mso_mdoc"},
		Type:   "Other",
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if d.Type != "Other" {
		t.Errorf("type = %q", d.Type)
	}
}

func TestCatalogProblems(t *testing.T) {
	t.Run("no catalog", func(t *testing.T) {
		svc := build(t, &fake.Registry{}, nil)
		if _, err := svc.Catalog(context.Background()); connect.CodeOf(err) != connect.CodeFailedPrecondition {
			t.Errorf("err = %v, want failed precondition", err)
		}
	})
	t.Run("catalog fails", func(t *testing.T) {
		svc := build(t, &fake.Registry{}, &fake.Catalog{Err: errors.New("down")})
		if _, err := svc.Catalog(context.Background()); connect.CodeOf(err) != connect.CodeUnavailable {
			t.Errorf("err = %v, want unavailable", err)
		}
	})
	t.Run("unknown entry", func(t *testing.T) {
		svc := build(t, &fake.Registry{}, &fake.Catalog{Entries: entries()})
		if _, err := svc.Entry(context.Background(), "nope"); connect.CodeOf(err) != connect.CodeNotFound {
			t.Errorf("err = %v, want not found", err)
		}
	})
	t.Run("entry with a broken document", func(t *testing.T) {
		bad := []*backendv1.CredentialConfiguration{{Id: "bad", JsonSchema: "{"}}
		svc := build(t, &fake.Registry{}, &fake.Catalog{Entries: bad})
		_, _, err := svc.Read(context.Background(), &schemabuilderv1.ImportRequest{
			Source: &schemabuilderv1.ImportRequest_CatalogEntryId{CatalogEntryId: "bad"},
		})
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("err = %v, want invalid argument", err)
		}
	})
	t.Run("import with an unknown entry", func(t *testing.T) {
		svc := build(t, &fake.Registry{}, &fake.Catalog{Entries: entries()})
		_, err := svc.Import(context.Background(), connect.NewRequest(&schemabuilderv1.ImportRequest{
			Source: &schemabuilderv1.ImportRequest_CatalogEntryId{CatalogEntryId: "nope"},
		}))
		if connect.CodeOf(err) != connect.CodeNotFound {
			t.Errorf("err = %v, want not found", err)
		}
	})
}

func TestSaveNewAndNextVersion(t *testing.T) {
	registry := &fake.Registry{}
	svc := build(t, registry, nil)
	d := sampleDraft()
	if _, err := svc.Save(context.Background(), d); err != nil {
		t.Fatalf("save: %v", err)
	}
	if registry.Created != 1 || registry.Updated != 0 {
		t.Errorf("calls = %d %d", registry.Created, registry.Updated)
	}
	d.ID = "schema-1"
	stored, err := svc.Save(context.Background(), d)
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if registry.Updated != 1 {
		t.Errorf("updated = %d", registry.Updated)
	}
	if stored.GetVersion() != 2 {
		t.Errorf("version = %d", stored.GetVersion())
	}
}

func TestSaveRejectsABrokenDraft(t *testing.T) {
	svc := build(t, &fake.Registry{}, nil)
	_, err := svc.Save(context.Background(), draft.Draft{})
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("err = %v, want invalid argument", err)
	}
	if !strings.Contains(err.Error(), "type") {
		t.Errorf("err = %v, want the problem sentences", err)
	}
}

func TestSaveMapsRegistryErrors(t *testing.T) {
	t.Run("connect error", func(t *testing.T) {
		registry := &fake.Registry{Err: connect.NewError(connect.CodeAlreadyExists, errors.New("taken"))}
		svc := build(t, registry, nil)
		if _, err := svc.Save(context.Background(), sampleDraft()); connect.CodeOf(err) != connect.CodeAlreadyExists {
			t.Errorf("err = %v, want already exists", err)
		}
	})
	t.Run("plain error on create", func(t *testing.T) {
		registry := &fake.Registry{Err: errors.New("down")}
		svc := build(t, registry, nil)
		if _, err := svc.Save(context.Background(), sampleDraft()); connect.CodeOf(err) != connect.CodeUnavailable {
			t.Errorf("err = %v, want unavailable", err)
		}
	})
	t.Run("plain error on update", func(t *testing.T) {
		registry := &fake.Registry{Err: errors.New("down")}
		svc := build(t, registry, nil)
		d := sampleDraft()
		d.ID = "schema-1"
		if _, err := svc.Save(context.Background(), d); connect.CodeOf(err) != connect.CodeUnavailable {
			t.Errorf("err = %v, want unavailable", err)
		}
	})
	t.Run("import that cannot save", func(t *testing.T) {
		registry := &fake.Registry{Err: errors.New("down")}
		svc := build(t, registry, nil)
		_, err := svc.Import(context.Background(), connect.NewRequest(&schemabuilderv1.ImportRequest{
			Source: &schemabuilderv1.ImportRequest_JsonSchema{JsonSchema: document},
		}))
		if connect.CodeOf(err) != connect.CodeUnavailable {
			t.Errorf("err = %v, want unavailable", err)
		}
	})
}

func TestResponseCopiesCard(t *testing.T) {
	p := preview.Preview{
		Card: preview.Card{Title: "T", Rows: []preview.Row{{Label: "a", Value: "1", SelectivelyDisclosable: true}}},
	}
	msg := service.Response(p)
	if msg.GetWalletCard().GetRows()[0].GetLabel() != "a" || !msg.GetWalletCard().GetRows()[0].GetSelectivelyDisclosable() {
		t.Errorf("rows = %+v", msg.GetWalletCard().GetRows())
	}
}
