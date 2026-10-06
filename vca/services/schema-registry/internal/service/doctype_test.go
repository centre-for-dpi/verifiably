// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/metadata"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/record"
)

// catalogueBackend signs every mDoc with the doctype of its catalogue,
// as a DPG whose catalogue the operator writes at setup does.
type catalogueBackend struct {
	fakeBackend
	doctype string
}

func (f *catalogueBackend) RegisterCredentialConfiguration(ctx context.Context, req *connect.Request[backendv1.RegisterCredentialConfigurationRequest]) (*connect.Response[backendv1.RegisterCredentialConfigurationResponse], error) {
	resp, err := f.fakeBackend.RegisterCredentialConfiguration(ctx, req)
	if err == nil && req.Msg.GetConfiguration().GetFormat() == commonv1.Format_FORMAT_MSO_MDOC {
		resp.Msg.Doctype = f.doctype
	}
	return resp, err
}

// mdocMetadata returns the doctype the issuer metadata publishes for the
// mso_mdoc configuration of a version.
func mdocMetadata(t *testing.T, s *Service, r record.Record) any {
	t.Helper()
	configs := metadata.Configurations([]record.Record{r}, s.MetadataOptions())
	entry, ok := configs[metadata.ConfigurationID(r, record.FormatMsoMdoc)]
	if !ok {
		t.Fatalf("the metadata has no mso_mdoc entry: %v", configs)
	}
	return entry["doctype"]
}

// TestPublishKeepsTheDoctypeTheStackSigns publishes an mso_mdoc schema
// on a stack that signs one doctype of its catalogue. The registry keeps
// that doctype and its issuer metadata names it, so the catalogue of the
// verifier, the DCQL query and the credential of the wallet agree.
func TestPublishKeepsTheDoctypeTheStackSigns(t *testing.T) {
	backend := &catalogueBackend{doctype: "vca.mdoc"}
	s, _ := newService(t, nil)
	s.opts.Backend = backend
	ctx := context.Background()
	in := schema("Residence")
	in.Formats = []commonv1.Format{commonv1.Format_FORMAT_DC_SD_JWT, commonv1.Format_FORMAT_MSO_MDOC}
	created, err := s.Create(ctx, connect.NewRequest(&schemav1.CreateRequest{Schema: in}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: created.Msg.GetSchema().GetId()})); err != nil {
		t.Fatal(err)
	}
	stored, ok := s.opts.Store.Get(created.Msg.GetSchema().GetId(), 1)
	if !ok {
		t.Fatal("the published version is gone")
	}
	if stored.Doctype != "vca.mdoc" {
		t.Fatalf("the record keeps the doctype %q, want vca.mdoc", stored.Doctype)
	}
	if got := mdocMetadata(t, s, stored); got != "vca.mdoc" {
		t.Fatalf("the issuer metadata names the doctype %v, want vca.mdoc", got)
	}

	// A version that an earlier release published kept no doctype. The
	// republish at start records the doctype the stack names now.
	backend.doctype = "vca.mdoc.2"
	if out := s.Republish(ctx, nil); out.Done != 1 {
		t.Fatalf("Republish = %+v", out)
	}
	again, _ := s.opts.Store.Get(created.Msg.GetSchema().GetId(), 1)
	if again.Doctype != "vca.mdoc.2" || again.State != record.StatePublished {
		t.Fatalf("after the republish the record is %s with the doctype %q", again.State, again.Doctype)
	}
}

// TestPublishWithoutADoctypeKeepsTheType publishes on a stack that signs
// the type of the request. The metadata names the schema type.
func TestPublishWithoutADoctypeKeepsTheType(t *testing.T) {
	s, _ := newService(t, &fakeBackend{})
	ctx := context.Background()
	in := schema("Residence")
	in.Formats = []commonv1.Format{commonv1.Format_FORMAT_MSO_MDOC}
	created, err := s.Create(ctx, connect.NewRequest(&schemav1.CreateRequest{Schema: in}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: created.Msg.GetSchema().GetId()})); err != nil {
		t.Fatal(err)
	}
	stored, _ := s.opts.Store.Get(created.Msg.GetSchema().GetId(), 1)
	if stored.Doctype != "" {
		t.Fatalf("the record keeps the doctype %q, want none", stored.Doctype)
	}
	if got := mdocMetadata(t, s, stored); got != "Residence" {
		t.Fatalf("the issuer metadata names the doctype %v, want the type", got)
	}
}
