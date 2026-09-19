// SPDX-License-Identifier: Apache-2.0

package datasource_test

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/mapping"
	datasourcev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/datasource"
)

// fakeAPI answers as the data source service.
type fakeAPI struct {
	fieldMap    *datasourcev1.FieldMap
	fieldMapErr error
	rows        []*datasourcev1.PreviewRowsResponse_Row
	rowsErr     error
	limit       int32
}

func (f *fakeAPI) GetFieldMap(
	context.Context, *connect.Request[datasourcev1.GetFieldMapRequest],
) (*connect.Response[datasourcev1.GetFieldMapResponse], error) {
	if f.fieldMapErr != nil {
		return nil, f.fieldMapErr
	}
	return connect.NewResponse(&datasourcev1.GetFieldMapResponse{FieldMap: f.fieldMap}), nil
}

func (f *fakeAPI) PreviewRows(
	_ context.Context, req *connect.Request[datasourcev1.PreviewRowsRequest],
) (*connect.Response[datasourcev1.PreviewRowsResponse], error) {
	f.limit = req.Msg.GetLimit()
	if f.rowsErr != nil {
		return nil, f.rowsErr
	}
	return connect.NewResponse(&datasourcev1.PreviewRowsResponse{Rows: f.rows}), nil
}

// farmerMap maps two columns onto two properties.
func farmerMap() *datasourcev1.FieldMap {
	return &datasourcev1.FieldMap{
		SourceId:      "source-1",
		SchemaId:      "farmer",
		SchemaVersion: 3,
		Rules: []*datasourcev1.FieldMap_Rule{
			{Property: "fullName", SourceFields: []string{"name"}},
			{
				Property:     "farmerID",
				SourceFields: []string{"id"},
				Transform:    datasourcev1.Transform_TRANSFORM_UPPER,
			},
		},
	}
}

func TestRowsMapsTheColumnsOntoTheProperties(t *testing.T) {
	api := &fakeAPI{
		fieldMap: farmerMap(),
		rows: []*datasourcev1.PreviewRowsResponse_Row{
			{Values: map[string]string{"name": "Ada Lovelace", "id": "fm-0001"}},
			{Values: map[string]string{"name": "Grace Hopper", "id": "fm-0002"}},
		},
	}
	got, err := datasource.New(api, "farmer").Rows(context.Background(), "source-1")
	if err != nil {
		t.Fatalf("Rows: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("rows = %d", len(got))
	}
	if got[0]["fullName"] != "Ada Lovelace" || got[0]["farmerID"] != "FM-0001" {
		t.Fatalf("the first row = %v", got[0])
	}
	if api.limit != datasource.RowLimit {
		t.Fatalf("limit = %d, want %d", api.limit, datasource.RowLimit)
	}
}

func TestRowsChecksItsInput(t *testing.T) {
	ctx := context.Background()
	var missing *datasource.Client
	if _, err := missing.Rows(ctx, "source-1"); err == nil {
		t.Fatal("a client without a service read rows")
	}
	if _, err := datasource.New(nil, "farmer").Rows(ctx, "source-1"); err == nil {
		t.Fatal("a client without a service read rows")
	}
	if _, err := datasource.New(&fakeAPI{}, "farmer").Rows(ctx, "  "); err == nil {
		t.Fatal("the client read rows without a source id")
	}
}

func TestRowsReportsAFailure(t *testing.T) {
	ctx := context.Background()
	down := connect.NewError(connect.CodeUnavailable, errors.New("down"))
	if _, err := datasource.New(&fakeAPI{fieldMapErr: down}, "farmer").Rows(ctx, "source-1"); err == nil {
		t.Fatal("the client passed a failed field map")
	}
	api := &fakeAPI{fieldMap: farmerMap(), rowsErr: down}
	if _, err := datasource.New(api, "farmer").Rows(ctx, "source-1"); err == nil {
		t.Fatal("the client passed a failed row read")
	}
}

func TestRowsReportsARowTheMapRejects(t *testing.T) {
	api := &fakeAPI{
		fieldMap: &datasourcev1.FieldMap{
			Rules: []*datasourcev1.FieldMap_Rule{{
				Property:     "birthDate",
				SourceFields: []string{"dob"},
				Transform:    datasourcev1.Transform_TRANSFORM_DATE_FORMAT,
			}},
		},
		rows: []*datasourcev1.PreviewRowsResponse_Row{{Values: map[string]string{"dob": "the first of May"}}},
	}
	if _, err := datasource.New(api, "farmer").Rows(context.Background(), "source-1"); err == nil {
		t.Fatal("the client accepted a row the map rejects")
	}
}

func TestConvertMapsTheContractOntoTheCore(t *testing.T) {
	got := datasource.Convert(farmerMap())
	if got.SourceID != "source-1" || got.SchemaID != "farmer" || got.SchemaVersion != 3 {
		t.Fatalf("field map = %+v", got)
	}
	if len(got.Rules) != 2 {
		t.Fatalf("rules = %d", len(got.Rules))
	}
	if got.Rules[0].Transform != mapping.Copy {
		t.Fatalf("an unset transform = %q, want copy", got.Rules[0].Transform)
	}
	if got.Rules[1].Transform != mapping.Transform("upper") {
		t.Fatalf("transform = %q", got.Rules[1].Transform)
	}
	if empty := datasource.Convert(nil); len(empty.Rules) != 0 {
		t.Fatalf("an empty map = %+v", empty)
	}
}
