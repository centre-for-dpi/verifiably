// SPDX-License-Identifier: Apache-2.0

// Package datasource reads rows from the data source service and maps
// them onto the properties of a schema with core/mapping.
//
// The usual direction is the other way: the data source service reads
// its own rows and calls IssueBatch with them and with its job id. This
// client covers the other case, where an operator starts a batch from
// the issuance service and names a source alone. It reads the field map
// of the source and the rows the source serves, and it applies the map.
package datasource

import (
	"context"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"github.com/centre-for-dpi/vc-adapters/core/mapping"
	datasourcev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1"
)

// RowLimit is the number of rows the client reads at most.
const RowLimit = 20

// API is the part of the data source service the client uses.
type API interface {
	// GetFieldMap returns the mapping of one source onto one schema.
	GetFieldMap(context.Context, *connect.Request[datasourcev1.GetFieldMapRequest]) (
		*connect.Response[datasourcev1.GetFieldMapResponse], error)
	// PreviewRows returns rows of one source.
	PreviewRows(context.Context, *connect.Request[datasourcev1.PreviewRowsRequest]) (
		*connect.Response[datasourcev1.PreviewRowsResponse], error)
}

// Client reads the rows of a source.
type Client struct {
	api API
	// schemaID names the schema the rows fill.
	schemaID string
}

// New returns a client over the data source service. The schema id
// selects the field map.
func New(api API, schemaID string) *Client {
	return &Client{api: api, schemaID: schemaID}
}

// Rows returns the mapped rows of one source.
func (c *Client) Rows(ctx context.Context, sourceID string) ([]map[string]string, error) {
	if c == nil || c.api == nil {
		return nil, fmt.Errorf("datasource: no data source service")
	}
	if strings.TrimSpace(sourceID) == "" {
		return nil, fmt.Errorf("datasource: the request needs a source id")
	}
	fieldMap, err := c.fieldMap(ctx, sourceID)
	if err != nil {
		return nil, err
	}
	resp, err := c.api.PreviewRows(ctx, connect.NewRequest(&datasourcev1.PreviewRowsRequest{
		SourceId: sourceID, Limit: RowLimit,
	}))
	if err != nil {
		return nil, fmt.Errorf("datasource: read the rows: %w", err)
	}
	out := make([]map[string]string, 0, len(resp.Msg.GetRows()))
	for i, row := range resp.Msg.GetRows() {
		values, aerr := mapping.Apply(row.GetValues(), fieldMap)
		if aerr != nil {
			return nil, fmt.Errorf("datasource: map the row %d: %w", i+1, aerr)
		}
		claims := make(map[string]string, len(values))
		for name, value := range values {
			claims[name] = fmt.Sprint(value)
		}
		out = append(out, claims)
	}
	return out, nil
}

// fieldMap reads the mapping of the source onto the schema.
func (c *Client) fieldMap(ctx context.Context, sourceID string) (mapping.FieldMap, error) {
	resp, err := c.api.GetFieldMap(ctx, connect.NewRequest(&datasourcev1.GetFieldMapRequest{
		SourceId: sourceID, SchemaId: c.schemaID,
	}))
	if err != nil {
		return mapping.FieldMap{}, fmt.Errorf("datasource: read the field map: %w", err)
	}
	return Convert(resp.Msg.GetFieldMap()), nil
}

// Convert maps the contract field map onto the core field map.
func Convert(fm *datasourcev1.FieldMap) mapping.FieldMap {
	out := mapping.FieldMap{
		SourceID:      fm.GetSourceId(),
		SchemaID:      fm.GetSchemaId(),
		SchemaVersion: int(fm.GetSchemaVersion()),
	}
	for _, r := range fm.GetRules() {
		out.Rules = append(out.Rules, mapping.Rule{
			Property:     r.GetProperty(),
			SourceFields: r.GetSourceFields(),
			Transform:    transformOf(r.GetTransform()),
			Params:       r.GetParams(),
		})
	}
	return out
}

// transformOf maps a contract transform onto the core transform. The
// unspecified value means copy, which uses the source value as it is.
func transformOf(t datasourcev1.Transform) mapping.Transform {
	if t == datasourcev1.Transform_TRANSFORM_UNSPECIFIED {
		return mapping.Copy
	}
	name := strings.TrimPrefix(t.String(), "TRANSFORM_")
	return mapping.Transform(strings.ToLower(name))
}
