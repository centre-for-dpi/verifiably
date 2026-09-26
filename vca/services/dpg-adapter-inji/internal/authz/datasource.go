// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"fmt"

	"connectrpc.com/connect"

	datasourcev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1/datasourcev1connect"
)

// DataSource finds the subject of a claim without an offer through
// DataSourceService.Lookup of the data source service of the pair.
type DataSource struct {
	// Client calls the data source service.
	Client datasourcev1connect.DataSourceServiceClient
}

// Lookup implements Lookup.
func (d DataSource) Lookup(ctx context.Context, src SignInSource, value string) (string, bool, error) {
	res, err := d.Client.Lookup(ctx, connect.NewRequest(&datasourcev1.LookupRequest{
		SourceId: src.SourceID, Field: src.Field, Value: value,
		SchemaId: src.SchemaID, SchemaVersion: src.SchemaVersion,
	}))
	if err != nil {
		return "", false, fmt.Errorf("authz: look the holder up in %s: %w", src.SourceID, err)
	}
	if !res.Msg.GetFound() {
		return "", false, nil
	}
	return res.Msg.GetSubjectData(), true, nil
}
