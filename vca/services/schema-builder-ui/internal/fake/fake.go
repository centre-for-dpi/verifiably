// SPDX-License-Identifier: Apache-2.0

// Package fake holds the test doubles of the clients the schema builder
// injects. Registry stands in for the schema registry. Catalog stands in
// for the DPG catalogue. The tests of the service and of the pages use
// them, so no test needs a network.
package fake

import (
	"context"
	"errors"
	"strconv"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1/schemav1connect"
)

// Registry is a schema registry that keeps versions in memory. Err makes
// every call fail with that error.
type Registry struct {
	schemav1connect.SchemaServiceClient
	// Err fails every call. Nil lets the call through.
	Err error
	// Created counts the Create calls.
	Created int
	// Updated counts the Update calls.
	Updated int
	// Last holds the schema of the last call.
	Last *schemav1.Schema
}

// Create stores version 1 of a new schema.
func (r *Registry) Create(_ context.Context, req *connect.Request[schemav1.CreateRequest]) (*connect.Response[schemav1.CreateResponse], error) {
	if r.Err != nil {
		return nil, r.Err
	}
	r.Created++
	r.Last = req.Msg.GetSchema()
	return connect.NewResponse(&schemav1.CreateResponse{Schema: stored(r.Last, "schema-"+strconv.Itoa(r.Created), 1)}), nil
}

// Update stores the next draft version of a schema.
func (r *Registry) Update(_ context.Context, req *connect.Request[schemav1.UpdateRequest]) (*connect.Response[schemav1.UpdateResponse], error) {
	if r.Err != nil {
		return nil, r.Err
	}
	r.Updated++
	r.Last = req.Msg.GetSchema()
	return connect.NewResponse(&schemav1.UpdateResponse{Schema: stored(r.Last, r.Last.GetId(), 2)}), nil
}

// Get returns the schema of the last call.
func (r *Registry) Get(_ context.Context, req *connect.Request[schemav1.GetRequest]) (*connect.Response[schemav1.GetResponse], error) {
	if r.Err != nil {
		return nil, r.Err
	}
	if r.Last == nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("fake: no schema"))
	}
	return connect.NewResponse(&schemav1.GetResponse{Schema: stored(r.Last, req.Msg.GetId(), 1)}), nil
}

// stored copies m and gives it the id, the version, and the draft state.
func stored(m *schemav1.Schema, id string, version int32) *schemav1.Schema {
	out := &schemav1.Schema{
		Id: id, Version: version, Type: m.GetType(), JsonSchema: m.GetJsonSchema(),
		State: schemav1.State_STATE_DRAFT, Display: m.GetDisplay(), SdClaims: m.GetSdClaims(),
		Formats: m.GetFormats(), Expires: m.GetExpires(),
	}
	return out
}

// Catalog is a DPG catalogue that returns a fixed list.
type Catalog struct {
	backendv1connect.CatalogBackendServiceClient
	// Entries is the list the catalogue returns.
	Entries []*backendv1.CredentialConfiguration
	// Err fails every call. Nil lets the call through.
	Err error
	// Calls counts the ListCredentialTypes calls.
	Calls int
}

// ListCredentialTypes returns Entries.
func (c *Catalog) ListCredentialTypes(context.Context, *connect.Request[backendv1.ListCredentialTypesRequest]) (*connect.Response[backendv1.ListCredentialTypesResponse], error) {
	c.Calls++
	if c.Err != nil {
		return nil, c.Err
	}
	return connect.NewResponse(&backendv1.ListCredentialTypesResponse{Configurations: c.Entries}), nil
}
