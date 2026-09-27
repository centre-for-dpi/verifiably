// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/credebl"
)

// DIDComm proof requests (P6-C6, ADR-061). The platform asks a wallet
// for an AnonCreds proof in the Indy format, with the attributes to
// reveal and the predicates to prove, or for a DIF Presentation Exchange
// proof. The request goes out as an out of band invitation, or over a
// connection of the organisation. The agent verifies the proof, and the
// platform reads the revealed values.

// DidcommProofPrefix starts the state of a DIDComm proof request. The
// rest is the id of the proof exchange in the agent. GetResult reads
// that exchange.
const DidcommProofPrefix = "didcomm-proof:"

// ProofCheckName names the check the agent runs on a proof.
const ProofCheckName = "credebl-proof-verified"

// proofComment is the text the wallet shows with a proof request.
const proofComment = "A verifier asks for a proof."

// predicateOps are the operators of an AnonCreds predicate.
var predicateOps = map[string]bool{">=": true, ">": true, "<=": true, "<": true}

// anonCredsRestriction is one restriction of an AnonCreds request.
type anonCredsRestriction struct {
	SchemaID  string `json:"schema_id,omitempty"`
	CredDefID string `json:"cred_def_id,omitempty"`
}

// anonCredsAttribute is one requested attribute group.
type anonCredsAttribute struct {
	Name         string                 `json:"name,omitempty"`
	Names        []string               `json:"names,omitempty"`
	Restrictions []anonCredsRestriction `json:"restrictions,omitempty"`
}

// anonCredsPredicate is one requested predicate.
type anonCredsPredicate struct {
	Name         string                 `json:"name"`
	Type         string                 `json:"p_type"`
	Value        int64                  `json:"p_value"`
	Restrictions []anonCredsRestriction `json:"restrictions,omitempty"`
}

// anonCredsRequest is an AnonCreds proof request of the specification.
type anonCredsRequest struct {
	Name       string                        `json:"name"`
	Version    string                        `json:"version"`
	Attributes map[string]anonCredsAttribute `json:"requested_attributes"`
	Predicates map[string]anonCredsPredicate `json:"requested_predicates"`
}

// parseAnonCreds reads and checks an AnonCreds proof request. It fills
// the name and the version when the request has none.
func parseAnonCreds(raw string) (anonCredsRequest, error) {
	var req anonCredsRequest
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		return req, fmt.Errorf("read the AnonCreds proof request: %w", err)
	}
	if len(req.Attributes)+len(req.Predicates) == 0 {
		return req, errors.New("the AnonCreds proof request asks for no attribute and no predicate")
	}
	for ref, a := range req.Attributes {
		if strings.TrimSpace(a.Name) == "" && len(a.Names) == 0 {
			return req, fmt.Errorf("the requested attribute %q names no attribute", ref)
		}
	}
	for ref, p := range req.Predicates {
		if strings.TrimSpace(p.Name) == "" || !predicateOps[p.Type] {
			return req, fmt.Errorf("the predicate %q needs an attribute and one of >=, >, <=, <", ref)
		}
	}
	if req.Name == "" {
		req.Name = "Proof request"
	}
	if req.Version == "" {
		req.Version = "1.0"
	}
	if req.Attributes == nil {
		req.Attributes = map[string]anonCredsAttribute{}
	}
	if req.Predicates == nil {
		req.Predicates = map[string]anonCredsPredicate{}
	}
	return req, nil
}

// sortedKeys returns the keys of a map in order, so a body is the same
// on every run.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// firstRestriction returns the first restriction, which is the one the
// attribute list of the platform carries.
func firstRestriction(list []anonCredsRestriction) anonCredsRestriction {
	if len(list) == 0 {
		return anonCredsRestriction{}
	}
	return list[0]
}

// attributes turns the request into the attribute list of a request over
// a connection: each attribute group, then each predicate.
func (r anonCredsRequest) attributes() []credebl.ProofAttribute {
	var out []credebl.ProofAttribute
	for _, ref := range sortedKeys(r.Attributes) {
		a := r.Attributes[ref]
		rs := firstRestriction(a.Restrictions)
		line := credebl.ProofAttribute{Name: a.Name, CredDefID: rs.CredDefID, SchemaID: rs.SchemaID}
		if line.Name == "" {
			line.Names = a.Names
		}
		out = append(out, line)
	}
	for _, ref := range sortedKeys(r.Predicates) {
		p := r.Predicates[ref]
		rs := firstRestriction(p.Restrictions)
		out = append(out, credebl.ProofAttribute{
			Name: p.Name, Condition: p.Type, Value: strconv.FormatInt(p.Value, 10), CredDefID: rs.CredDefID, SchemaID: rs.SchemaID,
		})
	}
	return out
}

// proofRequestOf reads the proof request of a CreateRequest call.
func proofRequestOf(msg *backendv1.CreateRequestRequest, connection bool) (credebl.ProofRequest, error) {
	if raw := strings.TrimSpace(msg.GetAnoncredsRequest()); raw != "" {
		req, err := parseAnonCreds(raw)
		if err != nil {
			return credebl.ProofRequest{}, err
		}
		out := credebl.ProofRequest{Type: credebl.ProofTypeIndy, Comment: proofComment}
		if connection {
			out.Attributes = req.attributes()
			return out, nil
		}
		// The request decoded from JSON, so it encodes again.
		out.Indy = anyval.Must(json.Marshal(req))
		return out, nil
	}
	if strings.TrimSpace(msg.GetPresentationDefinition()) == "" {
		return credebl.ProofRequest{}, errors.New("a DIDComm proof request needs an AnonCreds request or a presentation definition")
	}
	definition, err := platformDefinition(msg.GetPresentationDefinition())
	if err != nil {
		return credebl.ProofRequest{}, err
	}
	return credebl.ProofRequest{Type: credebl.ProofTypePE, Definition: definition, Comment: proofComment}, nil
}

// platformDefinition turns a Presentation Exchange definition into the
// form the platform takes: each input descriptor names the schema of the
// credential, which the adapter reads from the type filter of the
// descriptor when it has none.
func platformDefinition(raw string) (json.RawMessage, error) {
	var def map[string]any
	if err := json.Unmarshal([]byte(raw), &def); err != nil {
		return nil, fmt.Errorf("read the presentation definition: %w", err)
	}
	descriptors, ok := def["input_descriptors"].([]any)
	if !ok || len(descriptors) == 0 {
		return nil, errors.New("the presentation definition has no input descriptor")
	}
	for _, item := range descriptors {
		d, isObject := item.(map[string]any)
		if !isObject {
			return nil, errors.New("an input descriptor is not an object")
		}
		if _, has := d["schema"]; has {
			continue
		}
		typ := descriptorType(d)
		if typ == "" {
			return nil, fmt.Errorf("the input descriptor %q names no credential type; add a filter on $.type", text(d["id"]))
		}
		d["schema"] = []map[string]string{{"uri": typ}}
	}
	out := map[string]any{"id": def["id"], "input_descriptors": descriptors}
	for _, k := range []string{"name", "purpose"} {
		if v, has := def[k]; has {
			out[k] = v
		}
	}
	return json.Marshal(out)
}

// descriptorType returns the credential type a descriptor filters on: the
// constant of a field on $.type or $.vc.type.
func descriptorType(d map[string]any) string {
	constraints := anyval.As[map[string]any](d["constraints"])
	for _, item := range anyval.As[[]any](constraints["fields"]) {
		f := anyval.As[map[string]any](item)
		onType := false
		for _, p := range anyval.As[[]any](f["path"]) {
			if s := text(p); s == "$.type" || s == "$.vc.type" || s == "$['type']" {
				onType = true
			}
		}
		if !onType {
			continue
		}
		filter := anyval.As[map[string]any](f["filter"])
		if c := text(filter["const"]); c != "" {
			return c
		}
		if c := text(anyval.As[map[string]any](filter["contains"])["const"]); c != "" {
			return c
		}
	}
	return ""
}

// text returns a JSON value as text.
func text(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// didcommRequest sends a DIDComm proof request as an out of band
// invitation, or over the connection of the call.
func (s *Service) didcommRequest(ctx context.Context, msg *backendv1.CreateRequestRequest) (*connect.Response[backendv1.CreateRequestResponse], error) {
	connection := strings.TrimSpace(msg.GetConnectionId())
	req, err := proofRequestOf(msg, connection != "")
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if connection != "" {
		record, serr := s.client.SendConnectionProof(ctx, connection, req)
		if serr != nil {
			return nil, failed("send the proof request over the connection", serr)
		}
		return connect.NewResponse(&backendv1.CreateRequestResponse{State: DidcommProofPrefix + record.ID}), nil
	}
	invitation, err := s.client.CreateOOBProof(ctx, req)
	if err != nil {
		return nil, failed("create the out of band proof request", err)
	}
	return connect.NewResponse(&backendv1.CreateRequestResponse{
		RequestUri: invitation.InvitationURL, State: DidcommProofPrefix + invitation.RecordID,
	}), nil
}

// didcommResult reads the state of a DIDComm proof request. A
// presentation that waits for the verifier gets the verify call first.
func (s *Service) didcommResult(ctx context.Context, id string) (*connect.Response[backendv1.GetResultResponse], error) {
	if id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the state names no proof exchange"))
	}
	record, err := s.client.ProofRecord(ctx, id)
	if err != nil {
		return nil, failed("read the proof exchange", err)
	}
	if record.State == credebl.ProofStatePresentationReceived {
		if record, err = s.client.VerifyProof(ctx, id); err != nil {
			return nil, failed("verify the presentation", err)
		}
	}
	out := &backendv1.GetResultResponse{State: backendv1.GetResultResponse_STATE_PENDING}
	switch record.State {
	case credebl.ProofStateAbandoned, credebl.ProofStateDeclined:
		reason := record.ErrorMessage
		if reason == "" {
			reason = "the holder declined the request"
		}
		return connect.NewResponse(rejected(reason)), nil
	case credebl.ProofStateDone:
	default:
		return connect.NewResponse(out), nil
	}
	if record.IsVerified == nil || !*record.IsVerified {
		return connect.NewResponse(rejected("the proof is not valid")), nil
	}
	revealed, err := s.client.VerifiedProof(ctx, id)
	if err != nil {
		return nil, failed("read the revealed values", err)
	}
	out.State = backendv1.GetResultResponse_STATE_ACCEPTED
	out.DpgChecks = []*backendv1.GetResultResponse_DpgCheck{{Name: ProofCheckName, Passed: true}}
	out.Presented = proofViews(revealed)
	out.ReceivedAt = timestamp(record.UpdatedAt)
	if out.ReceivedAt == nil {
		out.ReceivedAt = timestamp(s.now().UTC())
	}
	return connect.NewResponse(out), nil
}

// rejected is the answer of a proof that failed, with the reason.
func rejected(reason string) *backendv1.GetResultResponse {
	return &backendv1.GetResultResponse{
		State:     backendv1.GetResultResponse_STATE_REJECTED,
		DpgChecks: []*backendv1.GetResultResponse_DpgCheck{{Name: ProofCheckName, Passed: false, Reason: reason}},
	}
}

// proofViews groups the revealed values by the credential they came
// from. Each group is a JSON view of the revealed values: the type of
// the schema, the issuer of the credential definition, the schema, and
// the values in credentialSubject. The view carries no proof, because
// the agent checked the proof. An AnonCreds group has the format
// AnonCreds. A DIF PE group names no format, because the view is not the
// credential that the holder presented.
func proofViews(revealed []credebl.Revealed) []*commonv1.Credential {
	type group struct {
		schema, credDef string
		values          map[string]string
	}
	var order []string
	groups := map[string]*group{}
	for _, r := range revealed {
		key := r.SchemaID + "|" + r.CredDefID
		g, ok := groups[key]
		if !ok {
			g = &group{schema: r.SchemaID, credDef: r.CredDefID, values: map[string]string{}}
			groups[key] = g
			order = append(order, key)
		}
		g.values[r.Name] = r.Value
	}
	out := make([]*commonv1.Credential, 0, len(order))
	for _, key := range order {
		g := groups[key]
		view := map[string]any{"type": []string{schemaName(g.schema)}, "credentialSubject": g.values}
		format := commonv1.Format_FORMAT_UNSPECIFIED
		if g.schema != "" {
			view["credentialSchema"] = map[string]string{"id": g.schema}
		}
		if g.credDef != "" {
			format = commonv1.Format_FORMAT_ANONCREDS
			view["credentialDefinitionId"] = g.credDef
			view["issuer"] = issuerOf(g.credDef)
		}
		out = append(out, &commonv1.Credential{Format: format, Payload: anyval.Must(json.Marshal(view))})
	}
	return out
}

// schemaName returns the name of a schema: the name part of an
// AnonCreds schema id, or the id itself.
func schemaName(id string) string {
	if i := strings.Index(id, "/anoncreds/v0/SCHEMA/"); i >= 0 {
		rest := strings.Split(id[i+len("/anoncreds/v0/SCHEMA/"):], "/")
		return rest[0]
	}
	if parts := strings.Split(id, ":"); len(parts) == 4 && parts[1] == "2" {
		return parts[2]
	}
	return id
}

// issuerOf returns the DID of the issuer of a credential definition:
// the DID before /anoncreds/ of a DID id, or the first part of a legacy
// id.
func issuerOf(credDef string) string {
	if i := strings.Index(credDef, "/anoncreds/"); i >= 0 {
		return credDef[:i]
	}
	return strings.SplitN(credDef, ":", 2)[0]
}

// pageNumber reads the page token of a list call. Page numbers start at
// one.
func pageNumber(p *commonv1.Pagination) (page, size int, err error) {
	size = int(p.GetPageSize())
	if size <= 0 || size > 100 {
		size = 20
	}
	page = 1
	if token := p.GetPageToken(); token != "" {
		n, perr := parseToken(token)
		if perr != nil || n < 1 {
			return 0, 0, connect.NewError(connect.CodeInvalidArgument, errors.New("service: bad page token"))
		}
		page = n
	}
	return page, size, nil
}

// nextToken returns the page token after page, or empty for the last
// page.
func nextToken(page, size, total int) string {
	if page*size < total {
		return strconv.Itoa(page + 1)
	}
	return ""
}

// ListProofRequests reads one page of the DIDComm proof requests of the
// organisation of the adapter, newest first.
func (s *Service) ListProofRequests(
	ctx context.Context, req *connect.Request[backendv1.ListProofRequestsRequest],
) (*connect.Response[backendv1.ListProofRequestsResponse], error) {
	page, size, err := pageNumber(req.Msg.GetPage())
	if err != nil {
		return nil, err
	}
	list, total, err := s.client.ProofRequests(ctx, page, size)
	if err != nil {
		return nil, failed("list the proof requests", err)
	}
	out := &backendv1.ListProofRequestsResponse{Page: &commonv1.PageResult{TotalSize: int64(total), NextPageToken: nextToken(page, size, total)}}
	for _, p := range list {
		item := &backendv1.ProofRequest{
			Id: p.PresentationID, ResultState: DidcommProofPrefix + p.PresentationID, ConnectionId: p.ConnectionID,
			State: p.State, CreatedAt: timestamp(p.CreatedAt), Error: p.ErrorMessage,
		}
		if p.Connection != nil {
			item.ConnectionLabel = p.Connection.Label
		}
		out.Requests = append(out.Requests, item)
	}
	return connect.NewResponse(out), nil
}

// ListProofSchemas reads one page of the AnonCreds schemas of the
// platform, with the credential definitions of each.
func (s *Service) ListProofSchemas(
	ctx context.Context, req *connect.Request[backendv1.ListProofSchemasRequest],
) (*connect.Response[backendv1.ListProofSchemasResponse], error) {
	page, size, err := pageNumber(req.Msg.GetPage())
	if err != nil {
		return nil, err
	}
	list, total, err := s.client.PlatformSchemas(ctx, page, size)
	if err != nil {
		return nil, failed("list the AnonCreds schemas", err)
	}
	out := &backendv1.ListProofSchemasResponse{Page: &commonv1.PageResult{TotalSize: int64(total), NextPageToken: nextToken(page, size, total)}}
	if len(list) == 0 {
		return connect.NewResponse(out), nil
	}
	credDefs, err := s.client.PlatformCredDefs(ctx)
	if err != nil {
		return nil, failed("list the credential definitions", err)
	}
	for _, sc := range list {
		item := &backendv1.ProofSchema{
			Id: sc.ID, Name: sc.Name, Version: sc.Version, IssuerDid: sc.IssuerID, CredentialDefinitions: credDefs[sc.ID],
		}
		for _, a := range sc.Attributes {
			item.Attributes = append(item.Attributes, a.Name)
		}
		if sc.Organisation != nil {
			item.Organisation = sc.Organisation.Name
		}
		out.Schemas = append(out.Schemas, item)
	}
	return connect.NewResponse(out), nil
}

// ListVerifierConnections reads the DIDComm connections that a proof
// request can go over: the connections of the organisation.
func (s *Service) ListVerifierConnections(
	ctx context.Context, req *connect.Request[backendv1.ListVerifierConnectionsRequest],
) (*connect.Response[backendv1.ListVerifierConnectionsResponse], error) {
	resp, err := s.ListConnections(ctx, connect.NewRequest(&backendv1.ListConnectionsRequest{Page: req.Msg.GetPage()}))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&backendv1.ListVerifierConnectionsResponse{
		Connections: resp.Msg.GetConnections(), Page: resp.Msg.GetPage(),
	}), nil
}
