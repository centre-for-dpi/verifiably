// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/credebl"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
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

// IssuerBoundCheckName names the check that fails when the request
// bound no issuer, so any issuer on the ledger could answer (ADR-064).
const IssuerBoundCheckName = "credebl-issuer-bound"

// proofComment is the text the wallet shows with a proof request.
const proofComment = "A verifier asks for a proof."

// predicateOps are the operators of an AnonCreds predicate.
var predicateOps = map[string]bool{">=": true, ">": true, "<=": true, "<": true}

// anonCredsRestriction is one restriction of an AnonCreds request.
type anonCredsRestriction struct {
	SchemaID  string `json:"schema_id,omitempty"`
	CredDefID string `json:"cred_def_id,omitempty"`
	// IssuerDID binds the issuer without a credential definition.
	IssuerDID string `json:"issuer_did,omitempty"`
	// IssuerID is the name of IssuerDID in later AnonCreds releases.
	IssuerID string `json:"issuer_id,omitempty"`
}

// issuer returns the issuer that a restriction binds: the issuer of its
// credential definition, or its issuer DID. Empty binds none.
func (r anonCredsRestriction) issuer() string {
	switch {
	case r.CredDefID != "":
		return issuerOf(r.CredDefID)
	case r.IssuerDID != "":
		return r.IssuerDID
	}
	return r.IssuerID
}

// proofPart is one attribute or predicate of a request, with the
// credential it binds. A part binds its issuer only with one
// restriction that names a credential definition or an issuer DID.
type proofPart struct {
	// Name is the attribute name.
	Name string `json:"name"`
	// SchemaID is the schema the part restricts to.
	SchemaID string `json:"schema_id,omitempty"`
	// CredDefID is the credential definition the part restricts to.
	CredDefID string `json:"cred_def_id,omitempty"`
	// Issuer is the issuer the part binds. Empty means any issuer.
	Issuer string `json:"issuer,omitempty"`
}

// partOf returns the part of one name and its restrictions.
func partOf(name string, list []anonCredsRestriction) proofPart {
	p := proofPart{Name: strings.TrimSpace(name)}
	if len(list) == 1 {
		r := list[0]
		p.SchemaID, p.CredDefID, p.Issuer = r.SchemaID, r.CredDefID, r.issuer()
	}
	return p
}

// anonCredsAttribute is one requested attribute. A request may name a
// group, which parseAnonCreds turns into one referent per name.
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
// the name and the version when the request has none. Unless the
// template accepts any issuer, every part binds its issuer (ADR-064
// decision 2).
func parseAnonCreds(raw string, anyIssuer bool) (anonCredsRequest, error) {
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
	split, err := oneNameEach(req.Attributes)
	if err != nil {
		return req, err
	}
	req.Attributes = split
	for _, name := range req.names() {
		if err := askable(name); err != nil {
			return req, err
		}
	}
	for ref, p := range req.Predicates {
		if strings.TrimSpace(p.Name) == "" || !predicateOps[p.Type] {
			return req, fmt.Errorf("the predicate %q needs an attribute and one of >=, >, <=, <", ref)
		}
	}
	for _, p := range req.parts() {
		if !anyIssuer && p.Issuer == "" {
			return req, fmt.Errorf("the part on %q binds no issuer; name one credential definition or issuer DID, "+
				"or accept any issuer in the template", p.Name)
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

// askable refuses an attribute name that the platform drops from the
// revealed values: it writes the source of each value under the names
// schemaId, credDefId and certificateTemplate.
func askable(name string) error {
	if credebl.DroppedName(name) {
		return fmt.Errorf("the platform drops an attribute named %q from the result; rename it in the schema", name)
	}
	return nil
}

// names returns the attribute names of the request: the attributes,
// then the predicates, each in referent order.
func (r anonCredsRequest) names() []string {
	var out []string
	for _, p := range r.parts() {
		out = append(out, p.Name)
	}
	return out
}

// parts returns the parts of the request with what each binds: the
// attributes, then the predicates, each in referent order.
func (r anonCredsRequest) parts() []proofPart {
	var out []proofPart
	for _, ref := range sortedKeys(r.Attributes) {
		out = append(out, partOf(r.Attributes[ref].Name, r.Attributes[ref].Restrictions))
	}
	for _, ref := range sortedKeys(r.Predicates) {
		out = append(out, partOf(r.Predicates[ref].Name, r.Predicates[ref].Restrictions))
	}
	return out
}

// oneNameEach turns each group of names into one referent per name,
// with the restrictions of the group. The platform reads the revealed
// values by the name of each referent and never reads
// revealed_attr_groups (verification.service.ts of the platform), so a
// group would come back with no value.
func oneNameEach(in map[string]anonCredsAttribute) (map[string]anonCredsAttribute, error) {
	out := map[string]anonCredsAttribute{}
	put := func(ref string, a anonCredsAttribute) error {
		if _, taken := out[ref]; taken {
			return fmt.Errorf("the request names the referent %q twice", ref)
		}
		out[ref] = a
		return nil
	}
	for _, ref := range sortedKeys(in) {
		a := in[ref]
		if len(a.Names) == 0 {
			if err := put(ref, a); err != nil {
				return nil, err
			}
			continue
		}
		for i, name := range a.Names {
			item := anonCredsAttribute{Name: name, Restrictions: a.Restrictions}
			if err := put(ref+"_"+strconv.Itoa(i+1), item); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
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
		out = append(out, credebl.ProofAttribute{Name: a.Name, CredDefID: rs.CredDefID, SchemaID: rs.SchemaID})
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

// proofRequestOf reads the proof request of a CreateRequest call. It
// returns the request and the record the adapter keeps of it.
func proofRequestOf(msg *backendv1.CreateRequestRequest, connection bool) (credebl.ProofRequest, proofRecord, error) {
	if raw := strings.TrimSpace(msg.GetAnoncredsRequest()); raw != "" {
		req, err := parseAnonCreds(raw, msg.GetAnyIssuer())
		if err != nil {
			return credebl.ProofRequest{}, proofRecord{}, err
		}
		out := credebl.ProofRequest{Type: credebl.ProofTypeIndy, Comment: proofComment}
		record := proofRecord{Names: req.names(), Indy: true, Parts: req.parts()}
		if connection {
			// The attribute list of the platform carries a credential
			// definition and a schema only, so an issuer DID stays out.
			for i, p := range record.Parts {
				if p.CredDefID == "" {
					if !msg.GetAnyIssuer() {
						return credebl.ProofRequest{}, proofRecord{}, fmt.Errorf(
							"over a connection the platform binds the issuer by credential definition only; name one for %q", p.Name)
					}
					record.Parts[i].Issuer = ""
				}
			}
			out.Attributes = req.attributes()
			return out, record, nil
		}
		// The request decoded from JSON, so it encodes again.
		out.Indy = anyval.Must(json.Marshal(req))
		return out, record, nil
	}
	if strings.TrimSpace(msg.GetPresentationDefinition()) == "" {
		return credebl.ProofRequest{}, proofRecord{}, errors.New("a DIDComm proof request needs an AnonCreds request or a presentation definition")
	}
	definition, parts, err := platformDefinition(msg.GetPresentationDefinition())
	if err != nil {
		return credebl.ProofRequest{}, proofRecord{}, err
	}
	names := make([]string, 0, len(parts))
	for _, p := range parts {
		names = append(names, p.Name)
	}
	return credebl.ProofRequest{Type: credebl.ProofTypePE, Definition: definition, Comment: proofComment},
		proofRecord{Names: names, Parts: parts}, nil
}

// proofRecord is what the adapter keeps of a DIDComm proof request it
// made, under the id of the proof exchange.
type proofRecord struct {
	// Names are the attribute names of the request, in request order.
	// The result reads each value by its name.
	Names []string `json:"names"`
	// Indy marks an AnonCreds request.
	Indy bool `json:"indy,omitempty"`
	// Parts are the parts of an AnonCreds request with what each binds.
	// The view names the issuer the request bound, never the restriction
	// that the platform reports (ADR-064 decision 3).
	Parts []proofPart `json:"parts,omitempty"`
}

// part returns the part of a name, or an unbound part.
func (r proofRecord) part(name string) proofPart {
	for _, p := range r.Parts {
		if p.Name == name {
			return p
		}
	}
	return proofPart{Name: name}
}

// proofKey is the store key of the record of a proof exchange.
func proofKey(id string) string {
	sum := sha256.Sum256([]byte(id))
	return "proof/" + hex.EncodeToString(sum[:])
}

// keepProof stores the record of a proof exchange.
func (s *Service) keepProof(ctx context.Context, id string, rec proofRecord) error {
	if err := s.store.Put(ctx, proofKey(id), anyval.Must(json.Marshal(rec))); err != nil {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("keep the record of the proof request: %w", err))
	}
	return nil
}

// proofOf reads the record of a proof exchange. A request that the
// adapter did not record, such as one from before an upgrade, gives
// false.
func (s *Service) proofOf(ctx context.Context, id string) (proofRecord, bool, error) {
	raw, err := s.store.Get(ctx, proofKey(id))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return proofRecord{}, false, nil
	case err != nil:
		return proofRecord{}, false, connect.NewError(connect.CodeInternal, fmt.Errorf("read the record of the proof request: %w", err))
	}
	var rec proofRecord
	if json.Unmarshal(raw, &rec) != nil {
		return proofRecord{}, false, connect.NewError(connect.CodeInternal, errors.New("the record of the proof request is damaged"))
	}
	return rec, true, nil
}

// platformDefinition turns a Presentation Exchange definition into the
// form the platform takes: each input descriptor names the schema of the
// credential, which the adapter reads from the type filter of the
// descriptor when it has none.
func platformDefinition(raw string) (json.RawMessage, []proofPart, error) {
	var def map[string]any
	if err := json.Unmarshal([]byte(raw), &def); err != nil {
		return nil, nil, fmt.Errorf("read the presentation definition: %w", err)
	}
	var parts []proofPart
	descriptors, ok := def["input_descriptors"].([]any)
	if !ok || len(descriptors) == 0 {
		return nil, nil, errors.New("the presentation definition has no input descriptor")
	}
	for _, item := range descriptors {
		d, isObject := item.(map[string]any)
		if !isObject {
			return nil, nil, errors.New("an input descriptor is not an object")
		}
		claims := claimNames(d)
		if len(claims) > 1 {
			return nil, nil, fmt.Errorf("the platform reads one claim per input descriptor, and %q asks for %s; "+
				"put each claim in its own descriptor or ask over OID4VP", text(d["id"]), strings.Join(claims, ", "))
		}
		issuer := descriptorIssuer(d)
		for _, name := range claims {
			if err := askable(name); err != nil {
				return nil, nil, err
			}
			parts = append(parts, proofPart{Name: name, Issuer: issuer})
		}
		claimFirst(d)
		if _, has := d["schema"]; has {
			continue
		}
		typ := descriptorType(d)
		if typ == "" {
			return nil, nil, fmt.Errorf("the input descriptor %q names no credential type; add a filter on $.type", text(d["id"]))
		}
		d["schema"] = []map[string]string{{"uri": typ}}
	}
	out := map[string]any{"id": def["id"], "input_descriptors": descriptors}
	for _, k := range []string{"name", "purpose"} {
		if v, has := def[k]; has {
			out[k] = v
		}
	}
	body, err := json.Marshal(out)
	return body, parts, err
}

// bracketName reads the name of a path in bracket form, such as
// $.credentialSubject['fullName'], as the platform does.
var bracketName = regexp.MustCompile(`\['(.*?)'\]`)

// claimNames returns the attribute names that the fields of a
// descriptor ask for, the way the platform reads a path: the name in
// brackets, or the part after the last dot. A field on the type of the
// credential names no attribute.
func claimNames(d map[string]any) []string {
	var out []string
	constraints := anyval.As[map[string]any](d["constraints"])
	for _, item := range anyval.As[[]any](constraints["fields"]) {
		f := anyval.As[map[string]any](item)
		for _, p := range anyval.As[[]any](f["path"]) {
			path := text(p)
			if typePath(path) || issuerPath(path) {
				continue
			}
			name := path[strings.LastIndex(path, ".")+1:]
			if m := bracketName.FindStringSubmatch(path); m != nil {
				name = m[1]
			}
			if name != "" && !slices.Contains(out, name) {
				out = append(out, name)
			}
		}
	}
	return out
}

// claimFirst moves the fields on a claim before the fields on the type
// of the credential. The platform reads the path of the first field of
// a descriptor only (verification.service.ts), and the PE form of a DCQL
// query puts the type filter first.
func claimFirst(d map[string]any) {
	constraints, ok := d["constraints"].(map[string]any)
	if !ok {
		return
	}
	fields := anyval.As[[]any](constraints["fields"])
	var claims, rest []any
	for _, item := range fields {
		onType := false
		for _, p := range anyval.As[[]any](anyval.As[map[string]any](item)["path"]) {
			onType = onType || typePath(text(p)) || issuerPath(text(p))
		}
		if onType {
			rest = append(rest, item)
		} else {
			claims = append(claims, item)
		}
	}
	if len(fields) > 0 {
		constraints["fields"] = append(claims, rest...)
	}
}

// issuerPath reports a path on the issuer of the credential.
func issuerPath(path string) bool {
	switch path {
	case "$.issuer", "$.issuer.id", "$.vc.issuer", "$.vc.issuer.id":
		return true
	}
	return false
}

// descriptorIssuer returns the issuer a descriptor binds: the constant of
// a field on the issuer. The agent checks the presentation against the
// definition, so a verified proof came from that issuer. Empty binds
// none.
func descriptorIssuer(d map[string]any) string {
	constraints := anyval.As[map[string]any](d["constraints"])
	for _, item := range anyval.As[[]any](constraints["fields"]) {
		f := anyval.As[map[string]any](item)
		for _, p := range anyval.As[[]any](f["path"]) {
			if issuerPath(text(p)) {
				return text(anyval.As[map[string]any](f["filter"])["const"])
			}
		}
	}
	return ""
}

// typePath reports a path on the type of the credential.
func typePath(path string) bool {
	return path == "$.type" || path == "$.vc.type" || path == "$['type']"
}

// descriptorType returns the credential type a descriptor filters on: the
// constant of a field on $.type or $.vc.type.
func descriptorType(d map[string]any) string {
	constraints := anyval.As[map[string]any](d["constraints"])
	for _, item := range anyval.As[[]any](constraints["fields"]) {
		f := anyval.As[map[string]any](item)
		onType := false
		for _, p := range anyval.As[[]any](f["path"]) {
			if typePath(text(p)) {
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
	req, kept, err := proofRequestOf(msg, connection != "")
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if connection != "" {
		record, serr := s.client.SendConnectionProof(ctx, connection, req)
		if serr != nil {
			return nil, failed("send the proof request over the connection", serr)
		}
		if kerr := s.keepProof(ctx, record.ID, kept); kerr != nil {
			return nil, kerr
		}
		return connect.NewResponse(&backendv1.CreateRequestResponse{State: DidcommProofPrefix + record.ID}), nil
	}
	invitation, err := s.client.CreateOOBProof(ctx, req)
	if err != nil {
		return nil, failed("create the out of band proof request", err)
	}
	if err := s.keepProof(ctx, invitation.RecordID, kept); err != nil {
		return nil, err
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
	kept, known, err := s.proofOf(ctx, id)
	if err != nil {
		return nil, err
	}
	revealed, err := s.client.VerifiedProof(ctx, id, kept.Names)
	if err != nil {
		return nil, failed("read the revealed values", err)
	}
	out.State = backendv1.GetResultResponse_STATE_ACCEPTED
	out.DpgChecks = []*backendv1.GetResultResponse_DpgCheck{{Name: ProofCheckName, Passed: true}}
	var bound bool
	out.Presented, bound = proofViews(revealed, kept, known)
	if !bound {
		reason := "the request bound no credential definition or issuer DID, so a credential of any issuer could answer; the view names no issuer"
		if !kept.Indy {
			reason = "the definition bound no issuer, so a credential of any issuer could answer; the view names no issuer"
		}
		out.DpgChecks = append(out.DpgChecks, &backendv1.GetResultResponse_DpgCheck{
			Name: IssuerBoundCheckName, Passed: false, Reason: reason,
		})
	}
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
// the schema, the issuer, the schema, and the values in
// credentialSubject. The view carries no proof, because the agent
// checked the proof. An AnonCreds group has the format AnonCreds, and
// its issuer is the credential definition or the issuer DID that the
// request bound the part to. The agent checked that the proof meets
// that restriction. The platform reports the restriction of the request
// too, but with no restriction it reports the first credential of the
// proof, so the adapter never takes the issuer from it (ADR-064). A
// DIF PE group names no format, because the view is not the credential
// that the holder presented. The second value is false when an
// AnonCreds value came from a part that bound no issuer.
func proofViews(revealed []credebl.Revealed, rec proofRecord, known bool) ([]*commonv1.Credential, bool) {
	type group struct {
		schema, credDef, issuer string
		values                  map[string]string
	}
	indy := rec.Indy
	if !known {
		for _, r := range revealed {
			indy = indy || r.CredDefID != ""
		}
	}
	bound := true
	var order []string
	groups := map[string]*group{}
	for _, r := range revealed {
		src := group{schema: r.SchemaID}
		switch {
		case indy:
			p := rec.part(r.Name)
			src.credDef, src.issuer = p.CredDefID, p.Issuer
			if p.SchemaID != "" {
				src.schema = p.SchemaID
			}
			bound = bound && src.issuer != ""
		case known:
			// A DIF PE view names the issuer the definition bound; the
			// platform reports none of the presented credential.
			src.issuer = rec.part(r.Name).Issuer
			bound = bound && src.issuer != ""
		}
		key := src.schema + "|" + src.credDef + "|" + src.issuer
		g, ok := groups[key]
		if !ok {
			src.values = map[string]string{}
			g = &src
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
		if indy {
			format = commonv1.Format_FORMAT_ANONCREDS
		}
		if g.schema != "" {
			view["credentialSchema"] = map[string]string{"id": g.schema}
		}
		if g.credDef != "" {
			view["credentialDefinitionId"] = g.credDef
		}
		if g.issuer != "" {
			view["issuer"] = g.issuer
		}
		out = append(out, &commonv1.Credential{Format: format, Payload: anyval.Must(json.Marshal(view))})
	}
	return out, bound
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
			if a.Type != "" {
				if item.AttributeTypes == nil {
					item.AttributeTypes = map[string]string{}
				}
				item.AttributeTypes[a.Name] = a.Type
			}
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
