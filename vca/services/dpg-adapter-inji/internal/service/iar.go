// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/inji"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// definitionKey is the store key of the presentation definition of a
// presentation during issuance (ADR-051 decision 6). requirementKey
// keeps the request that made it, so the settings card reads it back.
const (
	definitionKey  = "iar/definition"
	requirementKey = "iar/requirement"
)

// SetPresentationRequirement stores the credential a holder presents
// before Certify issues. Certify reads the definition from the plain
// HTTP handler of the adapter at each interactive authorization, so a
// change needs no restart.
func (s *Service) SetPresentationRequirement(
	ctx context.Context, req *connect.Request[backendv1.SetPresentationRequirementRequest],
) (*connect.Response[backendv1.SetPresentationRequirementResponse], error) {
	if !s.presentation {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New(
			"this Inji deployment checks no presentation during issuance; set VCA_INJI_PRESENTATION_DURING_ISSUANCE once Certify reaches Inji Verify"))
	}
	out := &backendv1.SetPresentationRequirementResponse{IdentityClaims: s.iarIdentity}
	if req.Msg.GetClear() {
		for _, key := range []string{definitionKey, requirementKey} {
			if err := s.store.Delete(ctx, key); err != nil {
				return nil, connect.NewError(connect.CodeInternal, err)
			}
		}
		return connect.NewResponse(out), nil
	}
	definition, err := presentationDefinition(req.Msg, s.newID())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	requirement, err := protojson.Marshal(req.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := s.store.Put(ctx, requirementKey, requirement); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := s.store.Put(ctx, definitionKey, definition); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out.DefinitionJson = string(definition)
	return connect.NewResponse(out), nil
}

// GetPresentationRequirement returns the requirement the issuer stored,
// with the definition and the claims that can identify a holder.
func (s *Service) GetPresentationRequirement(
	ctx context.Context, _ *connect.Request[backendv1.GetPresentationRequirementRequest],
) (*connect.Response[backendv1.GetPresentationRequirementResponse], error) {
	if !s.presentation {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New(
			"this Inji deployment checks no presentation during issuance; set VCA_INJI_PRESENTATION_DURING_ISSUANCE once Certify reaches Inji Verify"))
	}
	out := &backendv1.GetPresentationRequirementResponse{IdentityClaims: s.iarIdentity}
	raw, err := s.store.Get(ctx, requirementKey)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return connect.NewResponse(out), nil
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	requirement := &backendv1.SetPresentationRequirementRequest{}
	if err := protojson.Unmarshal(raw, requirement); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out.Requirement = requirement
	if definition, ok := s.PresentationDefinition(ctx); ok {
		out.DefinitionJson = string(definition)
	}
	return connect.NewResponse(out), nil
}

// PresentationDefinition returns the stored definition. The plain HTTP
// handler of the adapter serves it to Certify.
func (s *Service) PresentationDefinition(ctx context.Context) ([]byte, bool) {
	raw, err := s.store.Get(ctx, definitionKey)
	if err != nil || len(raw) == 0 {
		return nil, false
	}
	return raw, true
}

// presentationDefinition builds the file that Certify reads at
// mosip.certify.vp-request.config-file-url: a DIF Presentation Exchange
// definition in the shape of the release (see the SOURCE.md of the
// Certify folder of the stack). The type filter follows that shape.
func presentationDefinition(in *backendv1.SetPresentationRequirementRequest, id string) ([]byte, error) {
	typ := strings.TrimSpace(in.GetCredentialType())
	if typ == "" {
		return nil, errors.New("name the type of the credential to present")
	}
	var format map[string]any
	typePath, claimPrefix := "", ""
	switch in.GetFormat() {
	case commonv1.Format_FORMAT_LDP_VC, commonv1.Format_FORMAT_UNSPECIFIED:
		format = map[string]any{"ldp_vc": map[string]any{"proof_type": inji.ProofSuites()}}
		typePath, claimPrefix = "$.type", "$.credentialSubject."
	case commonv1.Format_FORMAT_VC_SD_JWT, commonv1.Format_FORMAT_DC_SD_JWT:
		name := wireFormat(in.GetFormat())
		format = map[string]any{name: map[string]any{
			"sd-jwt_alg_values": []string{"ES256", "EdDSA"}, "kb-jwt_alg_values": []string{"ES256", "EdDSA"},
		}}
		typePath, claimPrefix = "$.vct", "$."
	default:
		return nil, fmt.Errorf("a presentation during issuance takes an ldp_vc or an SD-JWT VC, not %s", in.GetFormat())
	}
	fields := []map[string]any{{
		"path": []string{typePath}, "filter": map[string]any{"type": "string", "pattern": typ},
	}}
	claimNames := append([]string(nil), in.GetRequiredClaims()...)
	sort.Strings(claimNames)
	for _, name := range claimNames {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if !inji.TemplateName(name) {
			return nil, fmt.Errorf("the claim name %q holds a character a path cannot", name)
		}
		fields = append(fields, map[string]any{"path": []string{claimPrefix + name}})
	}
	definition := map[string]any{
		"id":      "vca-" + id,
		"name":    typ,
		"purpose": strings.TrimSpace(in.GetPurpose()),
		"input_descriptors": []map[string]any{{
			"id": "vca-presented-credential", "format": format,
			"constraints": map[string]any{"fields": fields},
		}},
	}
	return json.Marshal(map[string]any{"presentation_definition": definition})
}
