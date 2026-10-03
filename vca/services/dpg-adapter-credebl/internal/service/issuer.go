// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/credebl"
)

// RegisterCredentialConfiguration makes a published schema known to
// CREDEBL. It stores the schema and then a credential template. The
// template identifier is what an offer uses.
func (s *Service) RegisterCredentialConfiguration(
	ctx context.Context, req *connect.Request[backendv1.RegisterCredentialConfigurationRequest],
) (*connect.Response[backendv1.RegisterCredentialConfigurationResponse], error) {
	cfg := req.Msg.GetConfiguration()
	if cfg == nil || strings.TrimSpace(cfg.GetId()) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the configuration needs an id"))
	}
	switch cfg.GetFormat() {
	case commonv1.Format_FORMAT_ANONCREDS:
		return s.registerAnonCreds(ctx, cfg)
	case commonv1.Format_FORMAT_LDP_VC:
		return s.registerJSONLD(ctx, cfg)
	}
	if cfg.GetLedger() != "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("only an AnonCreds configuration names a ledger"))
	}
	format, err := wireFormat(cfg.GetFormat())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	attributes, aerr := attributesOf(cfg)
	if aerr != nil {
		return nil, aerr
	}
	// A template with the same name already answers for the schema.
	templates, terr := s.client.Templates(ctx)
	if terr != nil {
		return nil, failed("list the templates", terr)
	}
	if found, ok := credebl.FindTemplate(templates, cfg.GetId()); ok {
		return connect.NewResponse(&backendv1.RegisterCredentialConfigurationResponse{Id: found.ID}), nil
	}
	// A run that stored the schema and failed on the template stores no
	// second schema (ADR-077 decision 2).
	stored, ferr := s.findW3CSchema(ctx, cfg.GetId(), "")
	if ferr != nil {
		return nil, failed("read the schemas of the organisation", ferr)
	}
	if stored == "" {
		if _, serr := s.client.CreateSchema(ctx, cfg.GetId(), cfg.GetType(), attributes); serr != nil {
			return nil, failed("store the schema", serr)
		}
	}
	vct := cfg.GetType()
	id, cerr := s.client.CreateTemplate(ctx, cfg.GetId(), format, vct, attributes)
	if cerr != nil {
		return nil, failed("store the template", cerr)
	}
	return connect.NewResponse(&backendv1.RegisterCredentialConfigurationResponse{Id: id}), nil
}

// attributesOf reads the claim names of one configuration. The names
// come from the JSON Schema of the credential.
func attributesOf(cfg *backendv1.CredentialConfiguration) ([]credebl.Attribute, error) {
	raw := strings.TrimSpace(cfg.GetJsonSchema())
	if raw == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the configuration needs a json_schema with the claim names"))
	}
	var schema struct {
		Properties map[string]struct {
			Type string `json:"type"`
		} `json:"properties"`
		Required []string `json:"required"`
	}
	if err := json.Unmarshal([]byte(raw), &schema); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("json_schema is not valid JSON: %w", err))
	}
	if len(schema.Properties) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the JSON Schema names no property"))
	}
	disclosable := map[string]bool{}
	for _, name := range cfg.GetSdClaims() {
		disclosable[name] = true
	}
	names := make([]string, 0, len(schema.Properties))
	for name := range schema.Properties {
		names = append(names, name)
	}
	sortNames(names)
	out := make([]credebl.Attribute, 0, len(names))
	for _, name := range names {
		valueType := schema.Properties[name].Type
		if valueType == "" {
			valueType = "string"
		}
		out = append(out, credebl.Attribute{
			Key:       name,
			ValueType: valueType,
			// Every claim is disclosable when the schema names none.
			Disclose: len(disclosable) == 0 || disclosable[name],
		})
	}
	return out, nil
}

// sortNames sorts the values in place, so the template is the same on
// every run.
func sortNames(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

// CreateOffer builds a pre-authorized code offer for one subject.
//
// A validity window fails the call. The create offer endpoint of CREDEBL
// has no field for one, and the payload check rejects an extra claim. An
// operator who asks for an end date must get an error, and never a
// credential that is valid for ever.
func (s *Service) CreateOffer(
	ctx context.Context, req *connect.Request[backendv1.CreateOfferRequest],
) (*connect.Response[backendv1.CreateOfferResponse], error) {
	spec := req.Msg.GetSpec()
	if spec == nil || strings.TrimSpace(spec.GetConfigurationId()) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the request needs a spec with a configuration_id"))
	}
	channel := req.Msg.GetChannel()
	if channel == backendv1.Channel_CHANNEL_UNSPECIFIED {
		channel = backendv1.Channel_CHANNEL_OID4VCI_PREAUTH
	}
	if isDidcommChannel(channel) {
		return s.didcommOffer(ctx, req.Msg, channel)
	}
	if channel != backendv1.Channel_CHANNEL_OID4VCI_PREAUTH {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(
			"CREDEBL builds a pre-authorized code offer or a DIDComm offer, not the channel %s", channel))
	}
	if isDidcommFormat(spec.GetFormat()) {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(
			"CREDEBL issues %s over DIDComm only; use CHANNEL_DIDCOMM_OOB", spec.GetFormat()))
	}
	if hasWindow(spec.GetValidity()) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New(
			"CREDEBL has no field for a validity window; issue without one, or use another DPG"))
	}
	payload := map[string]any{}
	if raw := strings.TrimSpace(spec.GetSubjectData()); raw != "" {
		if err := json.Unmarshal([]byte(raw), &payload); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument,
				fmt.Errorf("subject_data is not a JSON object: %w", err))
		}
	}
	if len(payload) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("CREDEBL checks the payload against the template, so it needs the claims"))
	}
	templateID, err := s.templateID(ctx, spec.GetConfigurationId())
	if err != nil {
		return nil, err
	}
	offer, oerr := s.client.CreateOffer(ctx, templateID, s.defaultPin, payload, s.statusList)
	if oerr != nil {
		return nil, failed("create the offer", oerr)
	}
	out := &backendv1.CreateOfferResponse{
		OfferUri: credebl.RewritePublic(offer.URI, s.internalURL, s.publicURL),
		OfferId:  offer.SessionID,
		Channel:  backendv1.Channel_CHANNEL_OID4VCI_PREAUTH,
		Pin:      offer.PIN,
	}
	if s.statusList {
		// The credential carries an entry of the status list of the
		// stack, never the entry of VCA in the spec. The answer names
		// it, so VCA revokes through Revoke and not through a list no
		// verifier reads.
		entry, serr := s.offerStatus(ctx, offer.SessionID)
		if serr != nil {
			return nil, serr
		}
		out.Status, out.CredentialId = entry, offer.SessionID
	}
	return connect.NewResponse(out), nil
}

// offerStatus reads the status entry that the agent wrote into the
// credential of a revocable offer. The agent writes it when it creates
// the offer, so the session holds it before a wallet claims.
func (s *Service) offerStatus(ctx context.Context, sessionID string) (*backendv1.StatusListBinding, error) {
	session, err := s.client.OfferSession(ctx, sessionID)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, fmt.Errorf(
			"CREDEBL created the offer %s, but its status entry cannot be read: %w", sessionID, err))
	}
	for _, c := range session.Metadata.Credentials {
		if entry := statusBinding(session, c.SupportedID); entry != nil {
			return entry, nil
		}
	}
	return nil, connect.NewError(connect.CodeUnavailable, fmt.Errorf(
		"CREDEBL created the revocable offer %s with no status entry; check the status list host of the stack", sessionID))
}

// hasWindow reports whether the caller asked for a validity window.
func hasWindow(v *commonv1.ValidityWindow) bool {
	return v != nil && (v.GetValidFrom() != nil || v.GetValidUntil() != nil)
}

// templateID returns the CREDEBL template of one configuration id. The
// id is the template identifier, or the name of a template.
func (s *Service) templateID(ctx context.Context, configurationID string) (string, error) {
	templates, err := s.client.Templates(ctx)
	if err != nil {
		return "", failed("list the templates", err)
	}
	found, ok := credebl.FindTemplate(templates, configurationID)
	if !ok {
		return "", connect.NewError(connect.CodeNotFound, fmt.Errorf(
			"CREDEBL has no credential template %q; register the configuration first", configurationID))
	}
	return found.ID, nil
}

// Issue is not available. CREDEBL signs a credential only when a wallet
// redeems an offer.
func (s *Service) Issue(
	context.Context, *connect.Request[backendv1.IssueRequest],
) (*connect.Response[backendv1.IssueResponse], error) {
	return nil, unimplemented(
		"CREDEBL signs a credential only when a wallet claims an offer; use CreateOffer")
}

// Revoke revokes the credentials of one OID4VC issuance session. The
// credential id is the session id that CreateOffer returned. The agent
// sets the revoked bit in the status list of the stack and publishes the
// list again (P6-C5b). The platform sets a bit and never clears it, so a
// suspension and a reinstatement fail. Without a status list host the
// platform issues no status entry, and the status list services of VCA
// own the status bits instead (ADR-018, ADR-019).
func (s *Service) Revoke(
	ctx context.Context, req *connect.Request[backendv1.RevokeRequest],
) (*connect.Response[backendv1.RevokeResponse], error) {
	if !s.statusList {
		return nil, unimplemented(
			"CREDEBL revokes an OID4VC session only with a status list host, which this stack does not name; " +
				"call the status list service that owns the list")
	}
	m := req.Msg
	switch m.GetAction() {
	case backendv1.RevokeRequest_ACTION_UNSPECIFIED, backendv1.RevokeRequest_ACTION_REVOKE:
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(
			"CREDEBL revokes a credential and cannot %s it", strings.ToLower(strings.TrimPrefix(m.GetAction().String(), "ACTION_"))))
	}
	id := strings.TrimSpace(m.GetCredentialId())
	if id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the request needs the credential id, which is the issuance session"))
	}
	if strings.HasPrefix(id, DidcommOfferPrefix) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New(
			"CREDEBL revokes an OID4VC credential only; a DIDComm credential of this stack has no revocation registry"))
	}
	if err := s.client.RevokeSession(ctx, id); err != nil {
		return nil, failed("revoke the issuance session", err)
	}
	return connect.NewResponse(&backendv1.RevokeResponse{}), nil
}

// GetIssuerMetadata returns the OID4VCI issuer metadata of the adapter.
//
// The api gateway serves no metadata document, so the adapter builds one
// from the credential templates of the issuer.
func (s *Service) GetIssuerMetadata(
	ctx context.Context, _ *connect.Request[backendv1.GetIssuerMetadataRequest],
) (*connect.Response[backendv1.GetIssuerMetadataResponse], error) {
	templates, err := s.client.Templates(ctx)
	if err != nil {
		return nil, failed("list the templates", err)
	}
	configurations := configurations(templates)
	issuer := s.publicURL
	if issuer == "" {
		issuer = s.client.BaseURL()
	}
	document := map[string]any{
		"credential_issuer":                   issuer,
		"credential_configurations_supported": metadataEntries(templates),
	}
	raw, merr := json.Marshal(document)
	if merr != nil {
		return nil, connect.NewError(connect.CodeInternal, merr)
	}
	return connect.NewResponse(&backendv1.GetIssuerMetadataResponse{
		Issuer:         issuer,
		MetadataJson:   string(raw),
		Configurations: configurations,
	}), nil
}

// metadataEntries returns the credential configurations of the built
// metadata document.
func metadataEntries(templates []credebl.Template) map[string]any {
	out := make(map[string]any, len(templates))
	for _, t := range templates {
		entry := map[string]any{"format": t.Format}
		if t.Body.Vct != "" {
			entry["vct"] = t.Body.Vct
		}
		claims := map[string]any{}
		for _, a := range t.Body.Attributes {
			claims[a.Key] = map[string]any{"mandatory": true}
		}
		if len(claims) > 0 {
			entry["claims"] = claims
		}
		out[t.ID] = entry
	}
	return out
}

// ListCredentialTypes returns one page of the CREDEBL templates.
func (s *Service) ListCredentialTypes(
	ctx context.Context, req *connect.Request[backendv1.ListCredentialTypesRequest],
) (*connect.Response[backendv1.ListCredentialTypesResponse], error) {
	templates, err := s.client.Templates(ctx)
	if err != nil {
		return nil, failed("list the templates", err)
	}
	all := configurations(templates)
	size := int(req.Msg.GetPage().GetPageSize())
	if size <= 0 || size > s.pageSizeMax {
		size = s.pageSizeMax
	}
	start := 0
	if token := req.Msg.GetPage().GetPageToken(); token != "" {
		if n, perr := parseToken(token); perr == nil {
			start = n
		}
	}
	page := &commonv1.PageResult{TotalSize: int64(len(all))}
	if start >= len(all) {
		return connect.NewResponse(&backendv1.ListCredentialTypesResponse{Page: page}), nil
	}
	end := start + size
	if end < len(all) {
		page.NextPageToken = fmt.Sprintf("%d", end)
	} else {
		end = len(all)
	}
	return connect.NewResponse(&backendv1.ListCredentialTypesResponse{
		Configurations: all[start:end],
		Page:           page,
	}), nil
}
