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
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/waltid"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// CreateOffer builds an OID4VCI credential offer. walt.id answers with
// the offer URI as plain text.
func (s *Service) CreateOffer(
	ctx context.Context, req *connect.Request[backendv1.CreateOfferRequest],
) (*connect.Response[backendv1.CreateOfferResponse], error) {
	if !s.client.HasIssuer() {
		return nil, unimplemented("this adapter has no issuer URL, so it cannot create an offer")
	}
	spec := req.Msg.GetSpec()
	if spec == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the request needs a spec"))
	}
	channel := req.Msg.GetChannel()
	if channel == backendv1.Channel_CHANNEL_UNSPECIFIED {
		channel = backendv1.Channel_CHANNEL_OID4VCI_PREAUTH
	}
	if channel != backendv1.Channel_CHANNEL_OID4VCI_PREAUTH &&
		channel != backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("the walt.id adapter serves the two OID4VCI channels only, not %s", channel))
	}
	issuance, err := s.buildIssuance(ctx, spec, channel == backendv1.Channel_CHANNEL_OID4VCI_PREAUTH)
	if err != nil {
		return nil, err
	}
	path, perr := waltid.IssuePath(waltid.Format(issuanceFormat(issuance)))
	if perr != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, perr)
	}
	offerID, callbackURL, err := s.newCallback(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	uri, cerr := s.client.CreateOffer(ctx, path, issuance.request, callbackURL)
	if cerr != nil {
		return nil, failed("create the offer", cerr)
	}
	if offerID == "" {
		offerID = waltid.StateFromAuthorizeURL(uri)
	}
	return connect.NewResponse(&backendv1.CreateOfferResponse{
		OfferUri: uri,
		OfferId:  offerID,
		Channel:  channel,
	}), nil
}

// built holds the issuance request and the format it uses.
type built struct {
	request waltid.IssuanceRequest
	format  waltid.Format
}

func issuanceFormat(b built) string { return string(b.format) }

// buildIssuance turns an issue spec into the walt.id issuance request.
func (s *Service) buildIssuance(ctx context.Context, spec *backendv1.IssueSpec, preAuthorized bool) (built, error) {
	reg, err := s.registrationFor(ctx, spec)
	if err != nil {
		return built{}, err
	}
	subject, err := subjectClaims(spec)
	if err != nil {
		return built{}, err
	}
	key, did, kerr := s.client.EnsureIssuerKey(ctx)
	if kerr != nil {
		return built{}, failed("onboard the issuer key", kerr)
	}
	format := waltid.Format(reg.Format)
	request := waltid.IssuanceRequest{
		IssuerKey:                 key,
		IssuerDid:                 did,
		CredentialConfigurationID: reg.ConfigurationID,
		AuthenticationMethod:      waltid.AuthenticationMethod(preAuthorized),
		StandardVersion:           strings.ToUpper(s.standardVersion),
	}
	if _, _, x5c := s.client.Issuer(); len(x5c) > 0 {
		request.X5Chain = x5c
	}
	status := statusEntry(spec.GetStatus())
	validity := validityWindow(spec.GetValidity())
	switch {
	case waltid.IsSdJwt(format):
		body, berr := waltid.BuildSdJwtCredential(subject, status, validity)
		if berr != nil {
			return built{}, connect.NewError(connect.CodeInternal, berr)
		}
		request.CredentialData = body
		request.SelectiveDisclosure = waltid.BuildSelectiveDisclosure(subject)
		request.Vct = reg.Vct
	case format == waltid.FormatMsoMdoc:
		body, berr := waltid.BuildMdocData(reg.Doctype, subject)
		if berr != nil {
			return built{}, connect.NewError(connect.CodeInvalidArgument, berr)
		}
		request.MdocData = body
	default:
		if raw := strings.TrimSpace(spec.GetCredentialData()); raw != "" {
			// The caller sent a whole credential body. Only a VCDM
			// format honours it.
			if !json.Valid([]byte(raw)) {
				return built{}, connect.NewError(connect.CodeInvalidArgument,
					errors.New("credential_data is not valid JSON"))
			}
			request.CredentialData = json.RawMessage(raw)
			break
		}
		body, berr := waltid.BuildVcdmCredential(reg.Types, subject, status, validity)
		if berr != nil {
			return built{}, connect.NewError(connect.CodeInternal, berr)
		}
		request.CredentialData = body
	}
	return built{request: request, format: format}, nil
}

// registrationFor returns the stored registration of the configuration,
// or one built from the walt.id catalog when the caller never registered
// the configuration.
func (s *Service) registrationFor(ctx context.Context, spec *backendv1.IssueSpec) (registration, error) {
	id := strings.TrimSpace(spec.GetConfigurationId())
	if id == "" {
		return registration{}, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the spec needs a configuration_id"))
	}
	raw, err := s.store.Get(ctx, registrationKey(id))
	if err == nil {
		var reg registration
		if jerr := json.Unmarshal(raw, &reg); jerr != nil {
			return registration{}, connect.NewError(connect.CodeInternal, jerr)
		}
		if spec.GetFormat() != commonv1.Format_FORMAT_UNSPECIFIED {
			// The format of the request wins when the caller sets one.
			if f, ferr := wireFormat(spec.GetFormat()); ferr == nil {
				reg.Format = string(f)
			}
		}
		return reg, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return registration{}, connect.NewError(connect.CodeInternal, err)
	}
	// The configuration is not registered. It must be one the walt.id
	// catalog already advertises.
	meta, merr := s.client.Metadata(ctx)
	if merr != nil {
		return registration{}, failed("read the issuer metadata", merr)
	}
	entry, ok := meta.CredentialConfigurationsSupported[id]
	if !ok {
		return registration{}, connect.NewError(connect.CodeNotFound, fmt.Errorf(
			"the walt.id issuer does not advertise the configuration %q; register it first", id))
	}
	reg := registration{ConfigurationID: id, Format: entry.Format, Vct: entry.Vct}
	if entry.CredentialDefinition != nil {
		reg.Types = entry.CredentialDefinition.Type
	}
	if waltid.Format(entry.Format) == waltid.FormatMsoMdoc {
		reg.Doctype = id
	}
	return reg, nil
}

// subjectClaims reads the subject data of the spec and adds the subject
// DID when the flow knows it.
func subjectClaims(spec *backendv1.IssueSpec) (map[string]any, error) {
	out := map[string]any{}
	if raw := strings.TrimSpace(spec.GetSubjectData()); raw != "" {
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument,
				fmt.Errorf("subject_data is not a JSON object: %w", err))
		}
	}
	if did := spec.GetSubject().GetDid(); did != "" {
		out["id"] = did
	}
	return out, nil
}

// statusEntry maps the status binding onto the walt.id status entry.
func statusEntry(b *backendv1.StatusListBinding) waltid.StatusEntry {
	if b == nil || b.GetPublishUrl() == "" {
		return waltid.StatusEntry{}
	}
	return waltid.StatusEntry{
		Bitstring: b.GetKind() == backendv1.StatusListBinding_KIND_BITSTRING,
		Token:     b.GetKind() == backendv1.StatusListBinding_KIND_TOKEN,
		Index:     b.GetIndex(),
		URL:       b.GetPublishUrl(),
	}
}

// validityWindow maps the contract window onto the walt.id window.
func validityWindow(v *commonv1.ValidityWindow) waltid.Validity {
	var out waltid.Validity
	if v == nil {
		return out
	}
	if from := v.GetValidFrom(); from != nil {
		out.From = from.AsTime()
	}
	if until := v.GetValidUntil(); until != nil {
		out.Until = until.AsTime()
	}
	return out
}

// Issue is not available. walt.id 0.18.2 signs a credential only when a
// wallet redeems an offer, so the adapter has no endpoint that returns
// credential bytes.
func (s *Service) Issue(
	context.Context, *connect.Request[backendv1.IssueRequest],
) (*connect.Response[backendv1.IssueResponse], error) {
	return nil, unimplemented(
		"walt.id 0.18.2 signs a credential only when a wallet claims an offer; use CreateOffer")
}

// IssueBatch is not available for the same reason as Issue.
func (s *Service) IssueBatch(
	context.Context, *connect.Request[backendv1.IssueBatchRequest],
) (*connect.Response[backendv1.IssueBatchResponse], error) {
	return nil, unimplemented(
		"walt.id 0.18.2 has no batch credential endpoint; call CreateOffer once per subject")
}

// Revoke is not available. The status list services of VCA own the
// status bits (ADR-018, ADR-019), and walt.id has no revocation API.
func (s *Service) Revoke(
	context.Context, *connect.Request[backendv1.RevokeRequest],
) (*connect.Response[backendv1.RevokeResponse], error) {
	return nil, unimplemented(
		"walt.id has no revocation API; call the status list service that owns the list")
}

// GetIssuerMetadata returns the OID4VCI issuer metadata of walt.id.
func (s *Service) GetIssuerMetadata(
	ctx context.Context, _ *connect.Request[backendv1.GetIssuerMetadataRequest],
) (*connect.Response[backendv1.GetIssuerMetadataResponse], error) {
	if !s.client.HasIssuer() {
		return nil, unimplemented("this adapter has no issuer URL, so it has no issuer metadata")
	}
	meta, err := s.client.Metadata(ctx)
	if err != nil {
		return nil, failed("read the issuer metadata", err)
	}
	_, did, kerr := s.client.EnsureIssuerKey(ctx)
	if kerr != nil {
		// The metadata is still useful without the DID.
		did = ""
	}
	return connect.NewResponse(&backendv1.GetIssuerMetadataResponse{
		Issuer:         meta.CredentialIssuer,
		IssuerDid:      did,
		MetadataJson:   string(meta.Raw),
		Configurations: configurations(meta),
	}), nil
}
