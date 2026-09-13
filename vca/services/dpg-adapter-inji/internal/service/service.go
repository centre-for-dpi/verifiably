// SPDX-License-Identifier: Apache-2.0

// Package service serves the vca.backend.v1 services against Inji
// Certify and Inji Verify (ADR-002 decision 2). Inji ships no wallet, so
// the holder service answers with the Connect code Unimplemented.
package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"connectrpc.com/connect"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/inji"
	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// AdapterName is the name the capability answer carries.
const AdapterName = "dpg-adapter-inji"

// Options configure New.
type Options struct {
	// Certify calls the Inji Certify issuer. Nil turns the issuer role
	// off.
	Certify *inji.Certify
	// Verify calls the Inji Verify service. Nil turns the verifier role
	// off.
	Verify *inji.Verify
	// Store keeps the hosted authorization code offers.
	Store store.KeyValue
	// ProofKey signs the holder proof of the pre-authorized flow.
	ProofKey *inji.ProofKey
	// DpgVersion names the Inji release.
	DpgVersion string
	// PublicURL is the address a wallet reaches this adapter on.
	PublicURL string
	// OfferIssuer is the credential_issuer of a hosted offer.
	OfferIssuer string
	// AuthorizationServer is the identity provider of the authorization
	// code flow.
	AuthorizationServer string
	// OfferTTL is the life of a hosted offer.
	OfferTTL time.Duration
	// PageSizeMax caps a list page.
	PageSizeMax int
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
	// NewID returns a new random identifier. Nil uses crypto/rand.
	NewID func() string
}

// Service implements every vca.backend.v1 service of this adapter.
type Service struct {
	certify             *inji.Certify
	verify              *inji.Verify
	store               store.KeyValue
	proofKey            *inji.ProofKey
	dpgVersion          string
	publicURL           string
	offerIssuer         string
	authorizationServer string
	offerTTL            time.Duration
	pageSizeMax         int
	now                 func() time.Time
	newID               func() string
}

// New returns the service.
func New(opts Options) (*Service, error) {
	if opts.Store == nil {
		return nil, errors.New("service: no store")
	}
	if opts.Certify == nil && opts.Verify == nil {
		return nil, errors.New("service: neither Inji Certify nor Inji Verify is configured")
	}
	if opts.ProofKey == nil {
		opts.ProofKey = inji.NewProofKey()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.NewID == nil {
		opts.NewID = randomID
	}
	if opts.PageSizeMax <= 0 {
		opts.PageSizeMax = 50
	}
	if opts.OfferTTL <= 0 {
		opts.OfferTTL = 15 * time.Minute
	}
	return &Service{
		certify:             opts.Certify,
		verify:              opts.Verify,
		store:               opts.Store,
		proofKey:            opts.ProofKey,
		dpgVersion:          opts.DpgVersion,
		publicURL:           strings.TrimRight(opts.PublicURL, "/"),
		offerIssuer:         opts.OfferIssuer,
		authorizationServer: opts.AuthorizationServer,
		offerTTL:            opts.OfferTTL,
		pageSizeMax:         opts.PageSizeMax,
		now:                 opts.Now,
		newID:               opts.NewID,
	}, nil
}

// Ready reports whether the service can take traffic.
func (s *Service) Ready() bool { return s != nil && s.store != nil }

// unimplemented returns a Connect error that names the missing role.
func unimplemented(text string) *connect.Error {
	return connect.NewError(connect.CodeUnimplemented, errors.New(text))
}

// failed maps a call error onto a Connect error.
func failed(action string, err error) *connect.Error {
	code := connect.CodeUnavailable
	switch {
	case dpgclient.IsStatus(err, 400), dpgclient.IsStatus(err, 422):
		code = connect.CodeInvalidArgument
	case dpgclient.IsStatus(err, 401), dpgclient.IsStatus(err, 403):
		code = connect.CodePermissionDenied
	case dpgclient.IsStatus(err, 404):
		code = connect.CodeNotFound
	}
	return connect.NewError(code, fmt.Errorf("%s: %w", action, err))
}

// GetCapabilities reports the formats, channels, roles, and protocols of
// the Inji deployment (ADR-016 decision 6).
func (s *Service) GetCapabilities(
	_ context.Context, _ *connect.Request[backendv1.GetCapabilitiesRequest],
) (*connect.Response[backendv1.GetCapabilitiesResponse], error) {
	out := &backendv1.GetCapabilitiesResponse{
		Adapter:    AdapterName,
		DpgVersion: s.dpgVersion,
	}
	if s.certify != nil {
		out.Roles = append(out.Roles, commonv1.Role_ROLE_ISSUER)
		out.Formats = []commonv1.Format{
			commonv1.Format_FORMAT_LDP_VC,
			commonv1.Format_FORMAT_VC_SD_JWT,
		}
		// The adapter runs the pre-authorized flow end to end, so the
		// deployment can hand a citizen a paper document as well
		// (ADR-016 decision 3).
		out.Channels = []backendv1.Channel{
			backendv1.Channel_CHANNEL_OID4VCI_PREAUTH,
			backendv1.Channel_CHANNEL_PDF,
		}
		if s.authorizationServer != "" {
			out.Channels = append(out.Channels, backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE)
		}
		out.Protocols = append(out.Protocols, backendv1.Protocol_PROTOCOL_OID4VCI)
	}
	if s.verify != nil {
		out.Roles = append(out.Roles, commonv1.Role_ROLE_VERIFIER)
		out.Protocols = append(out.Protocols,
			backendv1.Protocol_PROTOCOL_OID4VP, backendv1.Protocol_PROTOCOL_OID4VP_PEX)
	}
	return connect.NewResponse(out), nil
}

// Register is not available. Inji ships no wallet for a citizen.
func (s *Service) Register(
	context.Context, *connect.Request[backendv1.RegisterRequest],
) (*connect.Response[backendv1.RegisterResponse], error) {
	return nil, unimplemented(holderMessage)
}

// ListCredentials is not available. Inji ships no wallet for a citizen.
func (s *Service) ListCredentials(
	context.Context, *connect.Request[backendv1.ListCredentialsRequest],
) (*connect.Response[backendv1.ListCredentialsResponse], error) {
	return nil, unimplemented(holderMessage)
}

// AcceptOffer is not available. Inji ships no wallet for a citizen.
func (s *Service) AcceptOffer(
	context.Context, *connect.Request[backendv1.AcceptOfferRequest],
) (*connect.Response[backendv1.AcceptOfferResponse], error) {
	return nil, unimplemented(holderMessage)
}

// Present is not available. Inji ships no wallet for a citizen.
func (s *Service) Present(
	context.Context, *connect.Request[backendv1.PresentRequest],
) (*connect.Response[backendv1.PresentResponse], error) {
	return nil, unimplemented(holderMessage)
}

// DeleteCredential is not available. Inji ships no wallet for a citizen.
func (s *Service) DeleteCredential(
	context.Context, *connect.Request[backendv1.DeleteCredentialRequest],
) (*connect.Response[backendv1.DeleteCredentialResponse], error) {
	return nil, unimplemented(holderMessage)
}

// holderMessage says what to use instead of the holder role.
const holderMessage = "Inji ships no wallet for a citizen; " +
	"use the wallet portal, an external OID4VCI wallet, or the document channel"

// timestamp returns a protobuf time or nil for the zero time.
func timestamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// configurations maps the Inji catalogue onto the contract message in a
// stable order.
func configurations(meta inji.Metadata) []*backendv1.CredentialConfiguration {
	ids := make([]string, 0, len(meta.Configurations))
	for id := range meta.Configurations {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]*backendv1.CredentialConfiguration, 0, len(ids))
	for _, id := range ids {
		entry := meta.Configurations[id]
		cfg := &backendv1.CredentialConfiguration{
			Id:     id,
			Format: contractFormat(entry.Format),
			Type:   entry.Vct,
		}
		if entry.CredentialDefinition != nil && len(entry.CredentialDefinition.Type) > 0 {
			types := entry.CredentialDefinition.Type
			cfg.Type = types[len(types)-1]
		}
		if len(entry.Display) > 0 {
			cfg.Display = string(entry.Display[0])
		}
		cfg.SdClaims = entry.Order
		out = append(out, cfg)
	}
	return out
}

// contractFormat maps an Inji wire format onto the contract format.
func contractFormat(format string) commonv1.Format {
	switch format {
	case "ldp_vc":
		return commonv1.Format_FORMAT_LDP_VC
	case "vc+sd-jwt":
		return commonv1.Format_FORMAT_VC_SD_JWT
	case "dc+sd-jwt":
		return commonv1.Format_FORMAT_DC_SD_JWT
	case "jwt_vc_json":
		return commonv1.Format_FORMAT_JWT_VC_JSON
	default:
		return commonv1.Format_FORMAT_UNSPECIFIED
	}
}
