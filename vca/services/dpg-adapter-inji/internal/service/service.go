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
	"google.golang.org/protobuf/types/known/timestamppb"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/inji"
	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// DefaultCADomain is the partner domain the stack allows for a CA
// certificate (mosip.kernel.partner.allowed.domains).
const DefaultCADomain = "DEVICE"

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
	// Plugins name the plugins of the Certify deployment for the DPG
	// information.
	Plugins []string
	// CADomain is the partner domain of an uploaded CA certificate.
	CADomain string
	// PresentationDuringIssuance says that Certify checks a presentation
	// through its interactive authorization endpoint: its verify service
	// and its presentation definition are set. An offer can then ask the
	// holder to present a credential first.
	PresentationDuringIssuance bool
	// RenderingTemplateID names the SVG template of the Certify
	// deployment. A registered ldp_vc configuration then names it as its
	// render method. Empty names none.
	RenderingTemplateID string
	// Profiles name the Certify keys of each format. The zero value
	// selects inji.DefaultProfiles.
	Profiles inji.Profiles
	// Versions maps each stack component onto its pinned version for
	// the capability answer. The configuration supplies it.
	Versions map[string]string
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
	versions            map[string]string
	profiles            inji.Profiles
	renderingTemplateID string
	plugins             []string
	caDomain            string
	presentation        bool
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
	if opts.CADomain == "" {
		opts.CADomain = DefaultCADomain
	}
	if opts.Profiles.Ldp == (inji.SigningProfile{}) && opts.Profiles.SdJwt == (inji.SigningProfile{}) &&
		opts.Profiles.Mdoc == (inji.SigningProfile{}) {
		did := opts.Profiles.DidURL
		opts.Profiles = inji.DefaultProfiles()
		opts.Profiles.DidURL = did
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
		versions:            opts.Versions,
		profiles:            opts.Profiles,
		renderingTemplateID: opts.RenderingTemplateID,
		plugins:             opts.Plugins,
		caDomain:            opts.CADomain,
		presentation:        opts.PresentationDuringIssuance,
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
		// The three formats the configuration API of Certify 0.14.0
		// registers and its credential endpoint issues.
		out.Formats = []commonv1.Format{
			commonv1.Format_FORMAT_LDP_VC,
			commonv1.Format_FORMAT_VC_SD_JWT,
			commonv1.Format_FORMAT_MSO_MDOC,
		}
		// The adapter runs the pre-authorized flow end to end, so the
		// deployment can hand a citizen a paper document as well
		// (ADR-016 decision 3). A configuration with identity claims
		// makes Certify sign a Claim 169 QR code beside the credential,
		// which Issue returns (ADR-043 decision 1).
		// The authorization code offer names the configured identity
		// provider, else the authorization server Certify names in its
		// metadata: eSignet in the stack file.
		out.Channels = []backendv1.Channel{
			backendv1.Channel_CHANNEL_OID4VCI_PREAUTH,
			backendv1.Channel_CHANNEL_PDF,
			backendv1.Channel_CHANNEL_CLAIM169_QR,
			backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE,
		}
		out.Protocols = append(out.Protocols, backendv1.Protocol_PROTOCOL_OID4VCI)
		// RegisterCredentialConfiguration writes the configuration API of
		// Certify (ADR-045 decision 1).
		// Revoke and ListIssuedCredentials drive the ledger and the
		// status API of Certify. The stack allows the revocation purpose
		// only, so FEATURE_SUSPENSION stays off.
		out.Features = append(out.Features, backendv1.Feature_FEATURE_CREDENTIAL_CONFIG_API,
			backendv1.Feature_FEATURE_REVOCATION, backendv1.Feature_FEATURE_ISSUED_LEDGER,
			// The identity RPCs read the did:web of Certify and drive its
			// key manager. Certify reads its DID from its configuration,
			// so a DID import is not listed.
			backendv1.Feature_FEATURE_ISSUER_IDENTITY_PROVISION, backendv1.Feature_FEATURE_ISSUER_IDENTITY_IMPORT_X509)
		if s.presentation {
			// CreateOffer points the wallet at the interactive
			// authorization endpoint of Certify, which asks for a
			// presentation before it gives a code.
			out.Features = append(out.Features, backendv1.Feature_FEATURE_PRESENTATION_DURING_ISSUANCE)
		}
		out.DidMethods = []string{didWeb}
		for _, k := range inji.KeyTypes {
			out.KeyTypes = append(out.KeyTypes, k.Type)
		}
		// The staged claims carry the two status markers, so a credential
		// points at a token status list or a bitstring status list
		// (ADR-018, ADR-019).
		out.StatusMechanisms = []backendv1.StatusListBinding_Kind{
			backendv1.StatusListBinding_KIND_BITSTRING,
			backendv1.StatusListBinding_KIND_TOKEN,
		}
	}
	if s.verify != nil {
		out.Roles = append(out.Roles, commonv1.Role_ROLE_VERIFIER)
		out.Protocols = append(out.Protocols,
			backendv1.Protocol_PROTOCOL_OID4VP, backendv1.Protocol_PROTOCOL_OID4VP_PEX)
		// VerifyCredential calls the credential check of Inji Verify.
		out.Features = append(out.Features, backendv1.Feature_FEATURE_VERIFY_UPLOAD)
	}
	out.DpgInfo = s.dpgInfo()
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
		if entry.Doctype != "" {
			cfg.Type = entry.Doctype
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
	case "mso_mdoc":
		return commonv1.Format_FORMAT_MSO_MDOC
	default:
		return commonv1.Format_FORMAT_UNSPECIFIED
	}
}
