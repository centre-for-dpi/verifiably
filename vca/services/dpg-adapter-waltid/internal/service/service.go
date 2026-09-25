// SPDX-License-Identifier: Apache-2.0

// Package service serves the vca.backend.v1 services against the
// walt.id stack (ADR-002 decision 2). A role the stack does not support
// answers with the Connect code Unimplemented and a message that says
// what to use instead.
package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/waltid"
	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// AdapterName is the name the capability answer carries.
const AdapterName = "dpg-adapter-waltid"

// Options configure New.
type Options struct {
	// Client talks to the walt.id stack.
	Client *waltid.Client
	// Store keeps the wallet sessions and the registered credential
	// configurations.
	Store store.KeyValue
	// DpgVersion names the walt.id release.
	DpgVersion string
	// StandardVersion is the OID4VCI draft name walt.id serves.
	StandardVersion string
	// VctBase is the base URL of the vct of a custom SD-JWT credential.
	VctBase string
	// PageSizeMax caps a list page.
	PageSizeMax int
	// Versions maps each stack component onto its pinned version for
	// the capability answer. The configuration supplies it.
	Versions map[string]string
	// IdentityFile keeps the issuer identity with mode 0600 (ADR-046
	// decision 4). Empty keeps it in memory. The service reads the file
	// at start.
	IdentityFile string
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

// Service implements every vca.backend.v1 service of this adapter.
type Service struct {
	client          *waltid.Client
	store           store.KeyValue
	dpgVersion      string
	standardVersion string
	vctBase         string
	pageSizeMax     int
	versions        map[string]string
	now             func() time.Time
	identityFile    string

	idMu        sync.Mutex
	identity    identityState
	hasIdentity bool
}

// New returns the service.
func New(opts Options) (*Service, error) {
	if opts.Client == nil {
		return nil, errors.New("service: no walt.id client")
	}
	if opts.Store == nil {
		return nil, errors.New("service: no store")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.PageSizeMax <= 0 {
		opts.PageSizeMax = 50
	}
	if opts.StandardVersion == "" {
		opts.StandardVersion = "draft13"
	}
	s := &Service{
		client:          opts.Client,
		store:           opts.Store,
		dpgVersion:      opts.DpgVersion,
		standardVersion: opts.StandardVersion,
		vctBase:         strings.TrimRight(opts.VctBase, "/"),
		pageSizeMax:     opts.PageSizeMax,
		versions:        opts.Versions,
		now:             opts.Now,
		identityFile:    opts.IdentityFile,
	}
	if err := s.loadStateFile(); err != nil {
		return nil, err
	}
	opts.Client.OnOnboard(s.keepOnboarded)
	return s, nil
}

// Ready reports whether the service can take traffic.
func (s *Service) Ready() bool { return s != nil && s.client != nil }

// unimplemented returns a Connect error that names the missing role.
func unimplemented(text string) *connect.Error {
	return connect.NewError(connect.CodeUnimplemented, errors.New(text))
}

// failed maps a call error onto a Connect error. A status from walt.id
// keeps its meaning, so the caller can tell a bad request from an outage.
func failed(action string, err error) *connect.Error {
	code := connect.CodeUnavailable
	switch {
	case dpgclient.IsStatus(err, 400), dpgclient.IsStatus(err, 422):
		code = connect.CodeInvalidArgument
	case dpgclient.IsStatus(err, 401), dpgclient.IsStatus(err, 403):
		code = connect.CodePermissionDenied
	case dpgclient.IsStatus(err, 404):
		code = connect.CodeNotFound
	case dpgclient.IsStatus(err, 409):
		code = connect.CodeAlreadyExists
	}
	return connect.NewError(code, fmt.Errorf("%s: %w", action, err))
}

// GetCapabilities reports the formats, channels, roles, and protocols of
// the walt.id stack (ADR-016 decision 6).
func (s *Service) GetCapabilities(
	_ context.Context, _ *connect.Request[backendv1.GetCapabilitiesRequest],
) (*connect.Response[backendv1.GetCapabilitiesResponse], error) {
	out := &backendv1.GetCapabilitiesResponse{
		Adapter:    AdapterName,
		DpgVersion: s.dpgVersion,
	}
	if s.client.HasIssuer() {
		out.Roles = append(out.Roles, commonv1.Role_ROLE_ISSUER)
		out.Formats = []commonv1.Format{
			commonv1.Format_FORMAT_JWT_VC_JSON,
			commonv1.Format_FORMAT_VC_SD_JWT,
			commonv1.Format_FORMAT_DC_SD_JWT,
			commonv1.Format_FORMAT_MSO_MDOC,
		}
		out.Channels = []backendv1.Channel{
			backendv1.Channel_CHANNEL_OID4VCI_PREAUTH,
			backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE,
		}
		out.Protocols = append(out.Protocols, backendv1.Protocol_PROTOCOL_OID4VCI)
		// RegisterCredentialConfiguration works, so a schema can go to
		// the stack. The onboarding endpoint makes an identity, and every
		// issuance request takes a key object with a DID or an X.509
		// chain, so both imports work (ADR-046). Revoke,
		// GetIssuanceStatus, and IssueBatch answer Unimplemented, so their
		// features stay off the list.
		out.Features = []backendv1.Feature{
			backendv1.Feature_FEATURE_CREDENTIAL_CONFIG_API,
			backendv1.Feature_FEATURE_ISSUER_IDENTITY_PROVISION,
			backendv1.Feature_FEATURE_ISSUER_IDENTITY_IMPORT_DID,
			backendv1.Feature_FEATURE_ISSUER_IDENTITY_IMPORT_X509,
		}
		out.DidMethods = append([]string(nil), DidMethods...)
		out.KeyTypes = append([]string(nil), KeyTypes...)
		// The issued credential carries the status entry the caller
		// binds, of either list kind (ADR-018, ADR-019).
		out.StatusMechanisms = []backendv1.StatusListBinding_Kind{
			backendv1.StatusListBinding_KIND_BITSTRING,
			backendv1.StatusListBinding_KIND_TOKEN,
		}
	}
	if s.client.HasWallet() {
		out.Roles = append(out.Roles, commonv1.Role_ROLE_HOLDER)
	}
	if s.client.HasVerifier() || s.client.HasVerifier2() {
		out.Roles = append(out.Roles, commonv1.Role_ROLE_VERIFIER)
		out.Protocols = append(out.Protocols, backendv1.Protocol_PROTOCOL_OID4VP)
	}
	if s.client.HasVerifier2() {
		// The verifier-api2 speaks OID4VP 1.0 with DCQL, also through the
		// Digital Credentials API of a browser.
		out.Protocols = append(out.Protocols, backendv1.Protocol_PROTOCOL_OID4VP_DCQL, backendv1.Protocol_PROTOCOL_DC_API)
		out.Features = append(out.Features, backendv1.Feature_FEATURE_DC_API_VERIFY)
	}
	if s.client.HasVerifier() {
		// The verifier-api reads a Presentation Exchange request only.
		out.Protocols = append(out.Protocols, backendv1.Protocol_PROTOCOL_OID4VP_PEX)
	}
	out.DpgInfo = s.dpgInfo()
	return connect.NewResponse(out), nil
}

// registration is the stored link between a schema configuration id and
// the walt.id configuration that signs it.
type registration struct {
	// ConfigurationID is the id walt.id advertises.
	ConfigurationID string `json:"configuration_id"`
	// Format is the walt.id wire format.
	Format string `json:"format"`
	// Types are the credential type names of a W3C credential.
	Types []string `json:"types,omitempty"`
	// Vct is the SD-JWT VC type.
	Vct string `json:"vct,omitempty"`
	// Doctype is the mdoc doctype.
	Doctype string `json:"doctype,omitempty"`
}

// registrationKey returns the store key of one registration.
func registrationKey(id string) string { return "config/" + storeSafe(id) }

// walletKey returns the store key of one wallet session.
func walletKey(id string) string { return "wallet/" + storeSafe(id) }

// storeSafe makes a value usable as a store key segment.
func storeSafe(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:16])
}

// RegisterCredentialConfiguration records how the adapter issues one
// published schema.
//
// walt.id 0.18.2 reads its catalog from a configuration file at start.
// The adapter must not write that file or restart the container
// (ADR-002 decision 4). The adapter therefore records the credential
// type of the schema and signs it through a walt.id configuration of the
// same format. The signed credential carries the type of the schema.
func (s *Service) RegisterCredentialConfiguration(
	ctx context.Context, req *connect.Request[backendv1.RegisterCredentialConfigurationRequest],
) (*connect.Response[backendv1.RegisterCredentialConfigurationResponse], error) {
	if !s.client.HasIssuer() {
		return nil, unimplemented("this adapter has no issuer URL, so it cannot register a credential configuration")
	}
	cfg := req.Msg.GetConfiguration()
	if cfg == nil || strings.TrimSpace(cfg.GetId()) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the configuration needs an id"))
	}
	format, err := wireFormat(cfg.GetFormat())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	meta, err := s.client.Metadata(ctx)
	if err != nil {
		return nil, failed("read the issuer metadata", err)
	}
	configurationID := cfg.GetId()
	if _, ok := meta.CredentialConfigurationsSupported[configurationID]; !ok {
		borrowed, berr := waltid.BorrowConfigurationID(meta, format)
		if berr != nil {
			return nil, connect.NewError(connect.CodeFailedPrecondition, berr)
		}
		configurationID = borrowed
	}
	reg := registration{ConfigurationID: configurationID, Format: string(format)}
	switch {
	case waltid.IsSdJwt(format):
		reg.Vct = s.vctFor(cfg)
	case format == waltid.FormatMsoMdoc:
		reg.Doctype = cfg.GetType()
	default:
		reg.Types = []string{cfg.GetType()}
	}
	raw, err := json.Marshal(reg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := s.store.Put(ctx, registrationKey(cfg.GetId()), raw); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&backendv1.RegisterCredentialConfigurationResponse{Id: cfg.GetId()}), nil
}

// vctFor returns the SD-JWT VC type of one configuration. Every adapter
// must agree on the same value, or the verifier filter finds nothing.
func (s *Service) vctFor(cfg *backendv1.CredentialConfiguration) string {
	if s.vctBase == "" {
		return cfg.GetType()
	}
	return s.vctBase + "/credentials/" + cfg.GetId()
}

// wireFormat maps a contract format onto the walt.id wire format.
func wireFormat(f commonv1.Format) (waltid.Format, error) {
	switch f {
	case commonv1.Format_FORMAT_JWT_VC_JSON:
		return waltid.FormatJwtVcJSON, nil
	case commonv1.Format_FORMAT_VC_SD_JWT:
		return waltid.FormatVcSdJwt, nil
	case commonv1.Format_FORMAT_DC_SD_JWT:
		return waltid.FormatDcSdJwt, nil
	case commonv1.Format_FORMAT_MSO_MDOC:
		return waltid.FormatMsoMdoc, nil
	case commonv1.Format_FORMAT_LDP_VC:
		return waltid.FormatLdpVc, nil
	default:
		return "", fmt.Errorf("the walt.id adapter cannot issue the format %s", f)
	}
}

// contractFormat maps a walt.id wire format onto the contract format.
func contractFormat(f string) commonv1.Format {
	switch waltid.Format(f) {
	case waltid.FormatJwtVcJSON:
		return commonv1.Format_FORMAT_JWT_VC_JSON
	case waltid.FormatVcSdJwt:
		return commonv1.Format_FORMAT_VC_SD_JWT
	case waltid.FormatDcSdJwt:
		return commonv1.Format_FORMAT_DC_SD_JWT
	case waltid.FormatMsoMdoc:
		return commonv1.Format_FORMAT_MSO_MDOC
	case waltid.FormatLdpVc:
		return commonv1.Format_FORMAT_LDP_VC
	default:
		return commonv1.Format_FORMAT_UNSPECIFIED
	}
}

// timestamp returns a protobuf time or nil for the zero time.
func timestamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}
