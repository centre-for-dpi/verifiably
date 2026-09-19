// SPDX-License-Identifier: Apache-2.0

// Package service serves the vca.backend.v1 services against a CREDEBL
// platform (ADR-002 decision 2). CREDEBL ships no wallet for a citizen,
// so the holder service answers with the Connect code Unimplemented.
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
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/credebl"
	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// AdapterName is the name the capability answer carries.
const AdapterName = "dpg-adapter-credebl"

// verifierKey is the store key of the verifier identifier.
const verifierKey = "verifier/id"

// Options configure New.
type Options struct {
	// Client calls the CREDEBL platform.
	Client *credebl.Client
	// Store keeps the verifier identifier.
	Store store.KeyValue
	// DpgVersion names the CREDEBL release.
	DpgVersion string
	// VerifierID pins the OID4VP verifier. Empty makes the adapter
	// create one at first use.
	VerifierID string
	// VerifierName is the name of the verifier the adapter creates.
	VerifierName string
	// PublicURL is the host a wallet reaches the CREDEBL agent on.
	PublicURL string
	// InternalURL is the host the CREDEBL agent puts in an offer URI.
	InternalURL string
	// DefaultPin is the transaction code of a pre-authorized offer.
	DefaultPin string
	// PageSizeMax caps a list page.
	PageSizeMax int
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

// Service implements every vca.backend.v1 service of this adapter.
type Service struct {
	client       *credebl.Client
	store        store.KeyValue
	dpgVersion   string
	verifierID   string
	verifierName string
	publicURL    string
	internalURL  string
	defaultPin   string
	pageSizeMax  int
	now          func() time.Time
}

// New returns the service.
func New(opts Options) (*Service, error) {
	if opts.Client == nil {
		return nil, errors.New("service: no CREDEBL client")
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
	if opts.VerifierName == "" {
		opts.VerifierName = "verifiable-credentials-adapters"
	}
	return &Service{
		client:       opts.Client,
		store:        opts.Store,
		dpgVersion:   opts.DpgVersion,
		verifierID:   opts.VerifierID,
		verifierName: opts.VerifierName,
		publicURL:    strings.TrimRight(opts.PublicURL, "/"),
		internalURL:  strings.TrimRight(opts.InternalURL, "/"),
		defaultPin:   opts.DefaultPin,
		pageSizeMax:  opts.PageSizeMax,
		now:          opts.Now,
	}, nil
}

// Ready reports whether the service can take traffic.
func (s *Service) Ready() bool { return s != nil && s.client != nil }

// unimplemented returns a Connect error that names the missing ability.
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
	case dpgclient.IsStatus(err, 409):
		code = connect.CodeAlreadyExists
	}
	return connect.NewError(code, fmt.Errorf("%s: %w", action, err))
}

// GetCapabilities reports what the CREDEBL platform supports
// (ADR-016 decision 6).
func (s *Service) GetCapabilities(
	_ context.Context, _ *connect.Request[backendv1.GetCapabilitiesRequest],
) (*connect.Response[backendv1.GetCapabilitiesResponse], error) {
	return connect.NewResponse(&backendv1.GetCapabilitiesResponse{
		Adapter:    AdapterName,
		DpgVersion: s.dpgVersion,
		Formats: []commonv1.Format{
			commonv1.Format_FORMAT_DC_SD_JWT,
			commonv1.Format_FORMAT_VC_SD_JWT,
		},
		// CREDEBL builds a pre-authorized code offer only.
		Channels: []backendv1.Channel{backendv1.Channel_CHANNEL_OID4VCI_PREAUTH},
		Roles:    []commonv1.Role{commonv1.Role_ROLE_ISSUER, commonv1.Role_ROLE_VERIFIER},
		Protocols: []backendv1.Protocol{
			backendv1.Protocol_PROTOCOL_OID4VCI,
			backendv1.Protocol_PROTOCOL_OID4VP,
			backendv1.Protocol_PROTOCOL_OID4VP_DCQL,
		},
	}), nil
}

// holderMessage says what to use instead of the holder role.
const holderMessage = "CREDEBL ships no wallet for a citizen; " +
	"use the wallet portal or an external OID4VCI wallet"

// Register is not available. CREDEBL ships no wallet for a citizen.
func (s *Service) Register(
	context.Context, *connect.Request[backendv1.RegisterRequest],
) (*connect.Response[backendv1.RegisterResponse], error) {
	return nil, unimplemented(holderMessage)
}

// ListCredentials is not available. CREDEBL ships no wallet.
func (s *Service) ListCredentials(
	context.Context, *connect.Request[backendv1.ListCredentialsRequest],
) (*connect.Response[backendv1.ListCredentialsResponse], error) {
	return nil, unimplemented(holderMessage)
}

// AcceptOffer is not available. CREDEBL ships no wallet.
func (s *Service) AcceptOffer(
	context.Context, *connect.Request[backendv1.AcceptOfferRequest],
) (*connect.Response[backendv1.AcceptOfferResponse], error) {
	return nil, unimplemented(holderMessage)
}

// Present is not available. CREDEBL ships no wallet.
func (s *Service) Present(
	context.Context, *connect.Request[backendv1.PresentRequest],
) (*connect.Response[backendv1.PresentResponse], error) {
	return nil, unimplemented(holderMessage)
}

// DeleteCredential is not available. CREDEBL ships no wallet.
func (s *Service) DeleteCredential(
	context.Context, *connect.Request[backendv1.DeleteCredentialRequest],
) (*connect.Response[backendv1.DeleteCredentialResponse], error) {
	return nil, unimplemented(holderMessage)
}

// timestamp returns a protobuf time or nil for the zero time.
func timestamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// configurations maps the CREDEBL templates onto the contract message in
// a stable order.
func configurations(templates []credebl.Template) []*backendv1.CredentialConfiguration {
	out := make([]*backendv1.CredentialConfiguration, 0, len(templates))
	for _, t := range templates {
		cfg := &backendv1.CredentialConfiguration{
			Id:     t.ID,
			Format: contractFormat(t.Format),
			Type:   t.Body.Vct,
		}
		if cfg.Type == "" {
			cfg.Type = t.Name
		}
		for _, a := range t.Body.Attributes {
			if a.Disclose {
				cfg.SdClaims = append(cfg.SdClaims, a.Key)
			}
		}
		out = append(out, cfg)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetId() < out[j].GetId() })
	return out
}

// contractFormat maps a CREDEBL wire format onto the contract format.
func contractFormat(format string) commonv1.Format {
	switch format {
	case "dc+sd-jwt":
		return commonv1.Format_FORMAT_DC_SD_JWT
	case "vc+sd-jwt":
		return commonv1.Format_FORMAT_VC_SD_JWT
	case "jwt_vc_json":
		return commonv1.Format_FORMAT_JWT_VC_JSON
	case "ldp_vc":
		return commonv1.Format_FORMAT_LDP_VC
	default:
		return commonv1.Format_FORMAT_UNSPECIFIED
	}
}

// wireFormat maps a contract format onto the CREDEBL wire format.
func wireFormat(f commonv1.Format) (string, error) {
	switch f {
	case commonv1.Format_FORMAT_DC_SD_JWT, commonv1.Format_FORMAT_UNSPECIFIED:
		return "dc+sd-jwt", nil
	case commonv1.Format_FORMAT_VC_SD_JWT:
		return "vc+sd-jwt", nil
	default:
		return "", fmt.Errorf("CREDEBL issues SD-JWT VC only, not the format %s", f)
	}
}

// parseToken reads a page token.
func parseToken(token string) (int, error) {
	var n int
	if _, err := fmt.Sscanf(token, "%d", &n); err != nil || n < 0 {
		return 0, errors.New("service: bad page token")
	}
	return n, nil
}
