// SPDX-License-Identifier: Apache-2.0

// Package service serves the vca.backend.v1 services against a CREDEBL
// platform (ADR-002 decision 2). The holder service keeps a tenant
// wallet per holder in the shared agent of the stack (ADR-062). Without
// the address and the API key of the agent it answers with the Connect
// code Unimplemented.
package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
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
	// Versions maps each stack component onto its pinned version for
	// the capability answer. The configuration supplies it.
	Versions map[string]string
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
	// MailOffers reports that the stack names a mail provider, so the
	// platform mails an out of band offer (CHANNEL_EMAIL).
	MailOffers bool
	// Agent calls the shared agent of the stack for the holder role
	// (ADR-062). Nil turns the holder role off.
	Agent *credebl.Agent
	// HolderLabel is the label a holder wallet shows the other party of
	// a connection. Empty means DefaultHolderLabel.
	HolderLabel string
	// PollInterval is the wait between two reads of an exchange. Zero
	// means DefaultPollInterval.
	PollInterval time.Duration
	// PollAttempts is the number of reads of an exchange. Zero means
	// DefaultPollAttempts.
	PollAttempts int
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
	versions     map[string]string
	now          func() time.Time
	mailOffers   bool
	agent        *credebl.Agent
	holderLabel  string
	pollInterval time.Duration
	pollAttempts int

	// ledgerMu guards ledgers, the ledgers of the capability answer.
	ledgerMu sync.Mutex
	ledgers  ledgerCache
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
	if opts.HolderLabel == "" {
		opts.HolderLabel = DefaultHolderLabel
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = DefaultPollInterval
	}
	if opts.PollAttempts <= 0 {
		opts.PollAttempts = DefaultPollAttempts
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
		versions:     opts.Versions,
		now:          opts.Now,
		mailOffers:   opts.MailOffers,
		agent:        opts.Agent,
		holderLabel:  opts.HolderLabel,
		pollInterval: opts.PollInterval,
		pollAttempts: opts.PollAttempts,
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
	ctx context.Context, _ *connect.Request[backendv1.GetCapabilitiesRequest],
) (*connect.Response[backendv1.GetCapabilitiesResponse], error) {
	ledgers, schemaFormats := s.schemaTargets(ctx)
	return connect.NewResponse(&backendv1.GetCapabilitiesResponse{
		// An AnonCreds schema on a ledger and a W3C JSON-LD schema
		// (P6-C2). The platform issues them over DIDComm only.
		Ledgers:       ledgers,
		SchemaFormats: schemaFormats,
		Adapter:       AdapterName,
		DpgVersion:    s.dpgVersion,
		// SD-JWT over OID4VCI, and AnonCreds and W3C JSON-LD over
		// DIDComm (P6-C3). channel_formats names the formats of each
		// channel.
		Formats: []commonv1.Format{
			commonv1.Format_FORMAT_DC_SD_JWT,
			commonv1.Format_FORMAT_VC_SD_JWT,
			commonv1.Format_FORMAT_ANONCREDS,
			commonv1.Format_FORMAT_LDP_VC,
		},
		Channels:       s.channels(),
		ChannelFormats: s.channelFormats(),
		Roles:          s.roles(),
		Protocols: []backendv1.Protocol{
			backendv1.Protocol_PROTOCOL_OID4VCI,
			backendv1.Protocol_PROTOCOL_OID4VP,
			backendv1.Protocol_PROTOCOL_OID4VP_DCQL,
			backendv1.Protocol_PROTOCOL_DIDCOMM_ISSUE_V2,
			// DIDComm proof requests, AnonCreds and DIF PE (P6-C6).
			backendv1.Protocol_PROTOCOL_DIDCOMM_PRESENT_V2,
		},
		// RegisterCredentialConfiguration writes a schema and a template
		// to the platform. The organisations of the platform are the
		// tenants, and the agent makes the issuer DID (P6-C1). Revoke
		// answers Unimplemented, so its features stay off the list. The
		// platform embeds no status entry of VCA in what it signs. The
		// bulk import mails each row, so it needs a mail provider
		// (P6-C4).
		Features:   s.features(),
		BulkImport: s.bulkImport(),
		// The stack file runs one shared agent and no Docker socket, so
		// a tenant gets a wallet in the shared agent only.
		TenantAgentTypes: []backendv1.DpgTenant_AgentType{backendv1.DpgTenant_AGENT_TYPE_SHARED},
		DidMethods:       append([]string(nil), DidMethods...),
		KeyTypes:         append([]string(nil), KeyTypes...),
		WalletDidMethods: s.walletDidMethods(),
		DpgInfo:          s.dpgInfo(),
	}), nil
}

// roles lists the issuer and the verifier role, and the holder role
// with the agent (ADR-062 decision 7).
func (s *Service) roles() []commonv1.Role {
	out := []commonv1.Role{commonv1.Role_ROLE_ISSUER, commonv1.Role_ROLE_VERIFIER}
	if s.holderRole() {
		out = append(out, commonv1.Role_ROLE_HOLDER)
	}
	return out
}

// walletDidMethods lists the DID methods of a holder wallet, or none
// without the holder role.
func (s *Service) walletDidMethods() []string {
	if !s.holderRole() {
		return nil
	}
	return append([]string(nil), WalletDidMethods...)
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
