// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/credebl"
)

// DIDComm issuance (P6-C3, ADR-059). The platform issues an AnonCreds
// credential of a credential definition and a W3C JSON-LD credential of
// a schema of its schema file server over DIDComm: as an out of band
// invitation, over a connection of the organisation, or as an out of
// band invitation that the platform mails. The configuration id of an
// AnonCreds schema is its credential definition id, and the one of a
// JSON-LD schema is its address (P6-C2).

// DidcommOfferPrefix starts the offer id of a DIDComm offer. The rest is
// the id of the credential exchange in the agent. GetIssuanceStatus reads
// that exchange.
const DidcommOfferPrefix = "didcomm:"

// didcommFormats are the formats the platform issues over DIDComm.
var didcommFormats = []commonv1.Format{commonv1.Format_FORMAT_ANONCREDS, commonv1.Format_FORMAT_LDP_VC}

// oid4vciFormats are the formats the platform issues over OID4VCI.
var oid4vciFormats = []commonv1.Format{commonv1.Format_FORMAT_DC_SD_JWT, commonv1.Format_FORMAT_VC_SD_JWT}

// isDidcommFormat reports whether the platform issues a format over
// DIDComm only.
func isDidcommFormat(f commonv1.Format) bool {
	return f == commonv1.Format_FORMAT_ANONCREDS || f == commonv1.Format_FORMAT_LDP_VC
}

// isDidcommChannel reports whether a channel carries a DIDComm offer.
func isDidcommChannel(c backendv1.Channel) bool {
	return c == backendv1.Channel_CHANNEL_DIDCOMM_OOB || c == backendv1.Channel_CHANNEL_EMAIL
}

// channels returns the delivery channels of the capability answer. The
// platform mails an out of band invitation only with a mail provider.
func (s *Service) channels() []backendv1.Channel {
	out := []backendv1.Channel{backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, backendv1.Channel_CHANNEL_DIDCOMM_OOB}
	if s.mailOffers {
		out = append(out, backendv1.Channel_CHANNEL_EMAIL)
	}
	return out
}

// channelFormats names the formats each channel carries.
func (s *Service) channelFormats() []*backendv1.ChannelFormats {
	out := []*backendv1.ChannelFormats{}
	for _, c := range s.channels() {
		formats := oid4vciFormats
		if isDidcommChannel(c) {
			formats = didcommFormats
		}
		out = append(out, &backendv1.ChannelFormats{Channel: c, Formats: append([]commonv1.Format(nil), formats...)})
	}
	return out
}

// didcommOffer builds the DIDComm offer of one request and sends it on
// its channel.
func (s *Service) didcommOffer(ctx context.Context, msg *backendv1.CreateOfferRequest, channel backendv1.Channel) (*connect.Response[backendv1.CreateOfferResponse], error) {
	spec := msg.GetSpec()
	if !isDidcommFormat(spec.GetFormat()) {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(
			"CREDEBL carries AnonCreds and W3C JSON-LD over DIDComm, not the format %s; use an OID4VCI channel", spec.GetFormat()))
	}
	if channel == backendv1.Channel_CHANNEL_EMAIL && !s.mailOffers {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New(
			"the CREDEBL stack names no mail provider, so it mails no offer; set one in the stack .env"))
	}
	offer, err := s.buildDidcommOffer(ctx, spec)
	if err != nil {
		return nil, err
	}
	out := &backendv1.CreateOfferResponse{Channel: channel}
	switch {
	case channel == backendv1.Channel_CHANNEL_EMAIL:
		if strings.TrimSpace(msg.GetEmail()) == "" {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("an offer by email needs the address"))
		}
		if err := s.client.SendOOBEmail(ctx, msg.GetEmail(), offer); err != nil {
			return nil, failed("mail the offer", err)
		}
	case strings.TrimSpace(msg.GetConnectionId()) != "":
		record, err := s.client.SendConnectionOffer(ctx, msg.GetConnectionId(), offer)
		if err != nil {
			return nil, failed("send the offer over the connection", err)
		}
		out.OfferId = DidcommOfferPrefix + record.ID
	default:
		invitation, err := s.client.CreateOOBOffer(ctx, offer)
		if err != nil {
			return nil, failed("create the out of band offer", err)
		}
		out.OfferUri = invitation.InvitationURL
		out.OfferId = DidcommOfferPrefix + invitation.RecordID
	}
	return connect.NewResponse(out), nil
}

// buildDidcommOffer reads the claims of a spec into the offer of its
// format.
func (s *Service) buildDidcommOffer(ctx context.Context, spec *backendv1.IssueSpec) (credebl.DidcommOffer, error) {
	claims := map[string]any{}
	dec := json.NewDecoder(strings.NewReader(strings.TrimSpace(spec.GetSubjectData())))
	dec.UseNumber()
	if err := dec.Decode(&claims); err != nil || len(claims) == 0 {
		return credebl.DidcommOffer{}, connect.NewError(connect.CodeInvalidArgument,
			errors.New("subject_data must be a JSON object with the claims of the credential"))
	}
	configuration := strings.TrimSpace(spec.GetConfigurationId())
	if spec.GetFormat() == commonv1.Format_FORMAT_ANONCREDS {
		// An AnonCreds credential carries no validity window.
		if hasWindow(spec.GetValidity()) {
			return credebl.DidcommOffer{}, connect.NewError(connect.CodeInvalidArgument,
				errors.New("an AnonCreds credential has no validity window; issue without one"))
		}
		attributes := make(map[string]string, len(claims))
		for name, value := range claims {
			attributes[name] = anonCredsText(value)
		}
		return credebl.DidcommOffer{Type: credebl.CredentialTypeIndy, CredentialDefinitionID: configuration, Attributes: attributes}, nil
	}
	issuer, err := s.primaryDid(ctx)
	if err != nil {
		return credebl.DidcommOffer{}, err
	}
	issued := s.now().UTC()
	if from := spec.GetValidity().GetValidFrom(); from != nil {
		issued = from.AsTime().UTC()
	}
	subject := claims
	if did := strings.TrimSpace(spec.GetSubject().GetDid()); did != "" {
		subject["id"] = did
	}
	contexts, types := []any{credebl.W3CContext, configuration}, []string{"VerifiableCredential"}
	if t, ok := s.jsonldTypeOf(ctx, configuration); ok {
		// The type of the schema lets a Presentation Exchange filter on
		// $.type find the credential. The term comes inline, with the
		// IRI of the context the registry publishes, so the agent
		// fetches no document to sign.
		iri := t.Context
		if iri == "" {
			iri = configuration
		}
		contexts = append(contexts, map[string]string{t.Type: iri + "#" + t.Type})
		types = append(types, t.Type)
	}
	credential := map[string]any{
		"@context":          contexts,
		"type":              types,
		"issuer":            map[string]string{"id": issuer},
		"issuanceDate":      issued.Format(time.RFC3339),
		"credentialSubject": subject,
	}
	if until := spec.GetValidity().GetValidUntil(); until != nil {
		credential["expirationDate"] = until.AsTime().UTC().Format(time.RFC3339)
	}
	return credebl.DidcommOffer{Type: credebl.CredentialTypeJSONLD, Credential: credential, Options: credebl.JSONLDOptions()}, nil
}

// anonCredsText is the text of one AnonCreds claim, which carries text
// only.
func anonCredsText(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case map[string]any, []any:
		raw, err := json.Marshal(v)
		if err == nil {
			return string(raw)
		}
	}
	return fmt.Sprint(value)
}

// primaryDid returns the DID the organisation of the adapter signs with.
func (s *Service) primaryDid(ctx context.Context) (string, error) {
	dids, err := s.client.OrgDids(ctx, s.client.OrgID())
	if err != nil {
		return "", failed("read the DIDs of the organisation", err)
	}
	if len(dids) == 0 || dids[0].Did == "" {
		return "", connect.NewError(connect.CodeFailedPrecondition, errors.New(
			"the organisation has no DID yet; make the issuer identity first"))
	}
	return dids[0].Did, nil
}

// didcommStatus reads the state of a DIDComm offer from its credential
// exchange. The agent ends an exchange in done when the wallet took the
// credential, and in abandoned or declined when it failed.
func (s *Service) didcommStatus(ctx context.Context, id string) (*connect.Response[backendv1.GetIssuanceStatusResponse], error) {
	record, err := s.client.CredentialRecord(ctx, id)
	if err != nil {
		return nil, failed("read the credential exchange", err)
	}
	out := &backendv1.GetIssuanceStatusResponse{State: backendv1.GetIssuanceStatusResponse_STATE_PENDING}
	switch record.State {
	case "done", "credential-issued":
		out.State = backendv1.GetIssuanceStatusResponse_STATE_ISSUED
		out.ClaimedAt = timestamp(record.UpdatedAt)
	case "abandoned", "declined":
		out.State = backendv1.GetIssuanceStatusResponse_STATE_FAILED
		out.Error = record.ErrorMessage
	}
	return connect.NewResponse(out), nil
}

// ListConnections reads one page of the DIDComm connections of the
// organisation of the adapter, newest first.
func (s *Service) ListConnections(
	ctx context.Context, req *connect.Request[backendv1.ListConnectionsRequest],
) (*connect.Response[backendv1.ListConnectionsResponse], error) {
	size := int(req.Msg.GetPage().GetPageSize())
	if size <= 0 || size > 100 {
		size = 20
	}
	page := 1
	if token := req.Msg.GetPage().GetPageToken(); token != "" {
		n, err := parseToken(token)
		if err != nil || n < 1 {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("service: bad page token"))
		}
		page = n
	}
	list, total, err := s.client.Connections(ctx, page, size)
	if err != nil {
		return nil, failed("list the connections", err)
	}
	out := &backendv1.ListConnectionsResponse{Page: &commonv1.PageResult{TotalSize: int64(total)}}
	for _, c := range list {
		out.Connections = append(out.Connections, &backendv1.DidcommConnection{
			Id: c.ID, Label: c.Label, State: c.State, CreatedAt: timestamp(c.CreatedAt),
		})
	}
	if page*size < total {
		out.Page.NextPageToken = fmt.Sprintf("%d", page+1)
	}
	return connect.NewResponse(out), nil
}
