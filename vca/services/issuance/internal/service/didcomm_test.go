// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuancev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/service"
)

// P6-C3 and ADR-059: a stack that issues over DIDComm gets the channel
// CHANNEL_DIDCOMM_OOB, and a stack that mails its own offers gets the
// email channel through the stack. Each channel carries the formats the
// adapter names for it.

// didcommCaps is the capability answer of a stack that issues SD-JWT
// over OID4VCI, and AnonCreds and JSON-LD over DIDComm.
func didcommCaps(mail bool) *backendv1.GetCapabilitiesResponse {
	sdJwt := []commonv1.Format{commonv1.Format_FORMAT_DC_SD_JWT, commonv1.Format_FORMAT_VC_SD_JWT}
	didcomm := []commonv1.Format{commonv1.Format_FORMAT_ANONCREDS, commonv1.Format_FORMAT_LDP_VC}
	caps := &backendv1.GetCapabilitiesResponse{
		Adapter: "dpg-adapter-test", DpgVersion: "1.0",
		Formats:  append(append([]commonv1.Format(nil), sdJwt...), didcomm...),
		Channels: []backendv1.Channel{backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, backendv1.Channel_CHANNEL_DIDCOMM_OOB},
		ChannelFormats: []*backendv1.ChannelFormats{
			{Channel: backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, Formats: sdJwt},
			{Channel: backendv1.Channel_CHANNEL_DIDCOMM_OOB, Formats: didcomm},
		},
		Roles: []commonv1.Role{commonv1.Role_ROLE_ISSUER},
	}
	if mail {
		caps.Channels = append(caps.Channels, backendv1.Channel_CHANNEL_EMAIL)
		caps.ChannelFormats = append(caps.ChannelFormats, &backendv1.ChannelFormats{Channel: backendv1.Channel_CHANNEL_EMAIL, Formats: didcomm})
	}
	return caps
}

// anoncredsSchema is a schema published as SD-JWT and as AnonCreds, with
// the credential definition of the stack as its configuration.
func anoncredsSchema() *schemav1.Schema {
	s := farmerSchema()
	s.Formats = []commonv1.Format{commonv1.Format_FORMAT_VC_SD_JWT, commonv1.Format_FORMAT_ANONCREDS}
	s.ConfigurationIds = map[string]string{"anoncreds": "Ra8F7Qx1:3:CL:Ra8F7Qx1:2:Farmer:1.0:default"}
	return s
}

func didcommHarness(t *testing.T, mail bool) *harness {
	t.Helper()
	h := newHarness(t, func(_ *service.Options, h *harness) {
		h.adapter.capabilities = didcommCaps(mail)
		h.schemas.schema = anoncredsSchema()
	})
	h.adapter.offer = &backendv1.CreateOfferResponse{
		OfferUri: "https://agent.issuer.example.org?oob=eyJAdHlwZSI6Im91dC1vZi1iYW5kIn0",
		OfferId:  "didcomm:rec-1", Channel: backendv1.Channel_CHANNEL_DIDCOMM_OOB,
	}
	return h
}

// TestIssueOverTheDidcommChannel: the channel picks the format of the
// schema it carries, and the spec names the credential definition.
func TestIssueOverTheDidcommChannel(t *testing.T) {
	h := didcommHarness(t, false)
	offer := h.issue(t, backendv1.Channel_CHANNEL_DIDCOMM_OOB, nil)
	if offer.GetOfferUri() != h.adapter.offer.GetOfferUri() || offer.GetState() != issuancev1.Offer_STATE_PENDING {
		t.Fatalf("offer = %v", offer)
	}
	req := h.adapter.requests[0]
	if req.GetChannel() != backendv1.Channel_CHANNEL_DIDCOMM_OOB || req.GetConnectionId() != "" {
		t.Errorf("request = %v", req)
	}
	spec := req.GetSpec()
	if spec.GetFormat() != commonv1.Format_FORMAT_ANONCREDS || spec.GetConfigurationId() != "Ra8F7Qx1:3:CL:Ra8F7Qx1:2:Farmer:1.0:default" {
		t.Errorf("spec = %v", spec)
	}
	// The pre-authorized channel of the same schema carries SD-JWT.
	h.issue(t, backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, nil)
	if f := h.adapter.requests[1].GetSpec().GetFormat(); f != commonv1.Format_FORMAT_VC_SD_JWT {
		t.Errorf("the OID4VCI offer has the format %v", f)
	}
}

// TestIssueOverADidcommConnection: an offer to a connection names it.
func TestIssueOverADidcommConnection(t *testing.T) {
	h := didcommHarness(t, false)
	h.issue(t, backendv1.Channel_CHANNEL_DIDCOMM_OOB, func(r *issuancev1.IssueRequest) {
		r.Delivery.ConnectionId = "conn-1"
	})
	if got := h.adapter.requests[0].GetConnectionId(); got != "conn-1" {
		t.Errorf("connection = %q", got)
	}
}

// TestIssueByEmailThroughTheStack: a stack that mails its own offers
// gets the address, and VCA sends no message.
func TestIssueByEmailThroughTheStack(t *testing.T) {
	h := didcommHarness(t, true)
	offer := h.issue(t, backendv1.Channel_CHANNEL_EMAIL, func(r *issuancev1.IssueRequest) {
		r.Delivery.Email = "holder@registry.gov.test"
	})
	req := h.adapter.requests[0]
	if req.GetChannel() != backendv1.Channel_CHANNEL_EMAIL || req.GetEmail() != "holder@registry.gov.test" ||
		req.GetSpec().GetFormat() != commonv1.Format_FORMAT_ANONCREDS {
		t.Errorf("request = %v", req)
	}
	if len(*h.sent) != 0 || offer.GetState() != issuancev1.Offer_STATE_DELIVERED {
		t.Errorf("sent %d messages, state %v", len(*h.sent), offer.GetState())
	}
	_, err := h.service.Issue(context.Background(), connect.NewRequest(&issuancev1.IssueRequest{
		SchemaId: "farmer", SubjectData: `{"fullName":"Ada Lovelace","farmerID":"FM-0001"}`,
		Delivery: &issuancev1.Delivery{Channel: backendv1.Channel_CHANNEL_EMAIL},
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

// TestIssueRefusesAFormatTheChannelDoesNotCarry: SD-JWT goes over no
// DIDComm channel, and AnonCreds over no OID4VCI channel.
func TestIssueRefusesAFormatTheChannelDoesNotCarry(t *testing.T) {
	h := didcommHarness(t, false)
	for channel, format := range map[backendv1.Channel]commonv1.Format{
		backendv1.Channel_CHANNEL_DIDCOMM_OOB:     commonv1.Format_FORMAT_VC_SD_JWT,
		backendv1.Channel_CHANNEL_OID4VCI_PREAUTH: commonv1.Format_FORMAT_ANONCREDS,
	} {
		_, err := h.service.Issue(context.Background(), connect.NewRequest(&issuancev1.IssueRequest{
			SchemaId: "farmer", SubjectData: `{"fullName":"Ada Lovelace","farmerID":"FM-0001"}`,
			Format: format, Delivery: &issuancev1.Delivery{Channel: channel},
		}))
		wantCode(t, err, connect.CodeInvalidArgument)
	}
	// A schema without a DIDComm format has no DIDComm offer.
	h.schemas.schema = farmerSchema()
	_, err := h.service.Issue(context.Background(), connect.NewRequest(&issuancev1.IssueRequest{
		SchemaId: "farmer", SubjectData: `{"fullName":"Ada Lovelace","farmerID":"FM-0001"}`,
		Delivery: &issuancev1.Delivery{Channel: backendv1.Channel_CHANNEL_DIDCOMM_OOB},
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
	if len(h.adapter.requests) != 0 {
		t.Errorf("the adapter got %d offers", len(h.adapter.requests))
	}
}

// TestIssueRefusesDidcommOnAStackWithoutIt: a stack that lists no DIDComm
// channel gets no DIDComm offer.
func TestIssueRefusesDidcommOnAStackWithoutIt(t *testing.T) {
	h := newHarness(t, nil)
	_, err := h.service.Issue(context.Background(), connect.NewRequest(&issuancev1.IssueRequest{
		SchemaId: "farmer", SubjectData: `{"fullName":"Ada Lovelace","farmerID":"FM-0001"}`,
		Delivery: &issuancev1.Delivery{Channel: backendv1.Channel_CHANNEL_DIDCOMM_OOB},
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
}
