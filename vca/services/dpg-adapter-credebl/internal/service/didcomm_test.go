// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/service"
)

// P6-C3: the platform issues AnonCreds and W3C JSON-LD credentials over
// DIDComm: an out of band invitation, an offer over a connection, and
// an out of band invitation by email.

const (
	credDef   = "Ra8F7Qx1:3:CL:Ra8F7Qx1:2:Farmer:1.0:default" //nolint:gosec // G101: a credential definition id, not a credential.
	w3cSchema = "http://credebl-schema-file-server:4000/schemas/s-1"
)

func didcommOffer(format commonv1.Format, configuration string, channel backendv1.Channel) *backendv1.CreateOfferRequest {
	return &backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{
			ConfigurationId: configuration, Format: format,
			SubjectData: `{"fullName":"[holder]","acres":12}`,
		},
		Channel: channel,
	}
}

// TestOobOfferGivesInvitation is P6-C3: an AnonCreds offer on the
// channel CHANNEL_DIDCOMM_OOB gives the invitation of the agent, and the
// offer id names the credential exchange.
func TestOobOfferGivesInvitation(t *testing.T) {
	svc, f := newService(t, nil)
	resp, err := svc.CreateOffer(context.Background(), connect.NewRequest(
		didcommOffer(commonv1.Format_FORMAT_ANONCREDS, credDef, backendv1.Channel_CHANNEL_DIDCOMM_OOB)))
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	m := resp.Msg
	if !strings.Contains(m.GetOfferUri(), "?oob=") || m.GetChannel() != backendv1.Channel_CHANNEL_DIDCOMM_OOB ||
		m.GetOfferId() != service.DidcommOfferPrefix+"0a1b2c3d-4e5f-4a6b-9c7d-8e9f0a1b2c3d" || m.GetPin() != "" {
		t.Fatalf("offer = %+v", m)
	}
	if q := f.Query("/v1/orgs/org-1/credentials/oob/offer"); q != "credentialType=indy" {
		t.Errorf("query = %q", q)
	}
	var body struct {
		CredDef    string `json:"credentialDefinitionId"`
		Attributes []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"attributes"`
	}
	if err := f.RequestJSON("/v1/orgs/org-1/credentials/oob/offer", &body); err != nil {
		t.Fatal(err)
	}
	// An AnonCreds claim is text, so the number 12 travels as "12".
	if body.CredDef != credDef || len(body.Attributes) != 2 || body.Attributes[0].Name != "acres" || body.Attributes[0].Value != "12" {
		t.Errorf("body = %+v", body)
	}
}

// TestJsonLdOfferSignsWithThePrimaryDid: a W3C JSON-LD offer carries the
// context of the schema and names the primary DID of the organisation
// as the issuer.
func TestJsonLdOfferSignsWithThePrimaryDid(t *testing.T) {
	svc, f := newService(t, nil)
	if _, err := svc.CreateOffer(context.Background(), connect.NewRequest(
		didcommOffer(commonv1.Format_FORMAT_LDP_VC, w3cSchema, backendv1.Channel_CHANNEL_DIDCOMM_OOB))); err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	if q := f.Query("/v1/orgs/org-1/credentials/oob/offer"); q != "credentialType=jsonld" {
		t.Errorf("query = %q", q)
	}
	var body struct {
		Credential struct {
			Context []string       `json:"@context"`
			Type    []string       `json:"type"`
			Issuer  map[string]any `json:"issuer"`
			Issued  string         `json:"issuanceDate"`
			Subject map[string]any `json:"credentialSubject"`
		} `json:"credential"`
		Options map[string]string `json:"options"`
	}
	if err := f.RequestJSON("/v1/orgs/org-1/credentials/oob/offer", &body); err != nil {
		t.Fatal(err)
	}
	c := body.Credential
	if len(c.Context) != 2 || c.Context[1] != w3cSchema || !slices.Contains(c.Type, "VerifiableCredential") {
		t.Errorf("credential = %+v", c)
	}
	if did, ok := c.Issuer["id"].(string); !ok || !strings.HasPrefix(did, "did:") {
		t.Errorf("issuer = %v, want the primary DID", c.Issuer)
	}
	if c.Issued != "2026-04-01T12:00:00Z" || c.Subject["fullName"] != "[holder]" {
		t.Errorf("credential = %+v", c)
	}
	if body.Options["proofType"] == "" {
		t.Errorf("options = %v", body.Options)
	}
}

// TestConnectionOfferNamesTheRecord: an offer to a connection goes over
// that connection, with no invitation.
func TestConnectionOfferNamesTheRecord(t *testing.T) {
	svc, f := newService(t, nil)
	req := didcommOffer(commonv1.Format_FORMAT_ANONCREDS, credDef, backendv1.Channel_CHANNEL_DIDCOMM_OOB)
	req.ConnectionId = "6e7f8a9b-0c1d-4e2f-9a3b-4c5d6e7f8a9b"
	resp, err := svc.CreateOffer(context.Background(), connect.NewRequest(req))
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	if resp.Msg.GetOfferUri() != "" || resp.Msg.GetOfferId() != service.DidcommOfferPrefix+"3c4d5e6f-7a8b-4c9d-8e0f-1a2b3c4d5e6f" {
		t.Errorf("offer = %+v", resp.Msg)
	}
	if f.Request("/v1/orgs/org-1/credentials/offer") == nil {
		t.Error("the offer did not go over the connection")
	}
}

// TestOobEmailSendsThroughPlatform is P6-C3: with mail offers on, the
// platform mails the invitation to the address.
func TestOobEmailSendsThroughPlatform(t *testing.T) {
	svc, f := newService(t, func(o *service.Options) { o.MailOffers = true })
	req := didcommOffer(commonv1.Format_FORMAT_ANONCREDS, credDef, backendv1.Channel_CHANNEL_EMAIL)
	req.Email = "holder@registry.gov.test"
	resp, err := svc.CreateOffer(context.Background(), connect.NewRequest(req))
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	if resp.Msg.GetChannel() != backendv1.Channel_CHANNEL_EMAIL || resp.Msg.GetOfferUri() != "" {
		t.Errorf("offer = %+v", resp.Msg)
	}
	var body struct {
		Offers []struct {
			Email string `json:"emailId"`
		} `json:"credentialOffer"`
	}
	if err := f.RequestJSON("/v1/orgs/org-1/credentials/oob/email", &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Offers) != 1 || body.Offers[0].Email != "holder@registry.gov.test" {
		t.Errorf("body = %+v", body)
	}
	// No address, no mail.
	req.Email = ""
	if _, err := svc.CreateOffer(context.Background(), connect.NewRequest(req)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("an offer without an address: %v", err)
	}
	// A stack without a mail provider has no email channel.
	off, _ := newService(t, nil)
	req.Email = "holder@registry.gov.test"
	if _, err := off.CreateOffer(context.Background(), connect.NewRequest(req)); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("an email offer without a mail provider: %v", err)
	}
}

// TestDidcommOfferRefusesWhatItCannotCarry: DIDComm carries AnonCreds
// and JSON-LD, OID4VCI carries SD-JWT, and an AnonCreds credential has
// no validity window.
func TestDidcommOfferRefusesWhatItCannotCarry(t *testing.T) {
	svc, _ := newService(t, nil)
	ctx := context.Background()
	for name, req := range map[string]*backendv1.CreateOfferRequest{
		"sd-jwt over didcomm":    didcommOffer(commonv1.Format_FORMAT_DC_SD_JWT, credDef, backendv1.Channel_CHANNEL_DIDCOMM_OOB),
		"anoncreds over oid4vci": didcommOffer(commonv1.Format_FORMAT_ANONCREDS, credDef, backendv1.Channel_CHANNEL_OID4VCI_PREAUTH),
		"no claims": {Spec: &backendv1.IssueSpec{ConfigurationId: credDef, Format: commonv1.Format_FORMAT_ANONCREDS},
			Channel: backendv1.Channel_CHANNEL_DIDCOMM_OOB},
		"bad claims": {Spec: &backendv1.IssueSpec{ConfigurationId: credDef, Format: commonv1.Format_FORMAT_ANONCREDS, SubjectData: "[1]"},
			Channel: backendv1.Channel_CHANNEL_DIDCOMM_OOB},
		"a window": {Spec: &backendv1.IssueSpec{ConfigurationId: credDef, Format: commonv1.Format_FORMAT_ANONCREDS,
			SubjectData: `{"a":"b"}`, Validity: &commonv1.ValidityWindow{ValidUntil: timestamppb.Now()}},
			Channel: backendv1.Channel_CHANNEL_DIDCOMM_OOB},
	} {
		if _, err := svc.CreateOffer(ctx, connect.NewRequest(req)); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestDidcommStatusReadsTheExchange: the state of a DIDComm offer is the
// state of its credential exchange in the agent.
func TestDidcommStatusReadsTheExchange(t *testing.T) {
	svc, f := newService(t, nil)
	for answer, want := range map[fake.Answer]backendv1.GetIssuanceStatusResponse_State{
		fake.RecordOfferSent: backendv1.GetIssuanceStatusResponse_STATE_PENDING,
		fake.RecordDone:      backendv1.GetIssuanceStatusResponse_STATE_ISSUED,
		fake.RecordAbandoned: backendv1.GetIssuanceStatusResponse_STATE_FAILED,
	} {
		f.SetCredentialRecord(answer)
		resp, err := svc.GetIssuanceStatus(context.Background(), connect.NewRequest(&backendv1.GetIssuanceStatusRequest{
			OfferId: service.DidcommOfferPrefix + "0a1b2c3d-4e5f-4a6b-9c7d-8e9f0a1b2c3d",
		}))
		if err != nil || resp.Msg.GetState() != want {
			t.Errorf("%s: %v, %v", answer, resp, err)
			continue
		}
		if want == backendv1.GetIssuanceStatusResponse_STATE_ISSUED && resp.Msg.GetClaimedAt() == nil {
			t.Errorf("%s has no claim time", answer)
		}
		if want == backendv1.GetIssuanceStatusResponse_STATE_FAILED && !strings.Contains(resp.Msg.GetError(), "declined") {
			t.Errorf("%s error = %q", answer, resp.Msg.GetError())
		}
	}
}

// TestListConnectionsPages: the connections of the organisation, a page
// at a time, and an empty list when the platform knows none.
func TestListConnectionsPages(t *testing.T) {
	svc, f := newService(t, nil)
	resp, err := svc.ListConnections(context.Background(), connect.NewRequest(&backendv1.ListConnectionsRequest{
		Page: &commonv1.Pagination{PageSize: 10},
	}))
	if err != nil {
		t.Fatalf("ListConnections: %v", err)
	}
	got := resp.Msg.GetConnections()
	if len(got) != 2 || got[0].GetLabel() != "[wallet one]" || got[0].GetCreatedAt() == nil || resp.Msg.GetPage().GetTotalSize() != 2 {
		t.Fatalf("connections = %v", resp.Msg)
	}
	f.SetConnections(fake.NoConnections)
	none, err := svc.ListConnections(context.Background(), connect.NewRequest(&backendv1.ListConnectionsRequest{}))
	if err != nil || len(none.Msg.GetConnections()) != 0 {
		t.Errorf("no connections = %v, %v", none, err)
	}
}

// TestChannelsListed is P6-C3: the answer lists the DIDComm channel, the
// formats it carries, and the email channel only with a mail provider.
func TestChannelsListed(t *testing.T) {
	for _, mail := range []bool{false, true} {
		svc, _ := newService(t, func(o *service.Options) { o.MailOffers = mail })
		resp, err := svc.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		m := resp.Msg
		if !slices.Contains(m.GetChannels(), backendv1.Channel_CHANNEL_DIDCOMM_OOB) ||
			!slices.Contains(m.GetProtocols(), backendv1.Protocol_PROTOCOL_DIDCOMM_ISSUE_V2) {
			t.Errorf("channels %v protocols %v", m.GetChannels(), m.GetProtocols())
		}
		if slices.Contains(m.GetChannels(), backendv1.Channel_CHANNEL_EMAIL) != mail {
			t.Errorf("mail %v: channels %v", mail, m.GetChannels())
		}
		for _, f := range []commonv1.Format{commonv1.Format_FORMAT_ANONCREDS, commonv1.Format_FORMAT_LDP_VC, commonv1.Format_FORMAT_DC_SD_JWT} {
			if !slices.Contains(m.GetFormats(), f) {
				t.Errorf("formats %v lack %s", m.GetFormats(), f)
			}
		}
		carried := map[backendv1.Channel][]commonv1.Format{}
		for _, cf := range m.GetChannelFormats() {
			carried[cf.GetChannel()] = cf.GetFormats()
		}
		if got := carried[backendv1.Channel_CHANNEL_DIDCOMM_OOB]; !slices.Equal(got, []commonv1.Format{commonv1.Format_FORMAT_ANONCREDS, commonv1.Format_FORMAT_LDP_VC}) {
			t.Errorf("DIDComm carries %v", got)
		}
		if got := carried[backendv1.Channel_CHANNEL_OID4VCI_PREAUTH]; !slices.Equal(got, []commonv1.Format{commonv1.Format_FORMAT_DC_SD_JWT, commonv1.Format_FORMAT_VC_SD_JWT}) {
			t.Errorf("OID4VCI carries %v", got)
		}
	}
}

// TestJsonLdOfferCarriesTheTypeOfTheSchema: a W3C JSON-LD credential
// names the type of its schema, so the $.type filter of a Presentation
// Exchange request finds it. The context the registry publishes for the
// type defines the term, and the credential carries it inline, so the
// agent fetches no document to sign.
func TestJsonLdOfferCarriesTheTypeOfTheSchema(t *testing.T) {
	svc, f := newService(t, nil)
	const published = "https://registry.example/contexts/registration/1"
	res, err := svc.RegisterCredentialConfiguration(context.Background(), connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{
		Configuration: &backendv1.CredentialConfiguration{
			Id: "RegistrationCertificate_ldp_vc", Format: commonv1.Format_FORMAT_LDP_VC, Type: "RegistrationCertificate",
			JsonSchema: registrationSchema, TypeContext: published,
		},
	}))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := svc.CreateOffer(context.Background(), connect.NewRequest(
		didcommOffer(commonv1.Format_FORMAT_LDP_VC, res.Msg.GetId(), backendv1.Channel_CHANNEL_DIDCOMM_OOB))); err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	var body struct {
		Credential struct {
			Context []any    `json:"@context"`
			Type    []string `json:"type"`
		} `json:"credential"`
	}
	if err := f.RequestJSON("/v1/orgs/org-1/credentials/oob/offer", &body); err != nil {
		t.Fatal(err)
	}
	c := body.Credential
	if !slices.Equal(c.Type, []string{"VerifiableCredential", "RegistrationCertificate"}) {
		t.Fatalf("type = %v, want the type of the schema", c.Type)
	}
	terms, ok := c.Context[len(c.Context)-1].(map[string]any)
	if !ok || terms["RegistrationCertificate"] != published+"#RegistrationCertificate" {
		t.Fatalf("context = %v, want the term of the type", c.Context)
	}
}
