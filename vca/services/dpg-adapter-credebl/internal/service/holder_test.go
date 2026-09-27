// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/credebl"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// P6-C7: the holder wallet in the shared agent of the stack (ADR-062).

// holderSubject is a hashed pairwise subject, as the wallet
// authentication service sends it.
const holderSubject = "b1946ac92492d2347c6235b4d2611184"

// newHolder returns the service with the fake agent, the fake agent,
// and the store.
func newHolder(t *testing.T, change func(*service.Options)) (*service.Service, *fake.Agent, store.KeyValue) {
	t.Helper()
	agent := fake.NewAgent(testdata)
	t.Cleanup(agent.Close)
	kv := store.Memory()
	svc, _ := newService(t, func(o *service.Options) {
		o.Agent = credebl.NewAgent(credebl.AgentOptions{
			HTTP:   dpgclient.New(dpgclient.Options{BaseURL: agent.URL(), HTTP: agent.Client(), Retries: -1, Sleep: func(time.Duration) {}}),
			APIKey: fake.AgentAPIKey,
		})
		o.Store = kv
		o.HolderLabel = "[holder wallet]"
		o.PollInterval = time.Millisecond
		o.PollAttempts = 3
		if change != nil {
			change(o)
		}
	})
	return svc, agent, kv
}

// registerHolder opens the wallet of the test holder.
func registerHolder(t *testing.T, svc *service.Service) string {
	t.Helper()
	res, err := svc.Register(context.Background(), connect.NewRequest(&backendv1.RegisterRequest{PairwiseSubject: holderSubject}))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	return res.Msg.GetWalletId()
}

// count returns the number of calls to the method and path.
func count(calls []string, key string) int {
	n := 0
	for _, c := range calls {
		if c == key {
			n++
		}
	}
	return n
}

// TestCreateCloudWallet is ADR-062 decision 2: Register makes a tenant
// wallet with a did:key for a new holder, and opens the same wallet at
// the next login. The store keeps no subject in clear. Another holder
// gets another wallet.
func TestCreateCloudWallet(t *testing.T) {
	svc, agent, kv := newHolder(t, nil)
	ctx := context.Background()
	first, err := svc.Register(ctx, connect.NewRequest(&backendv1.RegisterRequest{PairwiseSubject: holderSubject}))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if first.Msg.GetWalletId() != fake.FirstTenant || first.Msg.GetHolderDid() != fake.HolderDid {
		t.Fatalf("Register = %+v", first.Msg)
	}
	var created struct {
		Config struct {
			Label string `json:"label"`
		} `json:"config"`
	}
	if uerr := json.Unmarshal(agent.Body("POST /multi-tenancy/create-tenant"), &created); uerr != nil || created.Config.Label != "[holder wallet]" {
		t.Errorf("the tenant label: %+v, %v", created, uerr)
	}
	again, err := svc.Register(ctx, connect.NewRequest(&backendv1.RegisterRequest{PairwiseSubject: holderSubject}))
	if err != nil || again.Msg.GetWalletId() != fake.FirstTenant || again.Msg.GetHolderDid() != fake.HolderDid {
		t.Fatalf("the second login = %+v, %v", again, err)
	}
	if n := count(agent.Calls(), "POST /multi-tenancy/create-tenant"); n != 1 {
		t.Errorf("the agent made %d tenants for one holder", n)
	}
	keys, err := kv.List(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if strings.Contains(k, holderSubject) {
			t.Errorf("the store key %q holds the subject", k)
		}
	}
	other, err := svc.Register(ctx, connect.NewRequest(&backendv1.RegisterRequest{PairwiseSubject: "another"}))
	if err != nil || other.Msg.GetWalletId() == fake.FirstTenant {
		t.Errorf("another holder = %+v, %v", other, err)
	}
	_, err = svc.Register(ctx, connect.NewRequest(&backendv1.RegisterRequest{PairwiseSubject: " "}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

// TestRegisterReportsAnAgentThatFails: a tenant or a DID the agent does
// not make fails the call, and the next login tries again.
func TestRegisterReportsAnAgentThatFails(t *testing.T) {
	svc, agent, _ := newHolder(t, nil)
	ctx := context.Background()
	agent.SetStatus("POST /multi-tenancy/create-tenant", http.StatusInternalServerError)
	_, err := svc.Register(ctx, connect.NewRequest(&backendv1.RegisterRequest{PairwiseSubject: holderSubject}))
	wantCode(t, err, connect.CodeUnavailable)
	agent.SetStatus("POST /dids/write", http.StatusBadRequest)
	_, err = svc.Register(ctx, connect.NewRequest(&backendv1.RegisterRequest{PairwiseSubject: holderSubject}))
	wantCode(t, err, connect.CodeInvalidArgument)
	if registerHolder(t, svc) == "" {
		t.Error("the next login made no wallet")
	}
}

// TestHolderCallsNeedAKnownWallet: a wallet id that Register did not
// return, such as the tenant of an organisation, opens nothing.
func TestHolderCallsNeedAKnownWallet(t *testing.T) {
	svc, _, _ := newHolder(t, nil)
	ctx := context.Background()
	_, err := svc.ListCredentials(ctx, connect.NewRequest(&backendv1.ListCredentialsRequest{WalletId: "org-tenant"}))
	wantCode(t, err, connect.CodeNotFound)
	_, err = svc.ListInbox(ctx, connect.NewRequest(&backendv1.ListInboxRequest{}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

// TestAcceptOfferThroughInvitation is ADR-062 decision 3: the wallet
// takes the invitation of the issuer, accepts the offer it carries, and
// returns the AnonCreds credential as the JSON view of the revealed
// values.
func TestAcceptOfferThroughInvitation(t *testing.T) {
	svc, agent, _ := newHolder(t, nil)
	ctx := context.Background()
	wallet := registerHolder(t, svc)
	res, err := svc.AcceptOffer(ctx, connect.NewRequest(&backendv1.AcceptOfferRequest{
		WalletId: wallet, OfferUri: fake.Invitation(testdata, "offer"),
	}))
	if err != nil {
		t.Fatalf("AcceptOffer: %v", err)
	}
	cred := res.Msg.GetCredential()
	if cred.GetId() != "anoncreds:"+fake.OfferRecord || cred.GetType() != "Farmer" || !cred.GetPermanent() ||
		cred.GetIssuer() != "did:indy:bcovrin:testnet:Ra8FGb2mXsTg1d4VqVnYpS" || cred.GetCredential().GetFormat() != commonv1.Format_FORMAT_ANONCREDS {
		t.Fatalf("credential = %+v", cred)
	}
	var view struct {
		Subject map[string]string `json:"credentialSubject"`
		CredDef string            `json:"credentialDefinitionId"`
	}
	if err := json.Unmarshal(cred.GetCredential().GetPayload(), &view); err != nil || view.Subject["acres"] != "12" ||
		view.Subject["fullName"] != "[holder]" || !strings.Contains(view.CredDef, "/CLAIM_DEF/") {
		t.Errorf("view %s, %v", cred.GetCredential().GetPayload(), err)
	}
	var sent struct {
		Label string `json:"label"`
	}
	if err := json.Unmarshal(agent.Body("POST /didcomm/oob/receive-invitation-url"), &sent); err != nil || sent.Label != "[holder wallet]" {
		t.Errorf("the invitation went with %+v, %v", sent, err)
	}
	if body := string(agent.Body("POST /didcomm/credentials/accept-offer")); body != `{"credentialExchangeRecordId":"`+fake.OfferRecord+`"}` {
		t.Errorf("accept-offer %s", body)
	}
}

// TestAcceptOfferFromTheInbox: an offer that came over a connection is
// accepted by its inbox id.
func TestAcceptOfferFromTheInbox(t *testing.T) {
	svc, agent, _ := newHolder(t, nil)
	agent.SetInbox(true)
	wallet := registerHolder(t, svc)
	res, err := svc.AcceptOffer(context.Background(), connect.NewRequest(&backendv1.AcceptOfferRequest{WalletId: wallet, InboxId: fake.OfferRecord}))
	if err != nil || res.Msg.GetCredential().GetType() != "Farmer" {
		t.Fatalf("AcceptOffer = %+v, %v", res, err)
	}
	if slices.Contains(agent.Calls(), "POST /didcomm/oob/receive-invitation-url") {
		t.Error("an inbox offer took an invitation")
	}
}

// TestAcceptOfferRefusals: an offer the issuer withdraws, an invitation
// with no offer, an offer that never comes, and an issuer that never
// answers stop the call with a reason.
func TestAcceptOfferRefusals(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		change func(*fake.Agent)
		uri    string
		code   connect.Code
		text   string
	}{
		"withdrawn":     {func(a *fake.Agent) { a.SetCredentialEnd(fake.OfferAbandoned) }, "offer", connect.CodeFailedPrecondition, "withdrew"},
		"no offer":      {nil, "request", connect.CodeInvalidArgument, "no credential offer"},
		"no answer":     {func(a *fake.Agent) { a.SetCredentialEnd(fake.OfferRequestSent) }, "offer", connect.CodeDeadlineExceeded, "did not send"},
		"bad invite":    {nil, "", connect.CodeInvalidArgument, "offer"},
		"refused":       {func(a *fake.Agent) { a.SetStatus("POST /didcomm/oob/receive-invitation-url", http.StatusBadRequest) }, "offer", connect.CodeInvalidArgument, "invitation"},
		"oid4vci offer": {nil, "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer%2Foffer", connect.CodeFailedPrecondition, "DIDComm"},
	} {
		svc, agent, _ := newHolder(t, nil)
		if c.change != nil {
			c.change(agent)
		}
		uri := c.uri
		if uri == "offer" || uri == "request" {
			uri = fake.Invitation(testdata, uri)
		}
		_, err := svc.AcceptOffer(ctx, connect.NewRequest(&backendv1.AcceptOfferRequest{WalletId: registerHolder(t, svc), OfferUri: uri}))
		if connect.CodeOf(err) != c.code || !strings.Contains(err.Error(), c.text) {
			t.Errorf("%s: %v", name, err)
		}
	}
	svc, _, _ := newHolder(t, nil)
	_, err := svc.AcceptOffer(ctx, connect.NewRequest(&backendv1.AcceptOfferRequest{WalletId: registerHolder(t, svc), InboxId: "gone"}))
	wantCode(t, err, connect.CodeNotFound)
}

// TestListCloudCredentials is ADR-062 decision 5: the wallet lists the
// AnonCreds credential of each finished exchange and each stored W3C
// credential, newest first. The agent removes a W3C credential and
// keeps an AnonCreds one.
func TestListCloudCredentials(t *testing.T) {
	svc, agent, _ := newHolder(t, func(o *service.Options) { o.PageSizeMax = 10 })
	ctx := context.Background()
	wallet := registerHolder(t, svc)
	res, err := svc.ListCredentials(ctx, connect.NewRequest(&backendv1.ListCredentialsRequest{WalletId: wallet}))
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	list := res.Msg.GetCredentials()
	if len(list) != 2 || res.Msg.GetPage().GetTotalSize() != 2 {
		t.Fatalf("credentials = %+v", list)
	}
	anon, w3c := list[0], list[1]
	if anon.GetId() != "anoncreds:"+fake.OfferRecord || !anon.GetPermanent() || anon.GetReceivedAt() == nil {
		t.Errorf("anoncreds = %+v", anon)
	}
	if w3c.GetId() != "w3c:"+fake.W3cRecord || w3c.GetPermanent() || w3c.GetType() != "PermanentResidentCard" ||
		w3c.GetCredential().GetFormat() != commonv1.Format_FORMAT_LDP_VC || w3c.GetIssuer() != "did:key:z6MkwpCi3Hu6EZtcbWTrK4GWFxtgf4ZvynCjhEtFqGjBV5Xi" ||
		!strings.Contains(string(w3c.GetCredential().GetPayload()), `"@context"`) {
		t.Errorf("w3c = %+v", w3c)
	}
	if _, err = svc.DeleteCredential(ctx, connect.NewRequest(&backendv1.DeleteCredentialRequest{WalletId: wallet, CredentialId: w3c.GetId()})); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}
	if body := string(agent.Body("DELETE /openid4vc/holder/credential")); body != `{"credentialId":"`+fake.W3cRecord+`","credentialType":"w3c-vc"}` {
		t.Errorf("delete %s", body)
	}
	_, err = svc.DeleteCredential(ctx, connect.NewRequest(&backendv1.DeleteCredentialRequest{WalletId: wallet, CredentialId: anon.GetId()}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	_, err = svc.DeleteCredential(ctx, connect.NewRequest(&backendv1.DeleteCredentialRequest{WalletId: wallet, CredentialId: "other"}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

// TestListCloudCredentialsPages: a page holds page_size credentials and
// the token of the next page.
func TestListCloudCredentialsPages(t *testing.T) {
	svc, _, _ := newHolder(t, nil)
	ctx := context.Background()
	wallet := registerHolder(t, svc)
	first, err := svc.ListCredentials(ctx, connect.NewRequest(&backendv1.ListCredentialsRequest{WalletId: wallet}))
	if err != nil || len(first.Msg.GetCredentials()) != 1 || first.Msg.GetPage().GetNextPageToken() == "" {
		t.Fatalf("first page = %+v, %v", first, err)
	}
	second, err := svc.ListCredentials(ctx, connect.NewRequest(&backendv1.ListCredentialsRequest{WalletId: wallet,
		Page: &commonv1.Pagination{PageToken: first.Msg.GetPage().GetNextPageToken()}}))
	if err != nil || len(second.Msg.GetCredentials()) != 1 || second.Msg.GetPage().GetNextPageToken() != "" ||
		second.Msg.GetCredentials()[0].GetId() == first.Msg.GetCredentials()[0].GetId() {
		t.Fatalf("second page = %+v, %v", second, err)
	}
	_, err = svc.ListCredentials(ctx, connect.NewRequest(&backendv1.ListCredentialsRequest{WalletId: wallet,
		Page: &commonv1.Pagination{PageToken: "x"}}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

// TestAcceptProofRequest is ADR-062 decision 3: the wallet takes the
// invitation of the verifier and answers the proof request it carries.
// The answer names what the wallet shared.
func TestAcceptProofRequest(t *testing.T) {
	svc, agent, _ := newHolder(t, nil)
	ctx := context.Background()
	wallet := registerHolder(t, svc)
	res, err := svc.Present(ctx, connect.NewRequest(&backendv1.PresentRequest{WalletId: wallet, RequestUri: fake.Invitation(testdata, "request")}))
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if !res.Msg.GetAccepted() || strings.Join(res.Msg.GetSharedClaims(), "|") != "fullName|acres >= 10" || res.Msg.GetVerifierState() != "done" {
		t.Fatalf("Present = %+v", res.Msg)
	}
	if !slices.Contains(agent.Calls(), "POST /didcomm/proofs/"+fake.ProofRecord+"/accept-request") {
		t.Error("the wallet sent no proof")
	}
}

// TestAcceptProofRequestStates: a proof the verifier refuses answers
// not accepted, a verifier that never answers stops the call, and a
// request from the inbox goes by its id.
func TestAcceptProofRequestStates(t *testing.T) {
	ctx := context.Background()
	svc, agent, _ := newHolder(t, nil)
	agent.SetProofEnd(fake.HolderProofAbandoned)
	res, err := svc.Present(ctx, connect.NewRequest(&backendv1.PresentRequest{WalletId: registerHolder(t, svc), RequestUri: fake.Invitation(testdata, "request")}))
	if err != nil || res.Msg.GetAccepted() || res.Msg.GetVerifierState() != "abandoned" {
		t.Errorf("refused = %+v, %v", res, err)
	}
	svc, agent, _ = newHolder(t, nil)
	agent.SetProofEnd(fake.HolderProofSent)
	_, err = svc.Present(ctx, connect.NewRequest(&backendv1.PresentRequest{WalletId: registerHolder(t, svc), RequestUri: fake.Invitation(testdata, "request")}))
	wantCode(t, err, connect.CodeDeadlineExceeded)
	svc, agent, _ = newHolder(t, nil)
	agent.SetInbox(true)
	res, err = svc.Present(ctx, connect.NewRequest(&backendv1.PresentRequest{WalletId: registerHolder(t, svc), InboxId: fake.ProofRecord}))
	if err != nil || !res.Msg.GetAccepted() {
		t.Errorf("inbox = %+v, %v", res, err)
	}
	_, err = svc.Present(ctx, connect.NewRequest(&backendv1.PresentRequest{WalletId: registerHolder(t, svc), RequestUri: fake.Invitation(testdata, "offer")}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = svc.Present(ctx, connect.NewRequest(&backendv1.PresentRequest{WalletId: registerHolder(t, svc), RequestUri: "openid4vp://?request_uri=https%3A%2F%2Fverifier%2Fr"}))
	wantCode(t, err, connect.CodeFailedPrecondition)
}

// TestOpenInvitationKeepsTheConnection: an invitation with no message
// makes a connection, which the connection list shows.
func TestOpenInvitationKeepsTheConnection(t *testing.T) {
	svc, _, _ := newHolder(t, nil)
	ctx := context.Background()
	wallet := registerHolder(t, svc)
	res, err := svc.OpenInvitation(ctx, connect.NewRequest(&backendv1.OpenInvitationRequest{WalletId: wallet, InvitationUri: fake.Invitation(testdata, "connection")}))
	if err != nil || res.Msg.GetConnection().GetLabel() != "[verifier organisation]" || res.Msg.GetConnection().GetId() == "" {
		t.Fatalf("OpenInvitation = %+v, %v", res, err)
	}
	list, err := svc.ListWalletConnections(ctx, connect.NewRequest(&backendv1.ListWalletConnectionsRequest{WalletId: wallet}))
	if err != nil || len(list.Msg.GetConnections()) != 2 || list.Msg.GetConnections()[0].GetLabel() != "[verifier organisation]" ||
		list.Msg.GetConnections()[0].GetState() != "completed" {
		t.Fatalf("ListWalletConnections = %+v, %v", list, err)
	}
	_, err = svc.OpenInvitation(ctx, connect.NewRequest(&backendv1.OpenInvitationRequest{WalletId: wallet, InvitationUri: "https://example.org/"}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

// TestListInbox: an offer and a proof request that came over a
// connection wait in the inbox with what they carry.
func TestListInbox(t *testing.T) {
	svc, agent, _ := newHolder(t, nil)
	ctx := context.Background()
	wallet := registerHolder(t, svc)
	empty, err := svc.ListInbox(ctx, connect.NewRequest(&backendv1.ListInboxRequest{WalletId: wallet}))
	if err != nil || len(empty.Msg.GetItems()) != 0 {
		t.Fatalf("empty inbox = %+v, %v", empty, err)
	}
	agent.SetInbox(true)
	res, err := svc.ListInbox(ctx, connect.NewRequest(&backendv1.ListInboxRequest{WalletId: wallet}))
	if err != nil || len(res.Msg.GetItems()) != 2 {
		t.Fatalf("ListInbox = %+v, %v", res, err)
	}
	proof, offer := res.Msg.GetItems()[0], res.Msg.GetItems()[1]
	if proof.GetKind() != backendv1.InboxItem_KIND_PROOF_REQUEST || proof.GetId() != fake.ProofRecord || proof.GetName() != "Farmer check" ||
		strings.Join(proof.GetRequested(), "|") != "fullName|acres >= 10" || proof.GetConnectionLabel() != "[verifier organisation]" {
		t.Errorf("proof = %+v", proof)
	}
	if offer.GetKind() != backendv1.InboxItem_KIND_OFFER || offer.GetId() != fake.OfferRecord || len(offer.GetOffered()) != 2 ||
		offer.GetOffered()[0].GetName() != "fullName" || offer.GetName() != "Farmer" || offer.GetConnectionLabel() != "[issuer organisation]" {
		t.Errorf("offer = %+v", offer)
	}
}

// TestWalletDids is ADR-062 decision 6: the wallet lists its did:key
// identifiers and makes a new one. It picks no default DID.
func TestWalletDids(t *testing.T) {
	svc, agent, _ := newHolder(t, nil)
	ctx := context.Background()
	wallet := registerHolder(t, svc)
	res, err := svc.ListDids(ctx, connect.NewRequest(&backendv1.ListDidsRequest{WalletId: wallet}))
	if err != nil || len(res.Msg.GetDids()) != 1 || res.Msg.GetDids()[0].GetDid() != fake.HolderDid || res.Msg.GetDids()[0].GetKeyId() == "" {
		t.Fatalf("ListDids = %+v, %v", res, err)
	}
	made, err := svc.CreateDid(ctx, connect.NewRequest(&backendv1.CreateDidRequest{WalletId: wallet, Method: "did:key"}))
	if err != nil || made.Msg.GetDid().GetDid() != fake.HolderDid {
		t.Fatalf("CreateDid = %+v, %v", made, err)
	}
	if n := count(agent.Calls(), "POST /dids/write"); n != 2 {
		t.Errorf("the agent made %d DIDs", n)
	}
	for _, bad := range []*backendv1.CreateDidRequest{{WalletId: wallet, Method: "did:web"}, {WalletId: wallet, Method: "did:key", KeyId: "k-1"}} {
		_, err = svc.CreateDid(ctx, connect.NewRequest(bad))
		wantCode(t, err, connect.CodeInvalidArgument)
	}
	_, err = svc.SetDefaultDid(ctx, connect.NewRequest(&backendv1.SetDefaultDidRequest{WalletId: wallet, Did: fake.HolderDid}))
	wantCode(t, err, connect.CodeUnimplemented)
}

// TestCapabilitiesListHolderRole is ADR-062 decision 7: with the agent
// the answer lists the holder role, the DIDComm wallet, and the DIDs of
// a wallet. Without it the answer lists none of them.
func TestCapabilitiesListHolderRole(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newHolder(t, nil)
	with, err := svc.GetCapabilities(ctx, connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(with.Msg.GetRoles(), commonv1.Role_ROLE_HOLDER) ||
		!slices.Contains(with.Msg.GetFeatures(), backendv1.Feature_FEATURE_WALLET_DIDCOMM) ||
		!slices.Contains(with.Msg.GetFeatures(), backendv1.Feature_FEATURE_WALLET_DIDS) ||
		slices.Contains(with.Msg.GetFeatures(), backendv1.Feature_FEATURE_WALLET_KEYS) ||
		strings.Join(with.Msg.GetWalletDidMethods(), ",") != "did:key" {
		t.Errorf("with the agent: roles %v, features %v, methods %v", with.Msg.GetRoles(), with.Msg.GetFeatures(), with.Msg.GetWalletDidMethods())
	}
	plain, _ := newService(t, nil)
	without, err := plain.GetCapabilities(ctx, connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(without.Msg.GetRoles(), commonv1.Role_ROLE_HOLDER) ||
		slices.Contains(without.Msg.GetFeatures(), backendv1.Feature_FEATURE_WALLET_DIDCOMM) || len(without.Msg.GetWalletDidMethods()) != 0 {
		t.Errorf("without the agent: roles %v, features %v", without.Msg.GetRoles(), without.Msg.GetFeatures())
	}
}

// TestHolderCallsReportAnAgentThatFails: an agent that fails a list
// fails the call.
func TestHolderCallsReportAnAgentThatFails(t *testing.T) {
	svc, agent, _ := newHolder(t, nil)
	ctx := context.Background()
	wallet := registerHolder(t, svc)
	for key, call := range map[string]func() error{
		"GET /didcomm/credentials/w3c": func() error {
			_, err := svc.ListCredentials(ctx, connect.NewRequest(&backendv1.ListCredentialsRequest{WalletId: wallet}))
			return err
		},
		"GET /didcomm/connections": func() error {
			_, err := svc.ListWalletConnections(ctx, connect.NewRequest(&backendv1.ListWalletConnectionsRequest{WalletId: wallet}))
			return err
		},
		"GET /didcomm/proofs": func() error {
			_, err := svc.ListInbox(ctx, connect.NewRequest(&backendv1.ListInboxRequest{WalletId: wallet}))
			return err
		},
		"GET /dids": func() error {
			_, err := svc.ListDids(ctx, connect.NewRequest(&backendv1.ListDidsRequest{WalletId: wallet}))
			return err
		},
	} {
		agent.SetStatus(key, http.StatusInternalServerError)
		if err := call(); connect.CodeOf(err) != connect.CodeUnavailable {
			t.Errorf("%s: %v", key, err)
		}
	}
}

// TestAcceptOfferOfAJsonLdCredential: an offer the issuer answers with
// a W3C JSON-LD credential returns the stored credential, and a
// finished exchange that names none fails the call.
func TestAcceptOfferOfAJsonLdCredential(t *testing.T) {
	ctx := context.Background()
	svc, agent, _ := newHolder(t, nil)
	agent.SetCredentialEnd(fake.OfferDoneJSONLD)
	res, err := svc.AcceptOffer(ctx, connect.NewRequest(&backendv1.AcceptOfferRequest{WalletId: registerHolder(t, svc), OfferUri: fake.Invitation(testdata, "offer")}))
	if err != nil || res.Msg.GetCredential().GetId() != "w3c:"+fake.W3cRecord || res.Msg.GetCredential().GetPermanent() {
		t.Fatalf("AcceptOffer = %+v, %v", res, err)
	}
	svc, agent, _ = newHolder(t, nil)
	agent.SetCredentialEnd(fake.OfferDoneUnbound)
	_, err = svc.AcceptOffer(ctx, connect.NewRequest(&backendv1.AcceptOfferRequest{WalletId: registerHolder(t, svc), OfferUri: fake.Invitation(testdata, "offer")}))
	wantCode(t, err, connect.CodeInternal)
	svc, agent, _ = newHolder(t, nil)
	agent.SetCredentialEnd(fake.OfferDoneJSONLD)
	wallet := registerHolder(t, svc)
	agent.SetStatus("GET /didcomm/credentials/w3c", http.StatusInternalServerError)
	_, err = svc.AcceptOffer(ctx, connect.NewRequest(&backendv1.AcceptOfferRequest{WalletId: wallet, OfferUri: fake.Invitation(testdata, "offer")}))
	wantCode(t, err, connect.CodeUnavailable)
}

// TestHolderExchangeFailures: an agent that fails a step of an offer, a
// proof, or a connection fails the call with the step.
func TestHolderExchangeFailures(t *testing.T) {
	ctx := context.Background()
	for key, call := range map[string]func(*service.Service, string) error{
		"POST /didcomm/credentials/accept-offer": func(svc *service.Service, w string) error {
			_, err := svc.AcceptOffer(ctx, connect.NewRequest(&backendv1.AcceptOfferRequest{WalletId: w, OfferUri: fake.Invitation(testdata, "offer")}))
			return err
		},
		"GET /didcomm/credentials/" + fake.OfferRecord: func(svc *service.Service, w string) error {
			_, err := svc.AcceptOffer(ctx, connect.NewRequest(&backendv1.AcceptOfferRequest{WalletId: w, OfferUri: fake.Invitation(testdata, "offer")}))
			return err
		},
		"GET /didcomm/credentials": func(svc *service.Service, w string) error {
			_, err := svc.AcceptOffer(ctx, connect.NewRequest(&backendv1.AcceptOfferRequest{WalletId: w, OfferUri: fake.Invitation(testdata, "offer")}))
			return err
		},
		"GET /didcomm/proofs": func(svc *service.Service, w string) error {
			_, err := svc.Present(ctx, connect.NewRequest(&backendv1.PresentRequest{WalletId: w, RequestUri: fake.Invitation(testdata, "request")}))
			return err
		},
		"GET /didcomm/proofs/" + fake.ProofRecord + "/form-data": func(svc *service.Service, w string) error {
			_, err := svc.Present(ctx, connect.NewRequest(&backendv1.PresentRequest{WalletId: w, RequestUri: fake.Invitation(testdata, "request")}))
			return err
		},
		"POST /didcomm/proofs/" + fake.ProofRecord + "/accept-request": func(svc *service.Service, w string) error {
			_, err := svc.Present(ctx, connect.NewRequest(&backendv1.PresentRequest{WalletId: w, RequestUri: fake.Invitation(testdata, "request")}))
			return err
		},
		"GET /didcomm/proofs/" + fake.ProofRecord: func(svc *service.Service, w string) error {
			_, err := svc.Present(ctx, connect.NewRequest(&backendv1.PresentRequest{WalletId: w, RequestUri: fake.Invitation(testdata, "request")}))
			return err
		},
		"POST /didcomm/oob/receive-invitation-url": func(svc *service.Service, w string) error {
			_, err := svc.OpenInvitation(ctx, connect.NewRequest(&backendv1.OpenInvitationRequest{WalletId: w, InvitationUri: fake.Invitation(testdata, "connection")}))
			return err
		},
		"GET /didcomm/connections/8a9b0c1d-2e3f-4a5b-9c6d-7e8f9a0b1c2d": func(svc *service.Service, w string) error {
			_, err := svc.OpenInvitation(ctx, connect.NewRequest(&backendv1.OpenInvitationRequest{WalletId: w, InvitationUri: fake.Invitation(testdata, "connection")}))
			return err
		},
		"GET /didcomm/connections": func(svc *service.Service, w string) error {
			_, err := svc.ListInbox(ctx, connect.NewRequest(&backendv1.ListInboxRequest{WalletId: w}))
			return err
		},
		"GET /didcomm/credentials?inbox": func(svc *service.Service, w string) error {
			_, err := svc.ListInbox(ctx, connect.NewRequest(&backendv1.ListInboxRequest{WalletId: w}))
			return err
		},
		"GET /didcomm/credentials?held": func(svc *service.Service, w string) error {
			_, err := svc.ListCredentials(ctx, connect.NewRequest(&backendv1.ListCredentialsRequest{WalletId: w}))
			return err
		},
		"POST /dids/write": func(svc *service.Service, w string) error {
			_, err := svc.CreateDid(ctx, connect.NewRequest(&backendv1.CreateDidRequest{WalletId: w, Method: "did:key"}))
			return err
		},
		"DELETE /openid4vc/holder/credential": func(svc *service.Service, w string) error {
			_, err := svc.DeleteCredential(ctx, connect.NewRequest(&backendv1.DeleteCredentialRequest{WalletId: w, CredentialId: "w3c:x"}))
			return err
		},
	} {
		svc, agent, _ := newHolder(t, nil)
		wallet := registerHolder(t, svc)
		path, _, _ := strings.Cut(key, "?")
		agent.SetStatus(path, http.StatusInternalServerError)
		if err := call(svc, wallet); err == nil {
			t.Errorf("%s: no error", key)
		}
	}
}

// TestHolderWaitsRunOut: an offer or a request of an invitation that
// never reaches the wallet stops the call, and so does a connection the
// agent does not finish.
func TestHolderWaitsRunOut(t *testing.T) {
	ctx := context.Background()
	svc, agent, _ := newHolder(t, nil)
	wallet := registerHolder(t, svc)
	agent.SetStatus("POST /didcomm/oob/receive-invitation-url")
	// The fake keeps the offer off the thread after an accept.
	agent.SetInbox(true)
	if _, err := svc.AcceptOffer(ctx, connect.NewRequest(&backendv1.AcceptOfferRequest{WalletId: wallet, InboxId: fake.OfferRecord})); err != nil {
		t.Fatal(err)
	}
	_, err := svc.AcceptOffer(ctx, connect.NewRequest(&backendv1.AcceptOfferRequest{WalletId: wallet, OfferUri: fake.Invitation(testdata, "offer")}))
	wantCode(t, err, connect.CodeDeadlineExceeded)
	if _, err = svc.Present(ctx, connect.NewRequest(&backendv1.PresentRequest{WalletId: wallet, InboxId: fake.ProofRecord})); err != nil {
		t.Fatal(err)
	}
	_, err = svc.Present(ctx, connect.NewRequest(&backendv1.PresentRequest{WalletId: wallet, RequestUri: fake.Invitation(testdata, "request")}))
	wantCode(t, err, connect.CodeDeadlineExceeded)
	_, err = svc.Present(ctx, connect.NewRequest(&backendv1.PresentRequest{WalletId: wallet, InboxId: "gone"}))
	wantCode(t, err, connect.CodeNotFound)
	_, err = svc.OpenInvitation(ctx, connect.NewRequest(&backendv1.OpenInvitationRequest{WalletId: wallet, InvitationUri: fake.Invitation(testdata, "offer") + "&x=1"}))
	if err != nil {
		t.Fatal(err)
	}
}

// TestRegisterOpensAStoredWalletOnly: a store that fails fails the
// call, and a record the adapter cannot read makes a new wallet.
func TestRegisterOpensAStoredWalletOnly(t *testing.T) {
	ctx := context.Background()
	svc, agent, kv := newHolder(t, nil)
	registerHolder(t, svc)
	keys, err := kv.List(ctx, "holder/")
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys %v, %v", keys, err)
	}
	if err := kv.Put(ctx, keys[0], []byte("{")); err != nil {
		t.Fatal(err)
	}
	registerHolder(t, svc)
	if n := count(agent.Calls(), "POST /multi-tenancy/create-tenant"); n != 2 {
		t.Errorf("tenants = %d", n)
	}
}
