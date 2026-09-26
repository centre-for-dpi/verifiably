// SPDX-License-Identifier: Apache-2.0

package issuers_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/fetchguard"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/cards"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/issuers"
)

// docs answers GET by URL from a map, and counts the reads.
type docs struct {
	body  map[string]string
	reads map[string]int
}

func (d *docs) Get(_ context.Context, url string) (fetchguard.Doc, error) {
	if d.reads == nil {
		d.reads = map[string]int{}
	}
	d.reads[url]++
	body, ok := d.body[url]
	if !ok {
		return fetchguard.Doc{}, errors.New("not found")
	}
	return fetchguard.Doc{URL: url, Body: []byte(body)}, nil
}

const preAuth = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

// metadata returns issuer metadata with one configuration per format.
func metadata(issuer, extra string) string {
	return `{"credential_issuer":"` + issuer + `",` + extra +
		`"display":[{"name":"Ministry of Health"}],"credential_configurations_supported":{` +
		`"nurse-licence_dc+sd-jwt":{"format":"dc+sd-jwt","vct":"NurseLicence","display":[{"name":"Nurse licence"}]},` +
		`"farmer_ldp_vc":{"format":"ldp_vc","credential_definition":{"type":["VerifiableCredential","FarmerRegistration"]}}}}`
}

func methods(o *walletportalv1.Offering) string {
	var out []string
	for _, m := range o.GetClaimMethods() {
		out = append(out, m.String())
	}
	return strings.Join(out, ",")
}

// TestHowToClaimFromMetadata checks that the grants the metadata names
// decide the ways to claim: a pre-authorized grant gives the code, an
// authorization code grant gives the sign in at the issuer. The grants
// come from the issuer metadata, then from the metadata of its
// authorization server.
func TestHowToClaimFromMetadata(t *testing.T) {
	for name, tc := range map[string]struct {
		grants []string
		anon   bool
		want   string
	}{
		"both":      {[]string{"authorization_code", preAuth}, false, "CLAIM_METHOD_AUTHORIZATION_CODE,CLAIM_METHOD_PRE_AUTHORIZED_CODE"},
		"code only": {[]string{preAuth}, false, "CLAIM_METHOD_PRE_AUTHORIZED_CODE"},
		"sign in":   {[]string{"authorization_code", "refresh_token"}, false, "CLAIM_METHOD_AUTHORIZATION_CODE"},
		"anonymous": {[]string{"authorization_code"}, true, "CLAIM_METHOD_AUTHORIZATION_CODE,CLAIM_METHOD_PRE_AUTHORIZED_CODE"},
		"none":      {nil, false, ""},
	} {
		var got []string
		for _, m := range issuers.MethodsOf(tc.grants, tc.anon) {
			got = append(got, m.String())
		}
		if strings.Join(got, ",") != tc.want {
			t.Errorf("%s: %v, want %s", name, got, tc.want)
		}
	}
	d := &docs{body: map[string]string{
		"https://a.example/.well-known/openid-credential-issuer": metadata("https://a.example",
			`"grant_types_supported":["`+preAuth+`"],`),
		"https://b.example/.well-known/openid-credential-issuer": metadata("https://b.example",
			`"authorization_servers":["https://login.b.example/realms/b"],`),
		"https://login.b.example/realms/b/.well-known/oauth-authorization-server": `{"grant_types_supported":["authorization_code","` + preAuth + `"]}`,
		"https://c.example/.well-known/openid-credential-issuer":                  metadata("https://c.example", ""),
		"https://c.example/.well-known/openid-configuration":                      `{"issuer":"https://c.example"}`,
	}}
	c, err := issuers.New(issuers.Options{Public: d})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for issuer, want := range map[string]string{
		"https://a.example": "CLAIM_METHOD_PRE_AUTHORIZED_CODE",
		"https://b.example": "CLAIM_METHOD_AUTHORIZATION_CODE,CLAIM_METHOD_PRE_AUTHORIZED_CODE",
		// An authorization server that names no grant supports the
		// authorization code grant (RFC 8414 section 2).
		"https://c.example":    "CLAIM_METHOD_AUTHORIZATION_CODE",
		"https://gone.example": "",
	} {
		var got []string
		for _, m := range c.Methods(ctx, issuer) {
			got = append(got, m.String())
		}
		if strings.Join(got, ",") != want {
			t.Errorf("%s: %v, want %s", issuer, got, want)
		}
	}
}

// fakeTrust lists trusted issuers and answers a lookup.
type fakeTrust struct {
	trustv1connect.TrustServiceClient
	entries []*trustv1.TrustEntry
	err     error
}

func (f *fakeTrust) ListEntries(_ context.Context, req *connect.Request[trustv1.ListEntriesRequest],
) (*connect.Response[trustv1.ListEntriesResponse], error) {
	if f.err != nil {
		return nil, f.err
	}
	if req.Msg.GetRole() != commonv1.Role_ROLE_ISSUER {
		return connect.NewResponse(&trustv1.ListEntriesResponse{}), nil
	}
	return connect.NewResponse(&trustv1.ListEntriesResponse{Entries: f.entries}), nil
}

// TestCrawlReadsPeersAndTrustedIssuers checks the fallback catalogue:
// the metadata of each live issuer pair through its internal address,
// the metadata of each trusted issuer, one offering per configuration,
// the trust of each issuer, and the ways to claim.
func TestCrawlReadsPeersAndTrustedIssuers(t *testing.T) {
	internal := &docs{body: map[string]string{
		"http://issuer-a-schema-registry:8084/.well-known/openid-credential-issuer": metadata("https://issuer-a.example", ""),
	}}
	public := &docs{body: map[string]string{
		"https://registry.county.example/.well-known/openid-credential-issuer": `{"credential_issuer":"https://registry.county.example",` +
			`"grant_types_supported":["` + preAuth + `"],"credential_configurations_supported":{"trade":{"format":"mso_mdoc","doctype":"org.county.trade.1"}}}`,
		"https://issuer-a.example/.well-known/oauth-authorization-server": `{"grant_types_supported":["authorization_code"]}`,
	}}
	trust := &fakeTrust{entries: []*trustv1.TrustEntry{
		{DisplayName: "County Licensing Office", ServiceEndpoint: "https://registry.county.example/"},
		{DisplayName: "No endpoint"},
	}}
	lookup := func(_ context.Context, issuer, _ string) (cards.Trust, error) {
		return cards.Trust{Outcome: trustv1.TrustLookupResponse_OUTCOME_UNKNOWN}, nil
	}
	c, err := issuers.New(issuers.Options{
		Peers: func(context.Context) []issuers.Source {
			return []issuers.Source{{
				Endpoint: "http://issuer-a-schema-registry:8084", Public: "https://issuer-a.example", Peer: true,
				Channels: []backendv1.Channel{backendv1.Channel_CHANNEL_OID4VCI_PREAUTH},
			}}
		},
		Trust: trust, Lookup: lookup, Internal: internal, Public: public,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Offerings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("offerings = %v", got)
	}
	byType := map[string]*walletportalv1.Offering{}
	for _, o := range got {
		byType[o.GetSchema().GetType()] = o
	}
	nurse := byType["NurseLicence"]
	if nurse.GetCredentialIssuer() != "https://issuer-a.example" || nurse.GetIssuerName() != "Ministry of Health" ||
		nurse.GetTrust() != trustv1.TrustLookupResponse_OUTCOME_UNKNOWN ||
		nurse.GetSchema().GetFormats()[0] != commonv1.Format_FORMAT_DC_SD_JWT ||
		nurse.GetSchema().GetDisplay()[0].GetName() != "Nurse licence" ||
		nurse.GetSchema().GetConfigurationIds()["FORMAT_DC_SD_JWT"] != "nurse-licence_dc+sd-jwt" {
		t.Fatalf("nurse = %v", nurse)
	}
	// The authorization server of the pair names the authorization code
	// grant; the adapter of the pair adds the pre-authorized channel.
	if methods(nurse) != "CLAIM_METHOD_AUTHORIZATION_CODE,CLAIM_METHOD_PRE_AUTHORIZED_CODE" {
		t.Fatalf("nurse methods = %s", methods(nurse))
	}
	if byType["FarmerRegistration"].GetSchema().GetFormats()[0] != commonv1.Format_FORMAT_LDP_VC {
		t.Fatalf("farmer = %v", byType["FarmerRegistration"])
	}
	trade := byType["org.county.trade.1"]
	if trade.GetIssuerName() != "County Licensing Office" || trade.GetTrust() != trustv1.TrustLookupResponse_OUTCOME_TRUSTED ||
		methods(trade) != "CLAIM_METHOD_PRE_AUTHORIZED_CODE" {
		t.Fatalf("trade = %v", trade)
	}
	// A trusted issuer that is also a live pair counts once, with the
	// name of the trust list.
	trust.entries = append(trust.entries, &trustv1.TrustEntry{DisplayName: "Ministry of Health (listed)", ServiceEndpoint: "https://issuer-a.example"})
	again, err := c.Offerings(context.Background())
	if err != nil || len(again) != 3 {
		t.Fatalf("again = %v, %v", again, err)
	}
	for _, o := range again {
		if o.GetSchema().GetType() == "NurseLicence" && (o.GetTrust() != trustv1.TrustLookupResponse_OUTCOME_TRUSTED ||
			o.GetIssuerName() != "Ministry of Health (listed)") {
			t.Fatalf("merged = %v", o)
		}
	}
}

// TestCrawlSurvivesFaults checks that a broken source drops out, a
// broken trust registry leaves the live pairs, and no source gives an
// empty list.
func TestCrawlSurvivesFaults(t *testing.T) {
	c, err := issuers.New(issuers.Options{
		Peers: func(context.Context) []issuers.Source {
			return []issuers.Source{
				{Endpoint: "http://broken:8084", Public: "https://broken.example", Peer: true},
				{Endpoint: "http://bad-json:8084", Public: "https://bad.example", Peer: true},
			}
		},
		Trust:    &fakeTrust{err: errors.New("down")},
		Internal: &docs{body: map[string]string{"http://bad-json:8084/.well-known/openid-credential-issuer": "{"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Offerings(context.Background())
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v", got, err)
	}
	empty, err := issuers.New(issuers.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := empty.Offerings(context.Background()); err != nil || len(got) != 0 {
		t.Fatalf("empty = %v, %v", got, err)
	}
}

func TestReadMetadata(t *testing.T) {
	m, err := issuers.ReadMetadata([]byte(`{"credential_issuer":"https://x.example","credentials_supported":{` +
		`"a":{"format":"jwt_vc_json","scope":"Degree"},"b":{"format":"vc+sd-jwt"},"c":{"vct":"NoFormat"}},` +
		`"pre-authorized_grant_anonymous_access_supported":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if m.CredentialIssuer != "https://x.example" || len(m.Configurations) != 2 || !m.AnonymousPreAuth {
		t.Fatalf("metadata = %+v", m)
	}
	if m.Configurations[0].Type != "Degree" || m.Configurations[1].Type != "b" {
		t.Fatalf("configurations = %+v", m.Configurations)
	}
	if _, err := issuers.ReadMetadata([]byte("[")); err == nil {
		t.Fatal("want a parse error")
	}
}

// TestEndpointsOfTheAuthorizationServer checks that the wallet finds
// where to send the holder to sign in and where to trade the code: the
// first authorization server of the issuer, or the issuer itself.
func TestEndpointsOfTheAuthorizationServer(t *testing.T) {
	d := &docs{body: map[string]string{
		"https://b.example/.well-known/openid-credential-issuer": metadata("https://b.example",
			`"authorization_servers":["https://login.b.example/realms/b"],`),
		"https://login.b.example/realms/b/.well-known/oauth-authorization-server": `{"authorization_endpoint":"https://login.b.example/auth",` +
			`"token_endpoint":"https://login.b.example/token"}`,
		"https://c.example/.well-known/openid-credential-issuer": metadata("https://c.example", ""),
		"https://c.example/.well-known/openid-configuration":     `{"authorization_endpoint":"https://c.example/authorize"}`,
		"https://d.example/.well-known/openid-credential-issuer": "{",
	}}
	c, err := issuers.New(issuers.Options{Public: d})
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Endpoints(context.Background(), "https://b.example")
	if err != nil || got.Authorization != "https://login.b.example/auth" || got.Token != "https://login.b.example/token" {
		t.Fatalf("b = %+v, %v", got, err)
	}
	for _, issuer := range []string{"https://c.example", "https://d.example", "https://gone.example"} {
		if _, err := c.Endpoints(context.Background(), issuer); err == nil {
			t.Errorf("%s: want an error", issuer)
		}
	}
}

// TestServerReadsTheInteractiveEndpoint reads the authorization server
// an offer names: a server with a token endpoint and an interactive
// endpoint needs no authorization endpoint.
func TestServerReadsTheInteractiveEndpoint(t *testing.T) {
	d := &docs{body: map[string]string{
		"https://certify.example/v1/certify/.well-known/oauth-authorization-server": `{"token_endpoint":"https://certify.example/t",` +
			`"interactive_authorization_endpoint":"https://certify.example/iar"}`,
		"https://idp.example/.well-known/openid-configuration":          `{"authorization_endpoint":"https://idp.example/a","token_endpoint":"https://idp.example/t"}`,
		"https://broken.example/.well-known/oauth-authorization-server": `{"token_endpoint":"https://broken.example/t"}`,
	}}
	c, err := issuers.New(issuers.Options{Public: d})
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Server(context.Background(), "https://certify.example/v1/certify/")
	if err != nil || got.Interactive != "https://certify.example/iar" || got.Token != "https://certify.example/t" || got.Authorization != "" {
		t.Fatalf("certify = %+v %v", got, err)
	}
	got, err = c.Server(context.Background(), "https://idp.example")
	if err != nil || got.Interactive != "" || got.Authorization != "https://idp.example/a" {
		t.Fatalf("idp = %+v %v", got, err)
	}
	for _, server := range []string{"https://broken.example", "https://gone.example"} {
		if _, err := c.Server(context.Background(), server); !errors.Is(err, issuers.ErrNoEndpoints) {
			t.Errorf("%s: %v", server, err)
		}
	}
}
