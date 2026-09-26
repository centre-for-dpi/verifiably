// SPDX-License-Identifier: Apache-2.0

package credebl

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// orgServer answers the sign in and hands every other call to answer.
func orgServer(t *testing.T, answer func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/signin" {
			mustWrite(t, w, []byte(`{"data":{"access_token":"a.b.c"}}`))
			return
		}
		answer(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestOrgCallsWithoutAPlatform(t *testing.T) {
	var c *Client
	ctx := context.Background()
	calls := []error{
		func() error { _, err := c.CreateOrg(ctx, "n", "d"); return err }(),
		func() error { _, err := c.GetOrg(ctx, "o"); return err }(),
		func() error { _, _, err := c.ListOrgs(ctx, 1, 10); return err }(),
		c.DeleteOrg(ctx, "o"),
		c.CreateSharedWallet(ctx, "o", "l"),
		func() error { _, err := c.CreateDid(ctx, "o", DidRequest{}); return err }(),
		func() error { _, err := c.OrgDids(ctx, "o"); return err }(),
		c.SetPrimaryDid(ctx, "o", OrgDid{}),
		func() error { _, err := c.OrgMembers(ctx, "o"); return err }(),
	}
	for i, err := range calls {
		if !errors.Is(err, ErrNoPlatform) {
			t.Errorf("call %d: err = %v", i, err)
		}
	}
}

func TestOrgAnswersWithoutTheirParts(t *testing.T) {
	srv := orgServer(t, func(w http.ResponseWriter, _ *http.Request) { mustWrite(t, w, []byte(`{"data":{}}`)) })
	c := newClient(srv, nil)
	ctx := context.Background()
	if _, err := c.CreateOrg(ctx, "n", "d"); err == nil {
		t.Error("an organisation answer with no id passed")
	}
	if _, err := c.GetOrg(ctx, "o"); !errors.Is(err, ErrNoOrganisation) {
		t.Errorf("GetOrg err = %v", err)
	}
	if _, err := c.CreateDid(ctx, "o", DidRequest{}); err == nil {
		t.Error("a DID answer with no DID passed")
	}
}

func TestCreateOrgKeepsTheNameAndTheWalletLabelFits(t *testing.T) {
	var label string
	srv := orgServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/agents/wallet") {
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			label = body["label"]
		}
		mustWrite(t, w, []byte(`{"data":{"id":"o-1"}}`))
	})
	c := newClient(srv, nil)
	org, err := c.CreateOrg(context.Background(), "[ORGANISATION]", "d")
	if err != nil || org.Name != "[ORGANISATION]" {
		t.Errorf("org = %v, %v", org, err)
	}
	long := strings.Repeat("a", 40)
	if err := c.CreateSharedWallet(context.Background(), "o-1", " "+long+" "); err != nil {
		t.Fatal(err)
	}
	if len(label) != 25 {
		t.Errorf("label %q has %d characters, want 25", label, len(label))
	}
}

func TestListOrgsReadsAnEmptyPlatformAsNone(t *testing.T) {
	status := http.StatusNotFound
	srv := orgServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })
	c := newClient(srv, nil)
	orgs, total, err := c.ListOrgs(context.Background(), 1, 10)
	if err != nil || len(orgs) != 0 || total != 0 {
		t.Errorf("orgs = %v, %d, %v", orgs, total, err)
	}
	status = http.StatusBadRequest
	if _, _, err := c.ListOrgs(context.Background(), 1, 10); err == nil {
		t.Error("a refused list passed")
	}
}

func TestAgentTypeOfAnOrganisation(t *testing.T) {
	cases := map[string]Org{
		"":             {},
		AgentShared:    {Agents: []OrgAgent{{TenantID: "t-1"}}},
		AgentDedicated: {Agents: []OrgAgent{{}}},
	}
	named := Org{Agents: []OrgAgent{{TenantID: "t-1"}}}
	named.Agents[0].Type.Agent = "dedicated"
	cases[AgentDedicated+" named"] = named
	for want, org := range cases {
		if got := org.AgentType(); got != strings.TrimSuffix(want, " named") {
			t.Errorf("%q: got %q", want, got)
		}
	}
}

func TestPrimaryDidComesFirst(t *testing.T) {
	dids := []OrgDid{{Did: "a"}, {Did: "b"}, {Did: "c", IsPrimaryDid: true}, {Did: "d"}}
	primaryFirst(dids)
	var got []string
	for _, d := range dids {
		got = append(got, d.Did)
	}
	if strings.Join(got, "") != "cabd" {
		t.Errorf("order = %v", got)
	}
}

func TestSetPrimaryDidSendsTheDidAndItsRecord(t *testing.T) {
	var body map[string]string
	var method string
	srv := orgServer(t, func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		mustWrite(t, w, []byte(`{"statusCode":201}`))
	})
	c := newClient(srv, nil)
	if err := c.SetPrimaryDid(context.Background(), "o-1", OrgDid{ID: "r-1", Did: "did:key:z6Mk"}); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPut || body["id"] != "r-1" || body["did"] != "did:key:z6Mk" {
		t.Errorf("%s %v", method, body)
	}
}

func TestOrgCallsReportAFailure(t *testing.T) {
	srv := orgServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadRequest) })
	c := newClient(srv, nil)
	ctx := context.Background()
	for i, err := range []error{
		func() error { _, err := c.CreateOrg(ctx, "n", "d"); return err }(),
		func() error { _, err := c.GetOrg(ctx, "o"); return err }(),
		func() error { _, err := c.CreateDid(ctx, "o", DidRequest{}); return err }(),
		func() error { _, err := c.OrgDids(ctx, "o"); return err }(),
		func() error { _, err := c.OrgMembers(ctx, "o"); return err }(),
	} {
		if err == nil {
			t.Errorf("call %d passed", i)
		}
	}
}

// TestOrgCallsReadTheDocumentedAnswers reads the answers written from
// the platform sources through the fake (P6-C1).
func TestOrgCallsReadTheDocumentedAnswers(t *testing.T) {
	f := fake.New("../../testdata")
	t.Cleanup(f.Close)
	c := New(Options{
		HTTP:       dpgclient.New(dpgclient.Options{BaseURL: f.URL(), HTTP: f.Client(), Retries: -1, Sleep: func(time.Duration) {}}),
		Account:    Account{Email: "e", Password: "p", CryptoKey: "k"},
		OrgID:      "org-1",
		RandomSalt: func() ([]byte, error) { return fixedSalt, nil },
	})
	ctx := context.Background()
	const org = "0b6c2f0e-5a38-4a1e-9d2b-3f7c1e6a9d41"
	got, err := c.GetOrg(ctx, org)
	if err != nil || got.AgentType() != AgentShared || len(got.Agents[0].DidDocument) == 0 {
		t.Errorf("GetOrg = %+v, %v", got, err)
	}
	orgs, total, err := c.ListOrgs(ctx, 1, 10)
	if err != nil || total != 2 || len(orgs) != 2 || orgs[1].Name != PlatformOrgName {
		t.Errorf("ListOrgs = %v, %d, %v", orgs, total, err)
	}
	dids, err := c.OrgDids(ctx, org)
	if err != nil || len(dids) != 2 || !dids[0].IsPrimaryDid || !strings.HasPrefix(dids[0].Did, "did:key:") {
		t.Errorf("OrgDids = %v, %v", dids, err)
	}
	did, err := c.CreateDid(ctx, org, DidRequest{Method: "key", KeyType: "ed25519", IsPrimaryDid: true})
	if err != nil || did.Did != dids[0].Did {
		t.Errorf("CreateDid = %v, %v", did, err)
	}
	members, err := c.OrgMembers(ctx, org)
	if err != nil || len(members) != 2 || strings.Join(members[0].Roles, ",") != "owner" || strings.Join(members[1].Roles, ",") != "issuer" {
		t.Errorf("OrgMembers = %v, %v", members, err)
	}
	if err := c.DeleteOrg(ctx, org); err != nil {
		t.Errorf("DeleteOrg: %v", err)
	}
	if !strings.Contains(strings.Join(f.Calls(), " "), "DELETE /v1/orgs/"+org) {
		t.Errorf("calls = %v", f.Calls())
	}
}
