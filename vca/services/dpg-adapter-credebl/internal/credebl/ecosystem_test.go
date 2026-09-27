// SPDX-License-Identifier: Apache-2.0

package credebl

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// P6-C9: the ecosystem calls of the api gateway.

// ecosystemID is the id of the ecosystem of the fixtures.
const ecosystemID = "3c9d7a41-6e2b-4f8a-b1d5-7e0c2f4a9b63"

// TestEcosystemCalls: the status reads and sets, the platform admin
// invites itself before each create, the create sends the lead in the
// query, the list reads the lead and the member count, and the members
// read, join and leave. A not found list of members reads as none.
func TestEcosystemCalls(t *testing.T) {
	p := newProofServer(t)
	c, ctx := p.client(), context.Background()
	p.answers["GET /v1/ecosystem/status"] = doc(t, "ecosystem-status.json")
	p.answers["PUT /v1/config/ecosystem"] = doc(t, "ecosystem-config-updated.json")
	p.answers["POST /v1/invitations"] = doc(t, "ecosystem-invitation-created.json")
	p.answers["POST /v1/ecosystem"] = doc(t, "ecosystem-created.json")
	p.answers["GET /v1/ecosystem"] = doc(t, "ecosystems.json")
	p.answers["GET /v1/ecosystem/members"] = doc(t, "ecosystem-members.json")
	p.answers["POST /v1/ecosystem/invitation"] = doc(t, "ecosystem-member-invited.json")
	p.answers["DELETE /v1/ecosystem/member"] = doc(t, "ecosystem-member-deleted.json")
	on, err := c.EcosystemsEnabled(ctx)
	if err != nil || !on {
		t.Fatalf("status = %v, %v", on, err)
	}
	if err = c.SetEcosystemsEnabled(ctx, true); err != nil || string(p.bodies["PUT /v1/config/ecosystem"]) != `{"isEcosystemEnabled":true}` {
		t.Fatalf("set = %v, body %s", err, p.bodies["PUT /v1/config/ecosystem"])
	}
	created, err := c.CreateEcosystem(ctx, "org-1", "[ECOSYSTEM]", "[ECOSYSTEM DESCRIPTION]")
	if err != nil || created.ID != ecosystemID || created.Name != "[ECOSYSTEM]" {
		t.Fatalf("create = %+v, %v", created, err)
	}
	if body := string(p.bodies["POST /v1/invitations"]); body != `{"email":"admin@example.org"}` {
		t.Errorf("invitation body = %s", body)
	}
	if q := p.queries["POST /v1/ecosystem"]; q != "orgId=org-1" {
		t.Errorf("create query = %s", q)
	}
	if body := string(p.bodies["POST /v1/ecosystem"]); body != `{"description":"[ECOSYSTEM DESCRIPTION]","name":"[ECOSYSTEM]"}` {
		t.Errorf("create body = %s", body)
	}
	list, err := c.Ecosystems(ctx, "org-1")
	if err != nil || len(list) != 1 || list[0].ID != ecosystemID || list[0].MemberCount != 1 ||
		list[0].Lead == nil || list[0].Lead.ID != "0b6c2f0e-5a38-4a1e-9d2b-3f7c1e6a9d41" || list[0].Lead.Name != "[ORGANISATION]" {
		t.Fatalf("list = %+v, %v", list, err)
	}
	if q := p.queries["GET /v1/ecosystem"]; q != "orgId=org-1&pageNumber=1&pageSize=100" {
		t.Errorf("list query = %s", q)
	}
	members, err := c.EcosystemMembers(ctx, ecosystemID)
	if err != nil || len(members) != 1 || members[0].Org.ID != "5e1a9c3d-7b2f-4d6e-8a0c-4f3b2e1d9c87" || members[0].Status != "ACTIVE" || members[0].At.IsZero() {
		t.Fatalf("members = %+v, %v", members, err)
	}
	if q := p.queries["GET /v1/ecosystem/members"]; q != "ecosystemId="+ecosystemID+"&pageNumber=1&pageSize=100" {
		t.Errorf("members query = %s", q)
	}
	if err = c.InviteEcosystemMember(ctx, ecosystemID, "org-2"); err != nil {
		t.Fatal(err)
	}
	if body := string(p.bodies["POST /v1/ecosystem/invitation"]); body != `{"ecosystemId":"`+ecosystemID+`","orgId":"org-2"}` {
		t.Errorf("invite body = %s", body)
	}
	if err = c.RemoveEcosystemMember(ctx, ecosystemID, "org-2"); err != nil {
		t.Fatal(err)
	}
	if body := string(p.bodies["DELETE /v1/ecosystem/member"]); body != `{"ecosystemId":"`+ecosystemID+`","orgIds":["org-2"]}` {
		t.Errorf("remove body = %s", body)
	}
	p.status["GET /v1/ecosystem/members"] = http.StatusNotFound
	if members, err = c.EcosystemMembers(ctx, ecosystemID); err != nil || len(members) != 0 {
		t.Errorf("no member = %+v, %v", members, err)
	}
	for _, key := range []string{"GET /v1/ecosystem/status", "PUT /v1/config/ecosystem", "POST /v1/invitations", "GET /v1/ecosystem",
		"GET /v1/ecosystem/members", "POST /v1/ecosystem/invitation", "DELETE /v1/ecosystem/member"} {
		p.status[key] = http.StatusBadGateway
	}
	_, e1 := c.EcosystemsEnabled(ctx)
	e2 := c.SetEcosystemsEnabled(ctx, false)
	_, e3 := c.CreateEcosystem(ctx, "org-1", "n", "d")
	_, e4 := c.Ecosystems(ctx, "org-1")
	_, e5 := c.EcosystemMembers(ctx, ecosystemID)
	e6 := c.InviteEcosystemMember(ctx, ecosystemID, "org-2")
	e7 := c.RemoveEcosystemMember(ctx, ecosystemID, "org-2")
	for i, err := range []error{e1, e2, e3, e4, e5, e6, e7} {
		if err == nil {
			t.Errorf("call %d passed a failed platform", i+1)
		}
	}
	p.status["POST /v1/invitations"] = 0
	p.status["POST /v1/ecosystem"] = http.StatusConflict
	if _, err = c.CreateEcosystem(ctx, "org-1", "n", "d"); err == nil {
		t.Error("a name that exists passed")
	}
	var none *Client
	if _, err = none.Ecosystems(ctx, "org-1"); !errors.Is(err, ErrNoPlatform) {
		t.Errorf("no platform = %v", err)
	}
}
