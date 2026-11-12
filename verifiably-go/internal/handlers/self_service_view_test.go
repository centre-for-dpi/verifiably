package handlers

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/verifiably/verifiably-go/internal/issuance"
)

func TestSelfServiceVisibleTo(t *testing.T) {
	cases := []struct {
		env, owner string
		want       bool
	}{
		{"", "sso|alice", false},
		{"*", "sso|alice", true},
		{"*", "", false},
		{"*", selfServiceOwner(), false},
		{"sso|alice, sso|bob", "sso|bob", true},
		{"sso|alice,sso|bob", "sso|carol", false},
	}
	for _, c := range cases {
		t.Setenv("VERIFIABLY_SELF_SERVICE_VIEWERS", c.env)
		if got := selfServiceVisibleTo(c.owner); got != c.want {
			t.Errorf("env=%q owner=%q: got %v, want %v", c.env, c.owner, got, c.want)
		}
	}
}

func TestMayManageIssued(t *testing.T) {
	t.Setenv("VERIFIABLY_SELF_SERVICE_VIEWERS", "sso|alice")
	if !mayManageIssued("sso|bob", "sso|bob") {
		t.Error("an operator must always manage their own entries")
	}
	if !mayManageIssued("sso|alice", selfServiceOwner()) {
		t.Error("an allowed operator must manage self-issued entries")
	}
	if mayManageIssued("sso|bob", selfServiceOwner()) {
		t.Error("an operator not in the list must not manage self-issued entries")
	}
	if mayManageIssued("sso|alice", "sso|bob") {
		t.Error("the setting must not open up other operators' entries")
	}
}

func TestWithSelfService(t *testing.T) {
	log, err := issuance.NewLog(filepath.Join(t.TempDir(), "issued.json"))
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for _, c := range []issuance.IssuedCredential{
		{ID: "own-1", OwnerKey: "sso|alice", IssuerDpg: "walt", Std: "sd_jwt_vc", IssuedAt: base},
		{ID: "self-1", OwnerKey: selfServiceOwner(), IssuerDpg: "walt", Std: "sd_jwt_vc", IssuedAt: base.Add(2 * time.Hour)},
		{ID: "self-other-dpg", OwnerKey: selfServiceOwner(), IssuerDpg: "inji", Std: "sd_jwt_vc", IssuedAt: base.Add(3 * time.Hour)},
		{ID: "self-other-std", OwnerKey: selfServiceOwner(), IssuerDpg: "walt", Std: "w3c_vcdm_2", IssuedAt: base.Add(4 * time.Hour)},
		{ID: "bob-1", OwnerKey: "sso|bob", IssuerDpg: "walt", Std: "sd_jwt_vc", IssuedAt: base.Add(time.Hour)},
	} {
		if _, err := log.Append(c); err != nil {
			t.Fatal(err)
		}
	}
	h := &H{IssuanceLog: log}
	filter := issuance.Filter{Std: "sd_jwt_vc", OwnerKey: "sso|alice"}
	own := filterIssuedByDpg(log.List(filter), "walt")

	t.Setenv("VERIFIABLY_SELF_SERVICE_VIEWERS", "")
	if got := selfServiceTestIDs(h.withSelfService("sso|alice", filter, "walt", own)); !selfServiceTestEqual(got, []string{"own-1"}) {
		t.Errorf("setting off: got %v, want only the operator's own entry", got)
	}

	t.Setenv("VERIFIABLY_SELF_SERVICE_VIEWERS", "sso|alice")
	// Same std filter and DPG track apply to the added entries; other
	// operators' entries never appear; result is newest first.
	if got := selfServiceTestIDs(h.withSelfService("sso|alice", filter, "walt", own)); !selfServiceTestEqual(got, []string{"self-1", "own-1"}) {
		t.Errorf("setting on: got %v, want [self-1 own-1]", got)
	}
	if got := selfServiceTestIDs(h.withSelfService("sso|bob", filter, "walt", nil)); len(got) != 0 {
		t.Errorf("operator not in the list: got %v, want nothing added", got)
	}
}

func selfServiceTestIDs(in []issuance.IssuedCredential) []string {
	out := make([]string, 0, len(in))
	for _, c := range in {
		out = append(out, c.ID)
	}
	return out
}

func selfServiceTestEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
