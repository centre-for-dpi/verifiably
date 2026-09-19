// SPDX-License-Identifier: Apache-2.0

package entry

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func issuer() Entry {
	return Entry{DID: "did:web:issuer.example", DisplayName: "Issuer", Role: RoleIssuer, Status: StatusActive}
}

func TestIDAndValidate(t *testing.T) {
	e := issuer()
	if e.ID() != "did:web:issuer.example" {
		t.Fatalf("id %q", e.ID())
	}
	x := Entry{X509Subject: "CN=CA", Role: RoleIssuer, Status: StatusActive}
	if x.ID() != "x509:CN=CA" || IDFromX509("CN=CA") != x.ID() {
		t.Fatalf("x509 id %q", x.ID())
	}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []Entry{
		{Role: RoleIssuer, Status: StatusActive},
		{DID: "did:web:a", X509Subject: "CN=b", Role: RoleIssuer, Status: StatusActive},
		{DID: "web:a", Role: RoleIssuer, Status: StatusActive},
		{DID: "did:web:a", Role: "admin", Status: StatusActive},
		{DID: "did:web:a", Role: RoleIssuer, Status: "gone"},
		{DID: "did:web:a", Role: RoleIssuer, Status: StatusActive, ValidFrom: t0, ValidUntil: t0.Add(-time.Hour)},
	}
	for i, b := range bad {
		if err := b.Validate(); err == nil {
			t.Errorf("case %d: want error", i)
		}
	}
}

func TestValidAtAndCovers(t *testing.T) {
	e := issuer()
	e.ValidFrom = t0
	e.ValidUntil = t0.Add(time.Hour)
	if e.ValidAt(t0.Add(-time.Second)) || !e.ValidAt(t0) || e.ValidAt(t0.Add(2*time.Hour)) {
		t.Fatal("validity window")
	}
	if !e.Covers("") || !e.Covers("Any") {
		t.Fatal("empty list covers every type")
	}
	e.CredentialTypes = []string{"A"}
	if !e.Covers("A") || e.Covers("B") {
		t.Fatal("typed list")
	}
}

func TestSorted(t *testing.T) {
	in := []Entry{{DID: "did:web:b"}, {DID: "did:web:a"}}
	out := Sorted(in)
	if out[0].DID != "did:web:a" || in[0].DID != "did:web:b" {
		t.Fatal("sorted copy")
	}
}

func TestEvaluate(t *testing.T) {
	active := issuer()
	suspended := Entry{DID: "did:web:s", Role: RoleIssuer, Status: StatusSuspended}
	revoked := Entry{DID: "did:web:r", Role: RoleIssuer, Status: StatusRevoked}
	expired := Entry{DID: "did:web:e", Role: RoleIssuer, Status: StatusActive, ValidUntil: t0.Add(-time.Hour)}
	typed := Entry{DID: "did:web:t", Role: RoleIssuer, Status: StatusActive, CredentialTypes: []string{"A"}}
	verifier := Entry{DID: "did:web:v", Role: RoleVerifier, Status: StatusActive}
	both := Entry{DID: "did:web:v", Role: RoleIssuer, Status: StatusActive}
	all := []Entry{active, suspended, revoked, expired, typed, verifier, both}
	cases := []struct {
		id, ctype string
		role      Role
		want      Outcome
		reason    string
	}{
		{"did:web:issuer.example", "", RoleIssuer, Trusted, ""},
		{"did:web:none", "", RoleIssuer, Unknown, "No enabled list"},
		{"did:web:s", "", RoleIssuer, Untrusted, "suspended"},
		{"did:web:r", "", RoleIssuer, Untrusted, "revoked"},
		{"did:web:e", "", RoleIssuer, Untrusted, "not valid"},
		{"did:web:t", "B", RoleIssuer, Untrusted, "credential type B"},
		{"did:web:t", "A", RoleIssuer, Trusted, ""},
		{"did:web:issuer.example", "", RoleVerifier, Untrusted, "role issuer, not verifier"},
		{"did:web:v", "", RoleIssuer, Trusted, ""},
		{"did:web:v", "", RoleVerifier, Trusted, ""},
	}
	for _, c := range cases {
		r := Evaluate(all, c.id, c.role, c.ctype, t0)
		if r.Outcome != c.want || !strings.Contains(r.Reason, c.reason) {
			t.Errorf("%s/%s: got %s %q, want %s %q", c.id, c.role, r.Outcome, r.Reason, c.want, c.reason)
		}
		if r.Outcome != Unknown && r.Entry == nil {
			t.Errorf("%s: entry missing", c.id)
		}
	}
}

func TestProtoRoundTrip(t *testing.T) {
	e := issuer()
	e.ValidFrom = t0
	e.ValidUntil = t0.Add(time.Hour)
	e.UpdatedAt = t0
	e.CredentialTypes = []string{"A"}
	e.ServiceEndpoint = "https://issuer.example"
	e.StatusListEndpoints = []string{"https://issuer.example/status/1"}
	p := ToProto(e)
	if p.GetIdentifier().GetDid() != e.DID || p.GetUpdatedAt().AsTime() != t0 {
		t.Fatal("to proto")
	}
	back, err := FromProto(p)
	if err != nil {
		t.Fatal(err)
	}
	back.UpdatedAt = t0
	if back.ID() != e.ID() || back.Role != e.Role || back.Status != e.Status || !back.ValidFrom.Equal(e.ValidFrom) || !back.ValidUntil.Equal(e.ValidUntil) || back.CredentialTypes[0] != "A" {
		t.Fatalf("round trip %+v", back)
	}
	x := Entry{X509Subject: "CN=CA", Role: RoleVerifier, Status: StatusRevoked}
	px := ToProto(x)
	if px.GetIdentifier().GetX509Subject() != "CN=CA" || px.Validity != nil || px.UpdatedAt != nil {
		t.Fatal("x509 to proto")
	}
	bx, err := FromProto(px)
	if err != nil || bx.X509Subject != "CN=CA" || bx.Role != RoleVerifier || bx.Status != StatusRevoked {
		t.Fatalf("x509 from proto %v %+v", err, bx)
	}
}

func TestFromProtoErrors(t *testing.T) {
	if _, err := FromProto(nil); err == nil {
		t.Fatal("nil")
	}
	base := func() *trustv1.TrustEntry {
		return &trustv1.TrustEntry{
			Identifier: &trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_Did{Did: "did:web:a"}},
			Role:       commonv1.Role_ROLE_ISSUER,
			Status:     trustv1.Status_STATUS_ACTIVE,
		}
	}
	p := base()
	p.Role = commonv1.Role_ROLE_ADMIN
	if _, err := FromProto(p); err == nil {
		t.Fatal("admin role")
	}
	p = base()
	p.Status = trustv1.Status_STATUS_UNSPECIFIED
	if _, err := FromProto(p); err == nil {
		t.Fatal("status")
	}
	p = base()
	p.Identifier = nil
	if _, err := FromProto(p); err == nil {
		t.Fatal("identifier")
	}
	p = base()
	p.Validity = &commonv1.ValidityWindow{ValidFrom: timestamppb.New(t0), ValidUntil: timestamppb.New(t0.Add(-time.Hour))}
	if _, err := FromProto(p); err == nil {
		t.Fatal("window")
	}
}

func TestEnumConversions(t *testing.T) {
	for _, r := range []Role{RoleIssuer, RoleHolder, RoleVerifier} {
		back, err := RoleFromProto(RoleToProto(r))
		if err != nil || back != r {
			t.Errorf("role %s", r)
		}
	}
	if RoleToProto("x") != commonv1.Role_ROLE_UNSPECIFIED {
		t.Error("unknown role")
	}
	for _, s := range []Status{StatusActive, StatusSuspended, StatusRevoked} {
		back, err := StatusFromProto(StatusToProto(s))
		if err != nil || back != s {
			t.Errorf("status %s", s)
		}
	}
	if StatusToProto("x") != trustv1.Status_STATUS_UNSPECIFIED {
		t.Error("unknown status")
	}
}

func TestIDFromProto(t *testing.T) {
	id, err := IDFromProto(&trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_Did{Did: "did:web:a"}})
	if err != nil || id != "did:web:a" {
		t.Fatal(id, err)
	}
	id, err = IDFromProto(&trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_X509Subject{X509Subject: "CN=a"}})
	if err != nil || id != "x509:CN=a" {
		t.Fatal(id, err)
	}
	bad := []*trustv1.TrustEntry_Identifier{
		nil,
		{Id: &trustv1.TrustEntry_Identifier_Did{Did: "a"}},
		{Id: &trustv1.TrustEntry_Identifier_X509Subject{X509Subject: ""}},
	}
	for i, b := range bad {
		if _, err := IDFromProto(b); err == nil {
			t.Errorf("case %d: want error", i)
		}
	}
}
