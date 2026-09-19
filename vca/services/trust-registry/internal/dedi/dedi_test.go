// SPDX-License-Identifier: Apache-2.0

package dedi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/entry"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/keys"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/publish"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func input(t *testing.T) publish.Input {
	t.Helper()
	k, err := keys.Generate(jose.EdDSA, t0)
	if err != nil {
		t.Fatal(err)
	}
	return publish.Input{
		Entries: []entry.Entry{
			{DID: "did:web:v.example", Role: entry.RoleVerifier, Status: entry.StatusActive},
			{X509Subject: "CN=CA", DisplayName: "CA", Role: entry.RoleIssuer, Status: entry.StatusRevoked, ValidFrom: t0, ValidUntil: t0.Add(time.Hour)},
			{DID: "did:web:i.example", Role: entry.RoleIssuer, Status: entry.StatusActive, CredentialTypes: []string{"A"}},
		},
		Sequence: 3,
		Now:      t0,
		TTL:      time.Hour,
		BaseURL:  "https://trust.example/",
		Issuer:   publish.Issuer{ID: "did:web:trust.example", Name: "Registry"},
		Signer:   k,
	}
}

func TestPaths(t *testing.T) {
	if FileName("issuers") != "dedi.issuers.json" || DirectoryPath("issuers") != "/dedi/dedi.issuers.json" {
		t.Fatal("names")
	}
	if n, ok := DirectoryNameFromPath("/dedi/dedi.issuers.json"); !ok || n != "issuers" {
		t.Fatal("from path")
	}
	for _, bad := range []string{"/x/dedi.a.json", "/dedi/a.json", "/dedi/dedi.a.txt", "/dedi/dedi..json", "/dedi/dedi.a/b.json"} {
		if _, ok := DirectoryNameFromPath(bad); ok {
			t.Errorf("%s must not parse", bad)
		}
	}
}

func TestRecordRoundTrip(t *testing.T) {
	in := input(t)
	for _, e := range in.Entries {
		back, err := ToEntry(FromEntry(e))
		if err != nil || back.ID() != e.ID() || back.Role != e.Role || back.Status != e.Status || !back.ValidFrom.Equal(e.ValidFrom) || !back.ValidUntil.Equal(e.ValidUntil) {
			t.Fatalf("%s: %v %+v", e.ID(), err, back)
		}
	}
	if _, err := ToEntry(Record{ID: "nope", Role: "issuer", Status: "active"}); err == nil {
		t.Fatal("bad id")
	}
}

func TestPublishAndVerify(t *testing.T) {
	in := input(t)
	var p Publisher
	if p.Method() != publish.MethodDedi {
		t.Fatal("method")
	}
	pub, err := p.Publish(in)
	if err != nil {
		t.Fatal(err)
	}
	if pub.URL != "https://trust.example/.well-known/dedi.index.json" || pub.EntryCount != 3 || pub.KeyID != in.Signer.ID || len(pub.Files) != 4 {
		t.Fatalf("publication %+v", pub)
	}
	var env struct {
		Document Index     `json:"document"`
		Proof    Signature `json:"proof"`
	}
	if serr := json.Unmarshal(pub.Files[IndexPath].Body, &env); serr != nil {
		t.Fatal(serr)
	}
	idx := env.Document
	if idx.SchemaVersion != SchemaVersion || idx.SigningKey.KeyID != in.Signer.ID || idx.SigningKey.Alg != "EdDSA" || idx.JWKSURL != "https://trust.example/.well-known/jwks.json" || idx.URL != pub.URL {
		t.Fatalf("index %+v", idx)
	}
	if len(idx.Directories) != 3 || idx.Directories[0].Name != "issuers" || idx.Directories[0].EntryCount != 2 || idx.Directories[1].EntryCount != 0 || idx.Directories[2].EntryCount != 1 {
		t.Fatalf("directories %+v", idx.Directories)
	}
	if idx.Directories[0].URL != "https://trust.example/dedi/dedi.issuers.json" || idx.Directories[0].File != "dedi.issuers.json" {
		t.Fatalf("row %+v", idx.Directories[0])
	}
	if env.Proof.Type != SignatureType || env.Proof.KeyID != in.Signer.ID || env.Proof.JWS == "" {
		t.Fatalf("proof %+v", env.Proof)
	}
	if !strings.Contains(string(pub.Files["/dedi/dedi.issuers.json"].Body), `"records":[{"id":"did:web:i.example"`) {
		t.Fatal("issuers file order")
	}
	ring, verr := keys.NewRing(in.Signer)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	v, err := p.Verify(pub.Files, ring.JWKS(), t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Entries) != 3 || v.Sequence != 3 || v.KeyID != in.Signer.ID || v.ListURL != pub.URL || v.IssuedAt != t0 || v.ExpiresAt != t0.Add(time.Hour) {
		t.Fatalf("verified %+v", v)
	}
	if v.Entries[0].ID() != "did:web:i.example" || v.Entries[2].Role != entry.RoleVerifier {
		t.Fatalf("entries %+v", v.Entries)
	}
}

func TestVerifyErrors(t *testing.T) {
	in := input(t)
	var p Publisher
	pub, verr := p.Publish(in)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	ring, verr := keys.NewRing(in.Signer)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	set := ring.JWKS()
	clone := func() map[string]publish.File {
		out := map[string]publish.File{}
		for k, v := range pub.Files {
			out[k] = v
		}
		return out
	}
	if _, err := p.Verify(pub.Files, set, t0.Add(2*time.Hour)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatal("expired")
	}
	if _, err := p.Verify(map[string]publish.File{}, set, t0); err == nil {
		t.Fatal("missing index")
	}
	other, verr := keys.Generate(jose.ES256, t0)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	otherRing, verr := keys.NewRing(other)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if _, err := p.Verify(pub.Files, otherRing.JWKS(), t0); err == nil {
		t.Fatal("wrong key")
	}
	files := clone()
	delete(files, "/dedi/dedi.holders.json")
	if _, err := p.Verify(files, set, t0); err == nil || !strings.Contains(err.Error(), "holders is missing") {
		t.Fatal("missing directory")
	}
	files = clone()
	files["/dedi/dedi.holders.json"] = publish.File{Body: append([]byte(nil), files["/dedi/dedi.issuers.json"].Body...)}
	if _, err := p.Verify(files, set, t0); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatal("digest")
	}
	files = clone()
	files[IndexPath] = publish.File{Body: []byte("{")}
	if _, err := p.Verify(files, set, t0); err == nil || !strings.Contains(err.Error(), "envelope") {
		t.Fatal("envelope")
	}
	wrongTyp, verr := ring.Sign("jwt", Index{})
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	files[IndexPath] = publish.File{Body: []byte(`{"proof":{"jws":"` + wrongTyp + `"}}`)}
	if _, err := p.Verify(files, set, t0); err == nil || !strings.Contains(err.Error(), "typ") {
		t.Fatal("typ")
	}
	notObject, verr := ring.Sign(TypeJWS, []int{1})
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	files[IndexPath] = publish.File{Body: []byte(`{"proof":{"jws":"` + notObject + `"}}`)}
	if _, err := p.Verify(files, set, t0); err == nil || !strings.Contains(err.Error(), "document") {
		t.Fatal("document")
	}
	badRecord := DirectoryFile{Records: []Record{{ID: "x", Role: "issuer", Status: "active"}}}
	body, verr := sign(badRecord, in.Signer)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	idx := Index{ExpiresAt: t0.Add(time.Hour), Directories: []Directory{{Name: "issuers", Digest: digest(body)}}}
	idxBody, verr := sign(idx, in.Signer)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	files = map[string]publish.File{IndexPath: {Body: idxBody}, "/dedi/dedi.issuers.json": {Body: body}}
	if _, err := p.Verify(files, set, t0); err == nil || !strings.Contains(err.Error(), "record 0") {
		t.Fatal("bad record")
	}
}

func TestPublishErrors(t *testing.T) {
	in := input(t)
	in.TTL = 0
	if _, err := (Publisher{}).Publish(in); err == nil {
		t.Fatal("ttl")
	}
	in.TTL = time.Hour
	in.Signer = keys.Key{Private: "bad", ID: "k"}
	if _, err := (Publisher{}).Publish(in); err == nil {
		t.Fatal("bad signer")
	}
}
