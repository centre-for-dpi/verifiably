// SPDX-License-Identifier: Apache-2.0

package etsi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/entry"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/keys"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/publish"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func input(t *testing.T, entries ...entry.Entry) publish.Input {
	t.Helper()
	k, err := keys.Generate(jose.ES256, t0)
	if err != nil {
		t.Fatal(err)
	}
	return publish.Input{
		Entries:  entries,
		Sequence: 7,
		Now:      t0,
		TTL:      time.Hour,
		BaseURL:  "https://trust.example",
		Issuer:   publish.Issuer{ID: "did:web:trust.example", Name: "Registry", Territory: "KE"},
		Signer:   k,
	}
}

func sample() []entry.Entry {
	return []entry.Entry{
		{DID: "did:web:b.example", DisplayName: "B", Role: entry.RoleVerifier, Status: entry.StatusSuspended},
		{X509Subject: "CN=CA", Role: entry.RoleIssuer, Status: entry.StatusActive, ValidFrom: t0, ValidUntil: t0.Add(24 * time.Hour), CredentialTypes: []string{"A"}, ServiceEndpoint: "https://a", StatusListEndpoints: []string{"https://a/s"}},
	}
}

func TestBuildAndConvert(t *testing.T) {
	list := Build(input(t, sample()...))
	si := list.SchemeInformation
	if si.Version != 1 || si.SequenceNumber != 7 || si.Type != ListType || si.ListIssuer.Territory != "KE" || si.NextUpdate != t0.Add(time.Hour) {
		t.Fatalf("scheme %+v", si)
	}
	if len(si.DistributionPoints) != 2 || si.DistributionPoints[0] != "https://trust.example/trust-list/etsi.jws" {
		t.Fatal("distribution points")
	}
	if len(list.Entities) != 2 || list.Entities[0].ServiceDigitalIdentities[0].DID != "did:web:b.example" {
		t.Fatalf("entities %+v", list.Entities)
	}
	x := list.Entities[1]
	if x.StatusURI != StatusGranted || x.ServiceDigitalIdentities[0].X509SubjectName != "CN=CA" || x.StatusStartingTime == nil || x.ValidUntil == nil {
		t.Fatalf("x509 entity %+v", x)
	}
	if list.Entities[0].StatusURI != StatusWithdrawn {
		t.Fatal("suspended maps to withdrawn")
	}
	back, err := ToEntries(list.Entities)
	if err != nil || len(back) != 2 || back[1].X509Subject != "CN=CA" || !back[1].ValidFrom.Equal(t0) || back[0].Status != entry.StatusSuspended {
		t.Fatalf("to entries %v %+v", err, back)
	}
	if _, err := ToEntries([]Entity{{Role: "issuer", Status: "active"}}); err == nil {
		t.Fatal("no identity")
	}
	if _, err := ToEntries([]Entity{{Role: "king", Status: "active", ServiceDigitalIdentities: []DigitalIdentity{{DID: "did:web:a"}}}}); err == nil {
		t.Fatal("bad role")
	}
}

func TestPublishAndVerify(t *testing.T) {
	in := input(t, sample()...)
	var p Publisher
	if p.Method() != publish.MethodEtsi {
		t.Fatal("method")
	}
	pub, err := p.Publish(in)
	if err != nil {
		t.Fatal(err)
	}
	if pub.URL != "https://trust.example/trust-list/etsi.jws" || pub.EntryCount != 2 || pub.KeyID != in.Signer.ID || pub.Sequence != 7 || pub.PublishedAt != t0 {
		t.Fatalf("publication %+v", pub)
	}
	var list List
	if serr := json.Unmarshal(pub.Files[PathJSON].Body, &list); serr != nil || len(list.Entities) != 2 {
		t.Fatal("json file")
	}
	if pub.Files[PathJWS].ContentType != ContentTypeJWS {
		t.Fatal("content type")
	}
	ring, verr := keys.NewRing(in.Signer)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	v, err := p.Verify(pub.Files, ring.JWKS(), t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Entries) != 2 || v.Sequence != 7 || v.KeyID != in.Signer.ID || v.ListURL != pub.URL || v.IssuedAt != t0 || v.ExpiresAt != t0.Add(time.Hour) {
		t.Fatalf("verified %+v", v)
	}
	if _, err := p.Verify(pub.Files, ring.JWKS(), t0.Add(2*time.Hour)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatal("expired")
	}
	other, verr := keys.Generate(jose.EdDSA, t0)
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
	if _, err := p.Verify(map[string]publish.File{}, ring.JWKS(), t0); err == nil {
		t.Fatal("missing file")
	}
	in.TTL = 0
	if _, err := p.Publish(in); err == nil {
		t.Fatal("zero ttl")
	}
	in.TTL = time.Hour
	in.Signer = keys.Key{Private: "bad"}
	if _, err := p.Publish(in); err == nil {
		t.Fatal("bad signer")
	}
}

func TestVerifyJWSErrors(t *testing.T) {
	in := input(t)
	ring, verr := keys.NewRing(in.Signer)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	sign := func(typ string, claims any) string {
		tok, err := ring.Sign(typ, claims)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	cases := map[string]string{
		"typ":     sign("jwt", Claims{ExpiresAt: t0.Add(time.Hour).Unix()}),
		"claims":  sign(TypeJWS, []int{1}),
		"exp":     sign(TypeJWS, Claims{}),
		"entity":  sign(TypeJWS, Claims{ExpiresAt: t0.Add(time.Hour).Unix(), List: List{Entities: []Entity{{Role: "issuer"}}}}),
		"garbage": "a.b",
	}
	for name, tok := range cases {
		_, _, err := VerifyJWS(tok, ring.JWKS(), t0)
		if name == "entity" {
			_, err = Publisher{}.Verify(map[string]publish.File{PathJWS: {Body: []byte(tok)}}, ring.JWKS(), t0)
		}
		if err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func selfSigned(t *testing.T, cn string, notAfter time.Time) string {
	t.Helper()
	priv, verr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn, Organization: []string{"Org"}}, NotBefore: t0, NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

const tslHead = `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" TSLTag="http://uri.etsi.org/19612/TSLTag">
  <SchemeInformation>
    <TSLVersionIdentifier>5</TSLVersionIdentifier>
    <TSLSequenceNumber>42</TSLSequenceNumber>
    <TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</TSLType>
    <SchemeOperatorName><Name xml:lang="de">Betreiber</Name><Name xml:lang="en">Operator</Name></SchemeOperatorName>
    <SchemeTerritory>EU</SchemeTerritory>
    <ListIssueDateTime>2026-01-01T00:00:00Z</ListIssueDateTime>
    <NextUpdate><dateTime>2026-07-01T00:00:00Z</dateTime></NextUpdate>
  </SchemeInformation>
  <TrustServiceProviderList>`

const tslTail = `  </TrustServiceProviderList>
</TrustServiceStatusList>`

func service(name, status, start string, ids ...string) string {
	var b strings.Builder
	b.WriteString(`<TSPService><ServiceInformation><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>`)
	if name != "" {
		b.WriteString(`<ServiceName><Name xml:lang="en">` + name + `</Name></ServiceName>`)
	}
	b.WriteString(`<ServiceDigitalIdentity>`)
	for _, id := range ids {
		b.WriteString(`<DigitalId>` + id + `</DigitalId>`)
	}
	b.WriteString(`</ServiceDigitalIdentity><ServiceStatus>` + status + `</ServiceStatus>`)
	if start != "" {
		b.WriteString(`<StatusStartingTime>` + start + `</StatusStartingTime>`)
	}
	b.WriteString(`</ServiceInformation></TSPService>`)
	return b.String()
}

func provider(name string, services ...string) string {
	return `<TrustServiceProvider><TSPInformation><TSPName><Name xml:lang="en">` + name + `</Name></TSPName></TSPInformation><TSPServices>` + strings.Join(services, "") + `</TSPServices></TrustServiceProvider>`
}

func TestImportTrustedList(t *testing.T) {
	cert := selfSigned(t, "Root CA", t0.Add(365*24*time.Hour))
	doc := tslHead + provider("Provider One",
		service("CA One", StatusGranted, "2016-06-30T22:00:00Z", "<X509Certificate>"+cert+"</X509Certificate>"),
		service("", StatusWithdrawn, "", "<X509SubjectName> CN=Old CA </X509SubjectName>"),
		service("No Identity", StatusGranted, ""),
		service("Bad Time", StatusGranted, "yesterday", "<X509SubjectName>CN=T</X509SubjectName>"),
		service("Bad Base64", StatusGranted, "", "<X509Certificate>!!</X509Certificate>"),
		service("Bad DER", StatusGranted, "", "<X509Certificate>AAAA</X509Certificate>"),
	) + provider("Provider Two",
		service("National", "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel", "", "<X509SubjectName>CN=Nat</X509SubjectName>"),
	) + tslTail
	tl, err := ParseTrustedList([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if tl.SchemeInformation.SequenceNumber != 42 || tl.SchemeInformation.Territory != "EU" || englishName(tl.SchemeInformation.OperatorName) != "Operator" || tl.SchemeInformation.NextUpdate != "2026-07-01T00:00:00Z" {
		t.Fatalf("scheme %+v", tl.SchemeInformation)
	}
	entries, skipped := Import(tl, t0)
	if len(entries) != 3 {
		t.Fatalf("entries %+v", entries)
	}
	first := entries[0]
	if first.X509Subject != "CN=Root CA,O=Org" || first.DisplayName != "CA One" || first.Status != entry.StatusActive || first.Role != entry.RoleIssuer || first.Source != entry.SourceEtsiImport {
		t.Fatalf("first %+v", first)
	}
	if first.ValidFrom != time.Date(2016, 6, 30, 22, 0, 0, 0, time.UTC) || first.ValidUntil != t0.Add(365*24*time.Hour) {
		t.Fatalf("first validity %+v", first)
	}
	if entries[1].X509Subject != "CN=Old CA" || entries[1].DisplayName != "Provider One" || entries[1].Status != entry.StatusRevoked || !entries[1].ValidUntil.IsZero() {
		t.Fatalf("second %+v", entries[1])
	}
	if entries[2].Status != entry.StatusActive {
		t.Fatal("national status")
	}
	if len(skipped) != 4 {
		t.Fatalf("skipped %+v", skipped)
	}
	wantReasons := []string{"no x509 digital identity", "status starting time", "base64", "x509 certificate:"}
	for i, s := range skipped {
		if !strings.Contains(s.String(), wantReasons[i]) || !strings.HasPrefix(s.String(), "Provider One / ") {
			t.Errorf("skipped %d: %s", i, s)
		}
	}
}

func TestParseTrustedListErrors(t *testing.T) {
	if _, err := ParseTrustedList([]byte("<x")); err == nil {
		t.Fatal("bad xml")
	}
	if _, err := ParseTrustedList([]byte(`<TrustServiceStatusList xmlns="urn:other"/>`)); err == nil {
		t.Fatal("namespace")
	}
	tl, err := ParseTrustedList([]byte(`<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"/>`))
	if err != nil {
		t.Fatal(err)
	}
	entries, skipped := Import(tl, t0)
	if len(entries) != 0 || len(skipped) != 0 {
		t.Fatal("empty list")
	}
	if englishName(nil) != "" || englishName([]MultiLangName{{Lang: "fr", Value: " A "}}) != "A" {
		t.Fatal("english name")
	}
}
