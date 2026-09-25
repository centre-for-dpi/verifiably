// SPDX-License-Identifier: Apache-2.0

package federation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/fetchguard"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	sharedstore "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/dedi"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/entry"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/etsi"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/keys"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/publish"
)

// now sits inside the validity of the XML fixture certificates.
var now = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

// upstream is an external registry: its lists, its JWKS, and a TS 119
// 612 XML list, served over HTTP.
type upstream struct {
	srv  *httptest.Server
	mu   sync.Mutex
	docs map[string][]byte
	key  keys.Key
	cert string // a PEM certificate over key
}

func (u *upstream) set(path string, body []byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.docs[path] = body
}

func (u *upstream) get(path string) []byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.docs[path]
}

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	u := &upstream{docs: map[string][]byte{}}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := u.get(r.URL.Path)
		if body == nil {
			http.NotFound(w, r)
			return
		}
		if _, err := w.Write(body); err != nil {
			t.Errorf("write: %v", err)
		}
	}))
	t.Cleanup(u.srv.Close)
	k, err := keys.Generate(jose.ES256, now)
	if err != nil {
		t.Fatal(err)
	}
	u.key = k
	ring, err := keys.NewRing(k)
	if err != nil {
		t.Fatal(err)
	}
	in := publish.Input{
		Entries: []entry.Entry{
			{DID: "did:web:registrar.go.ke", DisplayName: "National Registration Bureau", Role: entry.RoleIssuer, Status: entry.StatusActive},
			{DID: "did:web:old.go.ke", DisplayName: "Old Registrar", Role: entry.RoleIssuer, Status: entry.StatusRevoked},
		},
		Sequence: 3, Now: now, TTL: 24 * time.Hour, BaseURL: u.srv.URL,
		Issuer: publish.Issuer{ID: "did:web:trust.go.ke", Name: "Kenya trust registry", Territory: "KE"}, Signer: k,
	}
	for _, p := range []publish.Publisher{etsi.Publisher{}, dedi.Publisher{}} {
		pub, err := p.Publish(in)
		if err != nil {
			t.Fatal(err)
		}
		for path, f := range pub.Files {
			u.set(path, f.Body)
		}
	}
	u.set("/.well-known/jwks.json", ring.JWKSJSON())
	u.set("/tsl.xml", fixture(t, "tsl-rsa.xml"))
	u.cert = selfSigned(t, k)
	return u
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "xmldsig", "testdata", name)) // #nosec G304 -- a fixed test path
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// selfSigned returns a PEM certificate over the signing key of the lists.
func selfSigned(t *testing.T, k keys.Key) string {
	t.Helper()
	priv, ok := k.Private.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("the key is not ECDSA")
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Kenya trust list signer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// devFetcher reaches the loopback test servers over plain http.
func devFetcher() *fetchguard.Fetcher {
	return fetchguard.New(fetchguard.Options{Guard: fetchguard.Guard{AllowPrivateNetwork: true, AllowPlainHTTP: true}})
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newFederation(t *testing.T, backend sharedstore.Document, fetcher *fetchguard.Fetcher) (*Federation, *clock) {
	t.Helper()
	if backend == nil {
		backend = sharedstore.MemoryDoc()
	}
	c := &clock{t: now}
	f, err := New(Options{Backend: backend, Fetcher: fetcher, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	return f, c
}

// registries returns one registry per method and anchor kind.
func registries(u *upstream) map[string]Registry {
	return map[string]Registry{
		"lote jwks": {Name: "Kenya LoTE", Method: MethodEtsiLoteJSON, URL: u.srv.URL + etsi.PathJWS, JWKSURL: u.srv.URL + "/.well-known/jwks.json"},
		"lote x509": {Name: "Kenya LoTE pinned", Method: MethodEtsiLoteJSON, URL: u.srv.URL + etsi.PathJWS, X509PEM: u.cert},
		"dedi jwks": {Name: "Kenya DeDi", Method: MethodDedi, URL: u.srv.URL, JWKSURL: u.srv.URL + "/.well-known/jwks.json"},
		"dedi x509": {Name: "Kenya DeDi pinned", Method: MethodDedi, URL: u.srv.URL + dedi.IndexPath, X509PEM: u.cert},
		"tsl x509":  {Name: "Kenya TSL", Method: MethodEtsiTslXML, URL: u.srv.URL + "/tsl.xml", X509PEM: ""},
	}
}

// TestSyncVerifiesSignature reads each fixture list through its anchor.
// A tampered copy fails, and the registry keeps its last good copy.
func TestSyncVerifiesSignature(t *testing.T) {
	ctx := context.Background()
	anchor := string(fixture(t, "anchor.pem"))
	for name, r := range registries(newUpstream(t)) {
		t.Run(name, func(t *testing.T) {
			u := newUpstream(t)
			r = registries(u)[name]
			if r.Method == MethodEtsiTslXML {
				r.X509PEM = anchor
			}
			f, _ := newFederation(t, nil, devFetcher())
			got, err := f.Add(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			if got.LastError != "" || got.EntryCount == 0 || got.LastSync.IsZero() || got.SignedBy == "" || got.ID == "" {
				t.Fatalf("first sync = %+v", got)
			}
			count := got.EntryCount
			tamper(t, u, r.Method)
			got, err = f.Sync(ctx, got.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.LastError == "" {
				t.Fatal("a tampered list passed")
			}
			if got.EntryCount != count || !got.LastRead.After(got.LastSync) && !got.LastRead.Equal(got.LastSync) {
				t.Fatalf("the failed sync lost the last good copy: %+v", got)
			}
			if _, ok := f.Owner(ownerID(r.Method)); !ok {
				t.Fatal("the last good copy is gone")
			}
		})
	}
}

// ownerID is an entity that the fixture list of a method names.
func ownerID(m Method) string {
	if m == MethodEtsiTslXML {
		return entry.IDFromX509("CN=Registrar, O=National Registration Bureau, C=KE")
	}
	return "did:web:registrar.go.ke"
}

// tamper changes one served document of a method after its signature.
func tamper(t *testing.T, u *upstream, m Method) {
	t.Helper()
	switch m {
	case MethodEtsiLoteJSON:
		tok := string(u.get(etsi.PathJWS))
		parts := strings.Split(tok, ".")
		payload, err := jose.PeekPayload(tok)
		if err != nil || payload == nil {
			t.Fatalf("payload: %v", err)
		}
		// Swap one payload character: the JWS no longer verifies.
		b := []byte(parts[1])
		b[10] ^= 1
		parts[1] = string(b)
		u.set(etsi.PathJWS, []byte(strings.Join(parts, ".")))
	case MethodDedi:
		path := dedi.DirectoryPath("issuers")
		u.set(path, bytes.Replace(u.get(path), []byte("revoked"), []byte("active"), 1))
	case MethodEtsiTslXML:
		u.set("/tsl.xml", bytes.Replace(u.get("/tsl.xml"), []byte("Svcstatus/withdrawn"), []byte("Svcstatus/granted"), 1))
	}
}

// TestLookupFindsExternalEntryWithProvenance answers from the cached
// copy and names the registry, the list, the signer and the check time.
func TestLookupFindsExternalEntryWithProvenance(t *testing.T) {
	u := newUpstream(t)
	f, c := newFederation(t, nil, devFetcher())
	r, err := f.Add(context.Background(), registries(u)["lote jwks"])
	if err != nil {
		t.Fatal(err)
	}
	res, ok := f.Lookup("did:web:registrar.go.ke", entry.RoleIssuer, "", now)
	if !ok || res.Outcome != entry.Trusted {
		t.Fatalf("lookup = %+v, %v", res, ok)
	}
	if res.Registry.ID != r.ID || res.Registry.Name != "Kenya LoTE" || res.ListURL != u.srv.URL+etsi.PathJWS ||
		res.SignedBy != u.key.ID || !res.CheckedAt.Equal(now) || res.Method != MethodEtsiLoteJSON {
		t.Fatalf("provenance = %+v", res)
	}
	if res.Entry.Source != "registry:"+r.ID {
		t.Fatalf("source = %q", res.Entry.Source)
	}
	revoked, ok := f.Lookup("did:web:old.go.ke", entry.RoleIssuer, "", now)
	if !ok || revoked.Outcome != entry.Untrusted {
		t.Fatalf("revoked = %+v, %v", revoked, ok)
	}
	if _, ok := f.Lookup("did:web:nobody.example", entry.RoleIssuer, "", now); ok {
		t.Fatal("an unknown entity was found")
	}
	// An expired copy answers nothing: the lookup falls back to the local lists.
	c.t = now.Add(48 * time.Hour)
	if _, ok := f.Lookup("did:web:registrar.go.ke", entry.RoleIssuer, "", c.t); ok {
		t.Fatal("an expired copy still answers")
	}
}

// TestSyncRejectsPrivateAddress keeps the fetch guard on: a registry on
// a loopback address fails, and the reason reaches last_error.
func TestSyncRejectsPrivateAddress(t *testing.T) {
	u := newUpstream(t)
	guarded := fetchguard.New(fetchguard.Options{Guard: fetchguard.Guard{AllowPlainHTTP: true}})
	f, _ := newFederation(t, nil, guarded)
	r, err := f.Add(context.Background(), registries(u)["lote jwks"])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.LastError, "not a public address") || r.EntryCount != 0 || !r.LastSync.IsZero() {
		t.Fatalf("registry = %+v", r)
	}
	if _, ok := f.Lookup("did:web:registrar.go.ke", entry.RoleIssuer, "", now); ok {
		t.Fatal("a refused registry answers")
	}
}

// TestExternalEntriesAreReadOnly names the registry that owns an entity,
// so the service can refuse a local edit of it.
func TestExternalEntriesAreReadOnly(t *testing.T) {
	u := newUpstream(t)
	f, _ := newFederation(t, nil, devFetcher())
	r, err := f.Add(context.Background(), registries(u)["dedi jwks"])
	if err != nil {
		t.Fatal(err)
	}
	owner, ok := f.Owner("did:web:registrar.go.ke")
	if !ok || owner.ID != r.ID {
		t.Fatalf("owner = %+v, %v", owner, ok)
	}
	if werr := f.CheckWritable("did:web:registrar.go.ke"); !errors.Is(werr, ErrReadOnly) || !strings.Contains(werr.Error(), "Kenya DeDi") {
		t.Fatalf("CheckWritable = %v", werr)
	}
	if werr := f.CheckWritable("did:web:local.example"); werr != nil {
		t.Fatalf("a local entity is not writable: %v", werr)
	}
	if _, ok := f.Owner("did:web:local.example"); ok {
		t.Fatal("a local entity has an owner")
	}
	found, err := f.Remove(r.ID)
	if err != nil || !found {
		t.Fatalf("Remove = %v, %v", found, err)
	}
	if _, ok := f.Owner("did:web:registrar.go.ke"); ok {
		t.Fatal("a removed registry still owns its entities")
	}
	if found, err := f.Remove(r.ID); err != nil || found {
		t.Fatalf("a second Remove = %v, %v", found, err)
	}
}

func TestAddValidates(t *testing.T) {
	u := newUpstream(t)
	f, _ := newFederation(t, nil, devFetcher())
	good := registries(u)["lote jwks"]
	cases := map[string]func(r *Registry){
		"no name":     func(r *Registry) { r.Name = " " },
		"no url":      func(r *Registry) { r.URL = "" },
		"bad method":  func(r *Registry) { r.Method = "ldap" },
		"no anchor":   func(r *Registry) { r.JWKSURL = "" },
		"two anchors": func(r *Registry) { r.X509PEM = u.cert },
		"bad pem":     func(r *Registry) { r.JWKSURL, r.X509PEM = "", "not a certificate" },
		"bad der": func(r *Registry) {
			r.JWKSURL, r.X509PEM = "", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
		},
		"short refresh": func(r *Registry) { r.Refresh = time.Minute },
		"xml with jwks": func(r *Registry) { r.Method = MethodEtsiTslXML },
		"bad jwks url":  func(r *Registry) { r.JWKSURL = "ftp://keys.example" },
	}
	for name, change := range cases {
		r := good
		change(&r)
		if _, err := f.Add(context.Background(), r); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	if len(f.List()) != 0 {
		t.Fatal("an invalid registry was stored")
	}
	r, err := f.Add(context.Background(), good)
	if err != nil || r.Refresh != DefaultRefresh {
		t.Fatalf("default refresh = %v, %v", r.Refresh, err)
	}
	if _, err := f.Sync(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Sync of an unknown id = %v", err)
	}
	if _, ok := f.Get("missing"); ok {
		t.Fatal("Get found an unknown id")
	}
}

// TestSnapshotsSurviveARestart reads the registries and their cached
// copies back from the store, so a lookup works offline.
func TestSnapshotsSurviveARestart(t *testing.T) {
	u := newUpstream(t)
	backend := sharedstore.MemoryDoc()
	f, _ := newFederation(t, backend, devFetcher())
	if _, err := f.Add(context.Background(), registries(u)["dedi jwks"]); err != nil {
		t.Fatal(err)
	}
	u.srv.Close()
	again, _ := newFederation(t, backend, devFetcher())
	if len(again.List()) != 1 {
		t.Fatalf("registries after restart = %d", len(again.List()))
	}
	if res, ok := again.Lookup("did:web:registrar.go.ke", entry.RoleIssuer, "", now); !ok || res.Outcome != entry.Trusted {
		t.Fatalf("offline lookup = %+v, %v", res, ok)
	}
	broken := sharedstore.MemoryDoc()
	if err := broken.Save([]byte("{")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{Backend: broken, Fetcher: devFetcher()}); err == nil {
		t.Fatal("a broken store loaded")
	}
}

// TestSyncDueReadsOnlyDueRegistries follows the refresh interval.
func TestSyncDueReadsOnlyDueRegistries(t *testing.T) {
	u := newUpstream(t)
	f, c := newFederation(t, nil, devFetcher())
	r := registries(u)["lote jwks"]
	r.Refresh = time.Hour
	added, err := f.Add(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	c.t = now.Add(30 * time.Minute)
	if n := f.SyncDue(context.Background()); n != 0 {
		t.Fatalf("synced %d before the interval", n)
	}
	c.t = now.Add(61 * time.Minute)
	if n := f.SyncDue(context.Background()); n != 1 {
		t.Fatalf("synced %d after the interval", n)
	}
	got, _ := f.Get(added.ID)
	if !got.LastRead.Equal(c.t) {
		t.Fatalf("last read = %v", got.LastRead)
	}
}

// TestDediDirectoryOnAnotherHostIsRefused keeps the directory files on
// the host of the manifest.
func TestDediDirectoryOnAnotherHostIsRefused(t *testing.T) {
	u := newUpstream(t)
	index := u.get(dedi.IndexPath)
	u.set(dedi.IndexPath, bytes.ReplaceAll(index, []byte(u.srv.URL), []byte("http://elsewhere.example")))
	f, _ := newFederation(t, nil, devFetcher())
	r, err := f.Add(context.Background(), registries(u)["dedi jwks"])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.LastError, "host") {
		t.Fatalf("last error = %q", r.LastError)
	}
}

// TestSyncReportsFetchFaults names a missing list and a missing JWKS.
func TestSyncReportsFetchFaults(t *testing.T) {
	u := newUpstream(t)
	f, _ := newFederation(t, nil, devFetcher())
	for name, r := range map[string]Registry{
		"no list":      {Name: "Missing list", Method: MethodEtsiLoteJSON, URL: u.srv.URL + "/missing.jws", JWKSURL: u.srv.URL + "/.well-known/jwks.json"},
		"no jwks":      {Name: "Missing keys", Method: MethodEtsiLoteJSON, URL: u.srv.URL + etsi.PathJWS, JWKSURL: u.srv.URL + "/missing.json"},
		"bad jwks":     {Name: "Bad keys", Method: MethodDedi, URL: u.srv.URL, JWKSURL: u.srv.URL + etsi.PathJWS},
		"no manifest":  {Name: "No manifest", Method: MethodDedi, URL: u.srv.URL + "/missing/", JWKSURL: u.srv.URL + "/.well-known/jwks.json"},
		"bad xml":      {Name: "Bad XML", Method: MethodEtsiTslXML, URL: u.srv.URL + etsi.PathJWS, X509PEM: string(fixture(t, "anchor.pem"))},
		"other anchor": {Name: "Other anchor", Method: MethodEtsiTslXML, URL: u.srv.URL + "/tsl.xml", X509PEM: string(fixture(t, "other.pem"))},
		"wrong pin":    {Name: "Wrong pin", Method: MethodEtsiLoteJSON, URL: u.srv.URL + etsi.PathJWS, X509PEM: string(fixture(t, "other.pem"))},
	} {
		got, err := f.Add(context.Background(), r)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.LastError == "" || got.EntryCount != 0 {
			t.Errorf("%s: registry = %+v", name, got)
		}
	}
}

// failing is a store whose Save fails from the nth call.
type failing struct {
	sharedstore.Document
	saves, failAt int
}

func (f *failing) Save(data []byte) error {
	f.saves++
	if f.saves >= f.failAt {
		return errors.New("disk full")
	}
	return f.Document.Save(data)
}

func TestStoreFaultsAndDefaults(t *testing.T) {
	u := newUpstream(t)
	f, err := New(Options{})
	if err != nil || len(f.List()) != 0 {
		t.Fatalf("New with defaults = %v", err)
	}
	empty := sharedstore.MemoryDoc()
	if serr := empty.Save([]byte(`{}`)); serr != nil {
		t.Fatal(serr)
	}
	if e, nerr := New(Options{Backend: empty}); nerr != nil || e.CheckWritable("did:web:a") != nil {
		t.Fatalf("New over an empty document = %v", nerr)
	}
	for _, at := range []int{1, 2} {
		backend := &failing{Document: sharedstore.MemoryDoc(), failAt: at}
		broken, _ := newFederation(t, backend, devFetcher())
		if _, aerr := broken.Add(context.Background(), registries(u)["lote jwks"]); aerr == nil {
			t.Errorf("a store fault at save %d passed", at)
		}
	}
	backend := &failing{Document: sharedstore.MemoryDoc(), failAt: 3}
	f, _ = newFederation(t, backend, devFetcher())
	r, err := f.Add(context.Background(), registries(u)["lote jwks"])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Remove(r.ID); err == nil {
		t.Fatal("a store fault on remove passed")
	}
	if n := f.SyncDue(context.Background()); n != 0 {
		t.Fatalf("SyncDue with a broken store counted %d", n)
	}
}

func TestListOrdersByNameThenID(t *testing.T) {
	u := newUpstream(t)
	f, _ := newFederation(t, nil, devFetcher())
	for _, name := range []string{"B", "A", "B"} {
		r := registries(u)["lote jwks"]
		r.Name = name
		if _, err := f.Add(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
	list := f.List()
	if list[0].Name != "A" || list[1].Name != "B" || list[1].ID > list[2].ID {
		t.Fatalf("order = %+v", list)
	}
}

func TestExpiredAnchorsAndListsFail(t *testing.T) {
	u := newUpstream(t)
	f, c := newFederation(t, nil, devFetcher())
	c.t = now.Add(2 * 365 * 24 * time.Hour)
	for name, r := range map[string]Registry{
		"lote pin": registries(u)["lote x509"],
		"dedi pin": registries(u)["dedi x509"],
	} {
		got, err := f.Add(context.Background(), r)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(got.LastError, "not valid now") {
			t.Errorf("%s: last error = %q", name, got.LastError)
		}
	}
	c.t = time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	tsl := registries(u)["tsl x509"]
	tsl.X509PEM = string(fixture(t, "anchor.pem"))
	got, err := f.Add(context.Background(), tsl)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.LastError, "expired") {
		t.Fatalf("an expired TSL = %q", got.LastError)
	}
	u.set("/tsl.xml", bytes.Replace(fixture(t, "tsl-rsa.xml"), []byte("<tsl:dateTime>2027-03-01T00:00:00Z"), []byte("<tsl:dateTime>soon"), 1))
	c.t = now
	if got, err = f.Sync(context.Background(), got.ID); err != nil || got.LastError == "" {
		t.Fatal("a TSL with a changed next update passed")
	}
}

func TestDediFaults(t *testing.T) {
	u := newUpstream(t)
	f, _ := newFederation(t, nil, devFetcher())
	good := u.get(dedi.IndexPath)
	u.set(dedi.IndexPath, []byte("not json"))
	r, err := f.Add(context.Background(), registries(u)["dedi jwks"])
	if err != nil || !strings.Contains(r.LastError, "manifest") {
		t.Fatalf("a broken manifest = %+v, %v", r, err)
	}
	u.set(dedi.IndexPath, good)
	u.set(dedi.DirectoryPath("issuers"), nil)
	if r, err = f.Sync(context.Background(), r.ID); err != nil || r.LastError == "" {
		t.Fatal("a missing directory passed")
	}
	bad := registries(u)["dedi jwks"]
	bad.URL = "http://[::1"
	if r, err := f.Add(context.Background(), bad); err != nil || r.LastError == "" {
		t.Fatalf("a bad manifest URL = %+v, %v", r, err)
	}
}
