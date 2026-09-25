// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/waltid"
	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// identityService starts the fake and a service that keeps its identity
// in path. key and did pin the identity as the configuration does.
func identityService(t *testing.T, path, key, did string) (*service.Service, *fake.Server) {
	t.Helper()
	f := fake.New(testdata)
	t.Cleanup(f.Close)
	svc, err := service.New(service.Options{
		Client: waltid.New(waltid.Options{
			Issuer:    dpgclient.New(dpgclient.Options{BaseURL: f.URL(), HTTP: f.Client(), Retries: -1, Sleep: func(time.Duration) {}}),
			IssuerKey: key, IssuerDid: did,
		}),
		Store: store.Memory(), DpgVersion: "0.18.2", IdentityFile: path,
		Now: func() time.Time { return time.Date(2026, 9, 25, 9, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, f
}

// onboardBody is the part of the onboarding request the tests check.
type onboardBody struct {
	Key struct {
		Backend string `json:"backend"`
		KeyType string `json:"keyType"`
	} `json:"key"`
	Did struct {
		Method string `json:"method"`
		Config struct {
			Domain string `json:"domain"`
			Path   string `json:"path"`
		} `json:"config"`
	} `json:"did"`
}

func provision(t *testing.T, svc *service.Service, req *backendv1.ProvisionIssuerIdentityRequest) (*backendv1.IssuerIdentity, error) {
	t.Helper()
	res, err := svc.ProvisionIssuerIdentity(context.Background(), connect.NewRequest(req))
	if err != nil {
		return nil, err
	}
	return res.Msg.GetIdentity(), nil
}

func TestProvisionIdentityDidWeb(t *testing.T) {
	path := filepath.Join(t.TempDir(), "issuer.json")
	svc, f := identityService(t, path, "", "")
	id, err := provision(t, svc, &backendv1.ProvisionIssuerIdentityRequest{
		Method: "did:web", KeyType: "secp256r1", Domain: "issuer-one.labs.example",
		DisplayName: "Ministry of Agriculture", LegalIdentifier: "KE-GOV-017",
	})
	if err != nil {
		t.Fatal(err)
	}
	var body onboardBody
	if rerr := f.RequestJSON("/onboard/issuer", &body); rerr != nil {
		t.Fatal(rerr)
	}
	if body.Key.Backend != "jwk" || body.Key.KeyType != "secp256r1" || body.Did.Method != "web" ||
		body.Did.Config.Domain != "issuer-one.labs.example" || body.Did.Config.Path != "" {
		t.Fatalf("onboard body = %+v", body)
	}
	if len(id.GetIdentifiers()) != 1 || id.GetIdentifiers()[0] != "did:web:issuer-one.labs.example" {
		t.Fatalf("identifiers = %v", id.GetIdentifiers())
	}
	if id.GetKey().GetType() != "secp256r1" || id.GetKey().GetBackend() != "jwk" {
		t.Fatalf("key = %+v", id.GetKey())
	}
	if id.GetMetadata().GetDisplayName() != "Ministry of Agriculture" || id.GetMetadata().GetLegalIdentifier() != "KE-GOV-017" {
		t.Fatalf("metadata = %+v", id.GetMetadata())
	}
	// The DID document carries the public key only.
	var doc struct {
		ID                 string `json:"id"`
		VerificationMethod []struct {
			ID           string         `json:"id"`
			PublicKeyJWK map[string]any `json:"publicKeyJwk"`
		} `json:"verificationMethod"`
		AssertionMethod []string `json:"assertionMethod"`
	}
	if jerr := json.Unmarshal([]byte(id.GetDidDocument()), &doc); jerr != nil {
		t.Fatalf("did document %q: %v", id.GetDidDocument(), jerr)
	}
	if doc.ID != "did:web:issuer-one.labs.example" || len(doc.VerificationMethod) != 1 || len(doc.AssertionMethod) != 1 {
		t.Fatalf("did document = %+v", doc)
	}
	if _, private := doc.VerificationMethod[0].PublicKeyJWK["d"]; private || doc.VerificationMethod[0].PublicKeyJWK["crv"] != "P-256" {
		t.Fatalf("verification method key = %v", doc.VerificationMethod[0].PublicKeyJWK)
	}
	if !strings.HasPrefix(doc.VerificationMethod[0].ID, "did:web:issuer-one.labs.example#") {
		t.Fatalf("verification method id = %q", doc.VerificationMethod[0].ID)
	}
	// The key stays in the state file of the adapter, readable by the
	// owner only (ADR-046 decision 4).
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode %v", info.Mode().Perm())
	}
	// did:web needs the host.
	if _, err := provision(t, svc, &backendv1.ProvisionIssuerIdentityRequest{Method: "did:web", KeyType: "Ed25519"}); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("did:web without a domain: %v", err)
	}
}

func TestProvisionIdentityDidKeyEd25519(t *testing.T) {
	svc, f := identityService(t, filepath.Join(t.TempDir(), "issuer.json"), "", "")
	id, err := provision(t, svc, &backendv1.ProvisionIssuerIdentityRequest{Method: "did:key", KeyType: "Ed25519"})
	if err != nil {
		t.Fatal(err)
	}
	var body onboardBody
	if err := f.RequestJSON("/onboard/issuer", &body); err != nil {
		t.Fatal(err)
	}
	if body.Key.KeyType != "Ed25519" || body.Did.Method != "key" || body.Did.Config.Domain != "" {
		t.Fatalf("onboard body = %+v", body)
	}
	if got := id.GetIdentifiers(); len(got) != 1 || !strings.HasPrefix(got[0], "did:key:z6Mk") {
		t.Fatalf("identifiers = %v", got)
	}
	if !strings.Contains(id.GetDidDocument(), `"crv":"Ed25519"`) {
		t.Fatalf("did document = %s", id.GetDidDocument())
	}
	// An offer after the change signs with the new DID.
	if _, err := svc.RegisterCredentialConfiguration(context.Background(), connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{
		Configuration: sdJwtConfiguration(),
	})); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{Spec: sdJwtSpec()})); err != nil {
		t.Fatal(err)
	}
	var issued struct {
		IssuerDid string `json:"issuerDid"`
	}
	if err := f.RequestJSON("/openid4vc/sdjwt/issue", &issued); err != nil {
		t.Fatal(err)
	}
	if issued.IssuerDid != id.GetIdentifiers()[0] {
		t.Fatalf("the offer signs with %q", issued.IssuerDid)
	}
}

func TestProvisionRejectsWhatTheStackLacks(t *testing.T) {
	svc, _ := identityService(t, filepath.Join(t.TempDir(), "issuer.json"), "", "")
	for _, req := range []*backendv1.ProvisionIssuerIdentityRequest{
		{Method: "did:ion", KeyType: "Ed25519"},
		{Method: "did:key", KeyType: "P-521"},
		{Method: "did:key", KeyType: "Ed25519", KeyBackend: "vault"},
		// cheqd signs with Ed25519 only.
		{Method: "did:cheqd", KeyType: "secp256k1"},
		// No external key store is configured.
		{Method: "did:key", KeyType: "Ed25519", KeyBackend: "tse"},
	} {
		if _, err := provision(t, svc, req); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%+v: %v", req, err)
		}
	}
}

func TestGetIssuerIdentityReadsState(t *testing.T) {
	// The file of "vca dpg bootstrap waltid" has the onboarding answer.
	path := filepath.Join(t.TempDir(), "waltid-issuer.json")
	raw, err := os.ReadFile(filepath.Join(testdata, "onboard-issuer.json"))
	if err != nil {
		t.Fatal(err)
	}
	if werr := os.WriteFile(path, raw, 0o600); werr != nil {
		t.Fatal(werr)
	}
	svc, _ := identityService(t, path, "", "")
	res, err := svc.GetIssuerIdentity(context.Background(), connect.NewRequest(&backendv1.GetIssuerIdentityRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	id := res.Msg.GetIdentity()
	if len(id.GetIdentifiers()) != 1 || id.GetIdentifiers()[0] != "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169" {
		t.Fatalf("identity = %+v", id)
	}
	if id.GetKey().GetType() != "secp256r1" || id.GetKey().GetBackend() != "jwk" {
		t.Fatalf("key = %+v", id.GetKey())
	}
	// A service without a file and without a key has no identity.
	bare, _ := identityService(t, filepath.Join(t.TempDir(), "none.json"), "", "")
	res, err = bare.GetIssuerIdentity(context.Background(), connect.NewRequest(&backendv1.GetIssuerIdentityRequest{}))
	if err != nil || res.Msg.GetIdentity() != nil {
		t.Fatalf("bare identity = %v %v", res, err)
	}
	// A broken file stops the service at start.
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.New(service.Options{Client: waltid.New(waltid.Options{}), Store: store.Memory(), IdentityFile: path}); err == nil {
		t.Fatal("New accepted a broken identity file")
	}
}

func TestIdentityPinnedByConfiguration(t *testing.T) {
	key := `{"type":"jwk","jwk":{"kty":"OKP","crv":"Ed25519","x":"dVxMuSVsp83ErP3Gz-7ahJAX5bn5UU6ZGRvWfgsNQnY"}}`
	did := "did:key:z6MknMPNnbfMgsLj4nSUib4BjiPuvbZ4o7SRwQGcDU1nT9js"
	svc, _ := identityService(t, filepath.Join(t.TempDir(), "issuer.json"), key, did)
	res, err := svc.GetIssuerIdentity(context.Background(), connect.NewRequest(&backendv1.GetIssuerIdentityRequest{}))
	if err != nil || res.Msg.GetIdentity().GetIdentifiers()[0] != did {
		t.Fatalf("pinned identity = %v %v", res, err)
	}
	if _, err := provision(t, svc, &backendv1.ProvisionIssuerIdentityRequest{Method: "did:key", KeyType: "Ed25519"}); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("provision over a pinned key: %v", err)
	}
}

func importIdentity(svc *service.Service, req *backendv1.ImportIssuerIdentityRequest) (*backendv1.IssuerIdentity, error) {
	res, err := svc.ImportIssuerIdentity(context.Background(), connect.NewRequest(req))
	if err != nil {
		return nil, err
	}
	return res.Msg.GetIdentity(), nil
}

func TestImportDidWithKeyReference(t *testing.T) {
	svc, _ := identityService(t, filepath.Join(t.TempDir(), "issuer.json"), "", "")
	ref := `{"type":"jwk","jwk":{"kty":"OKP","crv":"Ed25519","x":"dVxMuSVsp83ErP3Gz-7ahJAX5bn5UU6ZGRvWfgsNQnY","d":"AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dw"}}`
	did := "did:key:z6MknMPNnbfMgsLj4nSUib4BjiPuvbZ4o7SRwQGcDU1nT9js"
	id, err := importIdentity(svc, &backendv1.ImportIssuerIdentityRequest{
		Subject: &backendv1.ImportIssuerIdentityRequest_Did{Did: did}, KeyReference: ref, DisplayName: "Ministry of Health",
	})
	if err != nil {
		t.Fatal(err)
	}
	if id.GetIdentifiers()[0] != did || id.GetKey().GetType() != "Ed25519" || id.GetMetadata().GetDisplayName() != "Ministry of Health" {
		t.Fatalf("identity = %+v", id)
	}
	// A key of an external key store names no key type.
	tse := `{"type":"tse","server":"http://vault:8200/v1/transit","accessKey":"s.token","id":"issuer-key"}`
	id, err = importIdentity(svc, &backendv1.ImportIssuerIdentityRequest{
		Subject: &backendv1.ImportIssuerIdentityRequest_Did{Did: "did:web:issuer-one.labs.example"}, KeyReference: tse,
	})
	if err != nil || id.GetKey().GetBackend() != "tse" || id.GetDidDocument() != "" {
		t.Fatalf("tse identity = %+v %v", id, err)
	}
	for name, req := range map[string]*backendv1.ImportIssuerIdentityRequest{
		"no subject":    {KeyReference: ref},
		"no key":        {Subject: &backendv1.ImportIssuerIdentityRequest_Did{Did: did}},
		"key not JSON":  {Subject: &backendv1.ImportIssuerIdentityRequest_Did{Did: did}, KeyReference: "vault:issuer"},
		"key no type":   {Subject: &backendv1.ImportIssuerIdentityRequest_Did{Did: did}, KeyReference: `{"id":"x"}`},
		"not a DID":     {Subject: &backendv1.ImportIssuerIdentityRequest_Did{Did: "issuer.example"}, KeyReference: ref},
		"other key":     {Subject: &backendv1.ImportIssuerIdentityRequest_Did{Did: "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169"}, KeyReference: ref},
		"bad PEM chain": {Subject: &backendv1.ImportIssuerIdentityRequest_X509ChainPem{X509ChainPem: "not a certificate"}, KeyReference: ref},
	} {
		if _, err := importIdentity(svc, req); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// selfSigned returns one self signed certificate in PEM.
func selfSigned(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Issuer One", Organization: []string{"Ministry of Agriculture"}, Country: []string{"KE"}},
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestImportX509ChainSignsWithTheChain(t *testing.T) {
	svc, f := identityService(t, filepath.Join(t.TempDir(), "issuer.json"), "", "")
	chain := selfSigned(t)
	ref := `{"type":"tse","server":"http://vault:8200/v1/transit","accessKey":"s.token","id":"issuer-key"}`
	id, err := importIdentity(svc, &backendv1.ImportIssuerIdentityRequest{
		Subject: &backendv1.ImportIssuerIdentityRequest_X509ChainPem{X509ChainPem: chain}, KeyReference: ref,
		LegalIdentifier: "KE-GOV-017",
	})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(chain))
	if len(id.GetX5C()) != 1 || id.GetX5C()[0] != base64.StdEncoding.EncodeToString(block.Bytes) {
		t.Fatalf("x5c = %v", id.GetX5C())
	}
	if len(id.GetIdentifiers()) != 1 || !strings.Contains(id.GetIdentifiers()[0], "CN=Issuer One") {
		t.Fatalf("identifiers = %v", id.GetIdentifiers())
	}
	// An offer carries the chain to walt.id.
	if _, err := svc.RegisterCredentialConfiguration(context.Background(), connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{
		Configuration: sdJwtConfiguration(),
	})); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{Spec: sdJwtSpec()})); err != nil {
		t.Fatal(err)
	}
	var issued struct {
		X5Chain []string `json:"x5Chain"`
	}
	if err := f.RequestJSON("/openid4vc/sdjwt/issue", &issued); err != nil {
		t.Fatal(err)
	}
	if len(issued.X5Chain) != 1 || issued.X5Chain[0] != id.GetX5C()[0] {
		t.Fatalf("x5Chain = %v", issued.X5Chain)
	}
}

func TestAutoOnboardKeepsTheIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "issuer.json")
	svc, _ := identityService(t, path, "", "")
	if _, err := svc.RegisterCredentialConfiguration(context.Background(), connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{
		Configuration: sdJwtConfiguration(),
	})); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{Spec: sdJwtSpec()})); err != nil {
		t.Fatal(err)
	}
	// The key of the first offer survives a restart.
	again, _ := identityService(t, path, "", "")
	res, err := again.GetIssuerIdentity(context.Background(), connect.NewRequest(&backendv1.GetIssuerIdentityRequest{}))
	if err != nil || res.Msg.GetIdentity() == nil {
		t.Fatalf("identity after restart = %v %v", res, err)
	}
}

func TestCapabilitiesListIdentityFeatures(t *testing.T) {
	svc, _ := identityService(t, "", "", "")
	res, err := svc.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	want := map[backendv1.Feature]bool{
		backendv1.Feature_FEATURE_ISSUER_IDENTITY_PROVISION:   true,
		backendv1.Feature_FEATURE_ISSUER_IDENTITY_IMPORT_DID:  true,
		backendv1.Feature_FEATURE_ISSUER_IDENTITY_IMPORT_X509: true,
	}
	for _, f := range res.Msg.GetFeatures() {
		delete(want, f)
	}
	if len(want) != 0 {
		t.Fatalf("missing features %v", want)
	}
	if strings.Join(res.Msg.GetDidMethods(), " ") != "did:web did:key did:jwk did:cheqd" {
		t.Fatalf("did methods = %v", res.Msg.GetDidMethods())
	}
	if strings.Join(res.Msg.GetKeyTypes(), " ") != "Ed25519 secp256r1 secp256k1 RSA" {
		t.Fatalf("key types = %v", res.Msg.GetKeyTypes())
	}
}

// sdJwtConfiguration is one SD-JWT schema of the stack.
func sdJwtConfiguration() *backendv1.CredentialConfiguration {
	return &backendv1.CredentialConfiguration{Id: "identity-2026", Format: commonv1.Format_FORMAT_VC_SD_JWT, Type: "IdentityCredential"}
}

// sdJwtSpec issues one credential of sdJwtConfiguration.
func sdJwtSpec() *backendv1.IssueSpec {
	return &backendv1.IssueSpec{ConfigurationId: "identity-2026", SubjectData: `{"given_name":"Wanjiru"}`}
}

func TestIdentityEdgeCases(t *testing.T) {
	ctx := context.Background()
	// No issuer URL: the adapter has no issuer identity.
	noIssuer, err := service.New(service.Options{Client: waltid.New(waltid.Options{}), Store: store.Memory()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := noIssuer.GetIssuerIdentity(ctx, connect.NewRequest(&backendv1.GetIssuerIdentityRequest{})); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("get without an issuer: %v", err)
	}
	if _, err := provision(t, noIssuer, &backendv1.ProvisionIssuerIdentityRequest{Method: "did:key", KeyType: "Ed25519"}); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("provision without an issuer: %v", err)
	}
	// A state file that cannot be written fails the call, and an offer
	// still signs with the key it onboards.
	blocked := filepath.Join(t.TempDir(), "issuer.json")
	if err := os.Mkdir(blocked+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	svc, f := identityService(t, blocked, "", "")
	if _, err := provision(t, svc, &backendv1.ProvisionIssuerIdentityRequest{Method: "did:key", KeyType: "Ed25519"}); connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("provision into a blocked file: %v", err)
	}
	if _, err := importIdentity(svc, &backendv1.ImportIssuerIdentityRequest{
		Subject: &backendv1.ImportIssuerIdentityRequest_Did{Did: "did:web:issuer.example"}, KeyReference: `{"type":"tse","id":"k"}`,
	}); connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("import into a blocked file: %v", err)
	}
	if _, err := svc.RegisterCredentialConfiguration(ctx, connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{Configuration: sdJwtConfiguration()})); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{Spec: sdJwtSpec()})); err != nil {
		t.Fatalf("offer with a blocked file: %v", err)
	}
	// walt.id refuses the onboarding.
	f.SetStatus("/onboard/issuer", 500)
	fresh, ff := identityService(t, "", "", "")
	ff.SetStatus("/onboard/issuer", 500)
	if _, err := provision(t, fresh, &backendv1.ProvisionIssuerIdentityRequest{Method: "did:jwk", KeyType: "RSA"}); err == nil {
		t.Fatal("provision passed a refused onboarding")
	}
	// A state file without a key stops the service at start.
	empty := filepath.Join(t.TempDir(), "issuer.json")
	if err := os.WriteFile(empty, []byte(`{"issuerDid":"did:web:x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.New(service.Options{Client: waltid.New(waltid.Options{}), Store: store.Memory(), IdentityFile: empty}); err == nil {
		t.Fatal("New accepted a state file without a key")
	}
	// The key type comes from the JWK of the reference.
	for kty, jwk := range map[string]string{
		"secp256k1": `{"kty":"EC","crv":"secp256k1","x":"a","y":"b"}`,
		"secp256r1": `{"kty":"EC","crv":"P-256","x":"a","y":"b"}`,
		"RSA":       `{"kty":"RSA","n":"a","e":"AQAB"}`,
		"":          `{"kty":"EC","crv":"P-521","x":"a","y":"b"}`,
	} {
		id, err := importIdentity(fresh, &backendv1.ImportIssuerIdentityRequest{
			Subject: &backendv1.ImportIssuerIdentityRequest_Did{Did: "did:web:issuer.example"}, KeyReference: `{"type":"jwk","jwk":` + jwk + `}`,
		})
		if err != nil || id.GetKey().GetType() != kty {
			t.Errorf("%s: %+v %v", kty, id.GetKey(), err)
		}
		if kty != "" && !strings.Contains(id.GetDidDocument(), `"kty"`) {
			t.Errorf("%s: the did:web document lacks the key: %s", kty, id.GetDidDocument())
		}
	}
}
