// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/waltid"
	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// kmsService is identityService with an external key store and a cheqd
// network, as VCA_WALTID_KMS_* and VCA_WALTID_CHEQD_NETWORK set them.
func kmsService(t *testing.T, path string, ks *waltid.KeyStore) (*service.Service, *fake.Server) {
	t.Helper()
	f := fake.New(testdata)
	t.Cleanup(f.Close)
	svc, err := service.New(service.Options{
		Client: waltid.New(waltid.Options{
			Issuer: dpgclient.New(dpgclient.Options{BaseURL: f.URL(), HTTP: f.Client(), Retries: -1, Sleep: func(time.Duration) {}}),
		}),
		Store: store.Memory(), DpgVersion: "0.18.2", IdentityFile: path, KeyStore: ks, CheqdNetwork: "mainnet",
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, f
}

// TestProvisionEveryMethod provisions each DID method with each key type
// the adapter lists, and checks the onboarding body and the identifier.
func TestProvisionEveryMethod(t *testing.T) {
	prefixes := map[string]string{"did:web": "did:web:issuer.labs.example", "did:key": "did:key:", "did:jwk": "did:jwk:", "did:cheqd": "did:cheqd:mainnet:"}
	for _, method := range service.DidMethods {
		for _, keyType := range service.KeyTypes {
			t.Run(method+" "+keyType, func(t *testing.T) {
				svc, f := kmsService(t, filepath.Join(t.TempDir(), "issuer.json"), nil)
				id, err := provision(t, svc, &backendv1.ProvisionIssuerIdentityRequest{Method: method, KeyType: keyType, Domain: "issuer.labs.example"})
				if method == "did:cheqd" && keyType != "Ed25519" {
					if connect.CodeOf(err) != connect.CodeInvalidArgument {
						t.Fatalf("cheqd with %s: %v", keyType, err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				var body struct {
					Key struct {
						Backend string          `json:"backend"`
						KeyType string          `json:"keyType"`
						Config  json.RawMessage `json:"config"`
					} `json:"key"`
					Did struct {
						Method string            `json:"method"`
						Config map[string]string `json:"config"`
					} `json:"did"`
				}
				if err := f.RequestJSON("/onboard/issuer", &body); err != nil {
					t.Fatal(err)
				}
				if body.Key.Backend != "jwk" || body.Key.KeyType != keyType || len(body.Key.Config) != 0 || "did:"+body.Did.Method != method {
					t.Fatalf("onboard body = %+v", body)
				}
				switch method {
				case "did:cheqd":
					if body.Did.Config["network"] != "mainnet" {
						t.Errorf("cheqd config = %v", body.Did.Config)
					}
				case "did:web":
					if body.Did.Config["domain"] != "issuer.labs.example" {
						t.Errorf("web config = %v", body.Did.Config)
					}
				default:
					if len(body.Did.Config) != 0 {
						t.Errorf("%s config = %v", method, body.Did.Config)
					}
				}
				if got := id.GetIdentifiers(); len(got) != 1 || !strings.HasPrefix(got[0], prefixes[method]) {
					t.Fatalf("identifiers = %v", got)
				}
				if id.GetKey().GetType() != keyType || id.GetKey().GetBackend() != "jwk" {
					t.Errorf("key = %+v", id.GetKey())
				}
			})
		}
	}
}

// TestImportDidWithJwk binds a did:jwk to the jwk key it carries, and
// refuses another key.
func TestImportDidWithJwk(t *testing.T) {
	svc, _ := kmsService(t, filepath.Join(t.TempDir(), "issuer.json"), nil)
	jwk := `{"kty":"OKP","crv":"Ed25519","x":"dVxMuSVsp83ErP3Gz-7ahJAX5bn5UU6ZGRvWfgsNQnY"}`
	id := "did:jwk:" + b64url(jwk)
	ref := `{"type":"jwk","jwk":{"kty":"OKP","crv":"Ed25519","x":"dVxMuSVsp83ErP3Gz-7ahJAX5bn5UU6ZGRvWfgsNQnY","d":"AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dw"}}`
	got, err := importIdentity(svc, &backendv1.ImportIssuerIdentityRequest{Subject: &backendv1.ImportIssuerIdentityRequest_Did{Did: id}, KeyReference: ref})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetIdentifiers()[0] != id || got.GetKey().GetType() != "Ed25519" || !strings.Contains(got.GetDidDocument(), `"crv":"Ed25519"`) {
		t.Fatalf("identity = %+v", got)
	}
	other := `{"type":"jwk","jwk":{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}}`
	if _, err := importIdentity(svc, &backendv1.ImportIssuerIdentityRequest{Subject: &backendv1.ImportIssuerIdentityRequest_Did{Did: id}, KeyReference: other}); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("another key: %v", err)
	}
}

// TestKeyBackendTseWhenConfigured makes every provisioned key in the
// external key store: the onboarding body names tse with the store
// settings, the key types drop the one the store cannot make, and the
// state file holds a key reference without a private key.
func TestKeyBackendTseWhenConfigured(t *testing.T) {
	path := filepath.Join(t.TempDir(), "issuer.json")
	ks := &waltid.KeyStore{Backend: "tse", Config: json.RawMessage(`{"server":"http://vault:8200/v1/transit","auth":{"accessKey":"dev-only-token"}}`)}
	svc, f := kmsService(t, path, ks)
	caps, err := svc.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(caps.Msg.GetKeyTypes(), ",") != "Ed25519,secp256r1,RSA" {
		t.Errorf("key types = %v", caps.Msg.GetKeyTypes())
	}
	id, err := provision(t, svc, &backendv1.ProvisionIssuerIdentityRequest{Method: "did:key", KeyType: "Ed25519"})
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Key struct {
			Backend string         `json:"backend"`
			Config  map[string]any `json:"config"`
		} `json:"key"`
	}
	if rerr := f.RequestJSON("/onboard/issuer", &body); rerr != nil {
		t.Fatal(rerr)
	}
	if body.Key.Backend != "tse" || body.Key.Config["server"] != "http://vault:8200/v1/transit" {
		t.Fatalf("onboard key = %+v", body.Key)
	}
	if id.GetKey().GetBackend() != "tse" || id.GetKey().GetType() != "Ed25519" {
		t.Fatalf("key = %+v", id.GetKey())
	}
	raw, err := os.ReadFile(path) //nolint:gosec // G304: a test path
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"type": "tse"`) || strings.Contains(string(raw), `"d":`) {
		t.Fatalf("state file = %s", raw)
	}
	// The store cannot make a secp256k1 key, and a jwk key stays possible.
	if _, err := provision(t, svc, &backendv1.ProvisionIssuerIdentityRequest{Method: "did:key", KeyType: "secp256k1"}); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("secp256k1 in tse: %v", err)
	}
	if _, err := provision(t, svc, &backendv1.ProvisionIssuerIdentityRequest{Method: "did:key", KeyType: "secp256k1", KeyBackend: "jwk"}); err != nil {
		t.Errorf("an explicit jwk key: %v", err)
	}
}

// b64url encodes text as base64url without padding.
func b64url(text string) string { return base64.RawURLEncoding.EncodeToString([]byte(text)) }
