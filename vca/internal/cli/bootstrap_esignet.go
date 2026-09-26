// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
)

// The eSignet of the Inji stack is a login provider of the issuer and
// holder pairs and the authorization server of Certify. Its token
// endpoint takes private_key_jwt only, with an RS256 assertion from an
// RSA key (eSignet 1.5.1, mosip.esignet.supported.client.auth.methods).
// The bootstrap run registers one VCA client with the public key and
// keeps the private key in a file of its own.
const (
	// EnvBootstrapEsignetURL overrides the address of eSignet for the
	// bootstrap run. Empty means 127.0.0.1 and INJI_ESIGNET_HOST_PORT.
	EnvBootstrapEsignetURL = "VCA_BOOTSTRAP_ESIGNET_URL"
	// EnvBootstrapEsignetToken names a bearer token with the scope
	// add_oidc_client, for an eSignet whose client API needs one.
	EnvBootstrapEsignetToken = "VCA_BOOTSTRAP_ESIGNET_TOKEN" //nolint:gosec // G101: this is a variable name, not a credential.
	// EsignetDir is the directory of the client key, beside the pair
	// directories. It holds a .gitignore that ignores everything.
	EsignetDir = "esignet-inji"
	// EsignetKeyFile is the private key of the VCA client, PEM PKCS #1.
	EsignetKeyFile = "vca-client.pem"
	// EsignetStateFile keeps the redirect URIs the runs registered.
	EsignetStateFile = "vca-client.json"
	// EsignetClientID is the client id of VCA in eSignet.
	EsignetClientID = "vca-inji"
	// esignetPath is the servlet path of eSignet.
	esignetPath = "/v1/esignet"
	// esignetDefaultPort is the host port of the stack file.
	esignetDefaultPort = "17082"
	// esignetKeyBits is the size of the client key.
	esignetKeyBits = 2048
)

// esignetState is what the runs registered, so a later run keeps the
// redirect URI of an earlier one.
type esignetState struct {
	ClientID     string   `json:"client_id"`
	RedirectURIs []string `json:"redirect_uris"`
}

// esignetAnswer is the ResponseWrapper of the eSignet client API.
type esignetAnswer struct {
	Response *struct {
		ClientID string `json:"clientId"`
		Status   string `json:"status"`
	} `json:"response"`
	Errors []struct {
		ErrorCode    string `json:"errorCode"`
		ErrorMessage string `json:"errorMessage"`
	} `json:"errors"`
}

// usesEsignet reports whether the pair logs in through the eSignet of
// the stack file: the issuer and the holder pairs run it.
func usesEsignet(p Pair) bool {
	return p.Role == commonv1.Role_ROLE_ISSUER || p.Role == commonv1.Role_ROLE_HOLDER
}

// registerEsignetClient creates the VCA client in eSignet, or adds the
// redirect URI of the pair to it. The key file stays on the host with
// mode 0600 and never reaches a tracked file (ADR-035 decision 4).
func registerEsignetClient(ctx context.Context, opts BootstrapOptions, result *BootstrapResult) error {
	base := strings.TrimRight(opts.value(EnvBootstrapEsignetURL,
		"http://"+LoopbackAddress+":"+opts.value("INJI_ESIGNET_HOST_PORT", esignetDefaultPort)), "/")
	dir := filepath.Join(filepath.Dir(opts.Dir), EsignetDir)
	keyPath := filepath.Join(dir, EsignetKeyFile)
	key, made, err := esignetKey(dir, keyPath)
	if err != nil {
		return err
	}
	if made {
		result.step(opts.Out, "eSignet client key written to %s with mode 0600", keyPath)
	}
	state := readEsignetState(filepath.Join(dir, EsignetStateFile))
	redirect := opts.value("VCA_OIDC_REDIRECT_URI", strings.TrimRight(opts.Values["VCA_PUBLIC_URL"], "/")+"/auth/callback")
	if !slices.Contains(state.RedirectURIs, redirect) {
		state.RedirectURIs = append(state.RedirectURIs, redirect)
	}
	state.ClientID = EsignetClientID
	details := esignetClient(opts, key, state)
	answer, err := esignetCall(ctx, opts, http.MethodPost, base+esignetPath+"/client-mgmt/oauth-client", details)
	if err != nil {
		return err
	}
	verb := "created"
	if len(answer.Errors) > 0 {
		if answer.Errors[0].ErrorCode != "duplicate_client_id" {
			return fmt.Errorf("register the eSignet client: %s %s", answer.Errors[0].ErrorCode, answer.Errors[0].ErrorMessage)
		}
		delete(details, "clientId")
		delete(details, "publicKey")
		delete(details, "relyingPartyId")
		details["status"] = "ACTIVE"
		if _, err := esignetCall(ctx, opts, http.MethodPut, base+esignetPath+"/client-mgmt/oauth-client/"+EsignetClientID, details); err != nil {
			return err
		}
		verb = "present and updated"
	}
	if err := writeEsignetState(filepath.Join(dir, EsignetStateFile), state); err != nil {
		return err
	}
	result.step(opts.Out, "eSignet client %s %s", EsignetClientID, verb)
	result.step(opts.Out, "Add eSignet as a login provider with the client %s, private_key_jwt, and the key file %s. "+
		"Its issuer is %s%s", EsignetClientID, keyPath, base, esignetPath)
	return nil
}

// esignetKey reads the client key, or makes one. It reports true when
// it made the key.
func esignetKey(dir, path string) (*rsa.PrivateKey, bool, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the path comes from the deploy root
	if err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, false, fmt.Errorf("the eSignet client key %s holds no PEM block", path)
		}
		key, perr := x509.ParsePKCS1PrivateKey(block.Bytes)
		if perr != nil {
			return nil, false, fmt.Errorf("the eSignet client key %s: %w", path, perr)
		}
		return key, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, fmt.Errorf("read the eSignet client key: %w", err)
	}
	if merr := os.MkdirAll(dir, 0o700); merr != nil {
		return nil, false, fmt.Errorf("make the eSignet key directory: %w", merr)
	}
	// The directory holds a key, so git ignores all of it.
	if werr := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("*\n"), 0o600); werr != nil {
		return nil, false, fmt.Errorf("write the eSignet key directory: %w", werr)
	}
	key, err := rsa.GenerateKey(rand.Reader, esignetKeyBits)
	if err != nil {
		return nil, false, fmt.Errorf("make the eSignet client key: %w", err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		return nil, false, fmt.Errorf("write the eSignet client key: %w", err)
	}
	return key, true, nil
}

// esignetClient returns the client detail of the create request
// (ClientDetailCreateRequestV2 of eSignet 1.5.1). The public key is an
// RSA JWK; the private part never leaves the host.
func esignetClient(opts BootstrapOptions, key *rsa.PrivateKey, state esignetState) map[string]any {
	jwk, kid := rsaJWK(key)
	jwk["kid"] = kid
	public := strings.TrimRight(opts.Values["VCA_PUBLIC_URL"], "/")
	return map[string]any{
		"clientId": EsignetClientID, "clientName": "Verifiable Credentials Adapters",
		"clientNameLangMap": map[string]string{"eng": "Verifiable Credentials Adapters"},
		"relyingPartyId":    "vca", "publicKey": jwk, "logoUri": public + "/favicon.ico",
		"userClaims":        []string{"name", "email", "phone_number"},
		"authContextRefs":   []string{"mosip:idp:acr:generated-code", "mosip:idp:acr:password"},
		"redirectUris":      state.RedirectURIs,
		"grantTypes":        []string{"authorization_code"},
		"clientAuthMethods": []string{"private_key_jwt"},
	}
}

// rsaJWK returns the public JWK of the key as an object and its RFC 7638
// thumbprint. The key is a valid RSA key, so neither step fails.
func rsaJWK(key *rsa.PrivateKey) (map[string]any, string) {
	jwk, err := jose.PublicJWK(&key.PublicKey, "")
	if err != nil {
		return map[string]any{}, ""
	}
	kid, err := jose.Thumbprint(jwk)
	if err != nil {
		return map[string]any{}, ""
	}
	out, err := jose.JWKToMap(jwk)
	if err != nil {
		return map[string]any{}, ""
	}
	return out, kid
}

// esignetCall sends one request of the client API in the RequestWrapper
// of eSignet and reads the ResponseWrapper.
func esignetCall(ctx context.Context, opts BootstrapOptions, method, target string, request map[string]any) (esignetAnswer, error) {
	body, err := json.Marshal(map[string]any{
		"requestTime": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), "request": request,
	})
	if err != nil {
		return esignetAnswer{}, fmt.Errorf("encode the eSignet request: %w", err)
	}
	status, raw, err := doStatus(ctx, opts.client(), method, target, opts.value(EnvBootstrapEsignetToken, ""), body)
	if err != nil {
		return esignetAnswer{}, fmt.Errorf("the eSignet client API: %w", err)
	}
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return esignetAnswer{}, fmt.Errorf("the eSignet client API answered %d; set %s to a token with the scope add_oidc_client",
			status, EnvBootstrapEsignetToken)
	case status < 200 || status > 299:
		return esignetAnswer{}, fmt.Errorf("%s %s: the server answered %d", method, target, status)
	}
	var answer esignetAnswer
	if err := json.Unmarshal(raw, &answer); err != nil {
		return esignetAnswer{}, fmt.Errorf("read the eSignet answer: %w", err)
	}
	return answer, nil
}

// readEsignetState reads the state file. A missing or broken file gives
// an empty state.
func readEsignetState(path string) esignetState {
	var state esignetState
	raw, err := os.ReadFile(path) // #nosec G304 -- the path comes from the deploy root
	if err != nil || json.Unmarshal(raw, &state) != nil {
		return esignetState{}
	}
	return state
}

// writeEsignetState writes the state file with mode 0600.
func writeEsignetState(path string, state esignetState) error {
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode the eSignet state: %w", err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		return fmt.Errorf("write the eSignet state: %w", err)
	}
	return nil
}
