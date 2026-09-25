// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/did"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/waltid"
)

// DidMethods are the DID methods the adapter provisions through the
// onboarding endpoint of walt.id, in the order a page offers them. A
// did:cheqd goes through the public cheqd registrar that walt.id calls,
// on the network of VCA_WALTID_CHEQD_NETWORK.
var DidMethods = []string{"did:web", "did:key", "did:jwk", "did:cheqd"}

// KeyTypes are the key types the onboarding endpoint makes in a jwk key,
// as walt.id names them.
var KeyTypes = []string{"Ed25519", "secp256r1", "secp256k1", "RSA"}

// tseKeyTypes are the key types the HashiCorp Vault transit engine makes.
// walt.id refuses secp256k1 there.
var tseKeyTypes = []string{"Ed25519", "secp256r1", "RSA"}

// cheqdKeyType is the only key type of a did:cheqd.
const cheqdKeyType = "Ed25519"

// DefaultKeyBackend is the key store of a provisioned key without an
// external key store. The community release then keeps a jwk key in
// each request (ADR-046 decision 4).
const DefaultKeyBackend = "jwk"

// defaultBackend is the key store of a provisioned key: the external key
// store when the configuration names one.
func (s *Service) defaultBackend() string {
	if s.keyStore != nil {
		return s.keyStore.Backend
	}
	return DefaultKeyBackend
}

// keyTypesOf lists the key types a key store makes.
func keyTypesOf(backend string) []string {
	if backend == "tse" {
		return tseKeyTypes
	}
	return KeyTypes
}

// identityState is the identity the adapter signs with. The file that
// holds it has mode 0600, because the community release of walt.id takes
// the key in each request (ADR-046 decision 4). The two first fields
// have the names of the onboarding answer, so the file that
// "vca dpg bootstrap waltid" writes reads as a state file.
type identityState struct {
	IssuerKey       json.RawMessage `json:"issuerKey"`
	IssuerDid       string          `json:"issuerDid,omitempty"`
	X5c             []string        `json:"x5c,omitempty"`
	X509Subject     string          `json:"x509Subject,omitempty"`
	KeyType         string          `json:"keyType,omitempty"`
	KeyBackend      string          `json:"keyBackend,omitempty"`
	DisplayName     string          `json:"displayName,omitempty"`
	LegalIdentifier string          `json:"legalIdentifier,omitempty"`
}

// loadIdentity reads the state file. A missing file gives no state.
func loadIdentity(path string) (identityState, bool, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the path comes from the configuration
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return identityState{}, false, nil
	case err != nil:
		return identityState{}, false, fmt.Errorf("read the issuer identity file: %w", err)
	}
	var st identityState
	if err := json.Unmarshal(raw, &st); err != nil {
		return identityState{}, false, fmt.Errorf("the issuer identity file %s is not JSON: %w", path, err)
	}
	if len(st.IssuerKey) == 0 {
		return identityState{}, false, fmt.Errorf("the issuer identity file %s holds no issuerKey", path)
	}
	return st, true, nil
}

// saveIdentity writes the state file with mode 0600 through a temporary
// file, so a crash leaves the old file or the new one.
func saveIdentity(path string, st identityState) error {
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return fmt.Errorf("write the issuer identity file: %w", err)
	}
	if err := os.Rename(tmp, filepath.Clean(path)); err != nil {
		return fmt.Errorf("write the issuer identity file: %w", err)
	}
	return nil
}

// keyObject is the part of a walt.id key object the adapter reads.
type keyObject struct {
	Type string         `json:"type"`
	JWK  map[string]any `json:"jwk"`
}

// parseKeyReference reads a walt.id key object: a jwk key, or a
// reference into an external key store such as tse, oci, or aws.
func parseKeyReference(raw string) (json.RawMessage, keyObject, error) {
	var k keyObject
	if err := json.Unmarshal([]byte(raw), &k); err != nil {
		return nil, k, errors.New("the key reference must be a walt.id key object in JSON")
	}
	if k.Type == "" {
		return nil, k, errors.New(`the key reference names no "type", such as jwk or tse`)
	}
	return json.RawMessage(raw), k, nil
}

// keyTypeOf names the type of a JWK as walt.id does, or "" for a key
// the adapter cannot read.
func keyTypeOf(jwk map[string]any) string {
	switch jwk["kty"] {
	case "OKP":
		if jwk["crv"] == "Ed25519" {
			return "Ed25519"
		}
	case "EC":
		switch jwk["crv"] {
		case "P-256":
			return "secp256r1"
		case "secp256k1":
			return "secp256k1"
		}
	case "RSA":
		return "RSA"
	}
	return ""
}

// publicJWK returns the JWK without its private members.
func publicJWK(jwk map[string]any) map[string]any {
	out := make(map[string]any, len(jwk))
	for k, v := range jwk {
		switch k {
		case "d", "p", "q", "dp", "dq", "qi", "oth", "k":
			continue
		}
		out[k] = v
	}
	return out
}

// didDocument builds the DID document of a DID from the key: did:key and
// did:jwk carry their key, and a did:web publishes the public part of
// the JWK. A key of an external store gives no document.
func didDocument(id string, key keyObject) (string, error) {
	var doc did.Document
	var err error
	switch {
	case strings.HasPrefix(id, "did:key:"):
		doc, err = did.KeyDocument(id)
	case strings.HasPrefix(id, "did:jwk:"):
		doc, err = did.JWKDocument(id)
	case strings.HasPrefix(id, "did:web:") && len(key.JWK) > 0:
		fragment := "0"
		if kid, ok := key.JWK["kid"].(string); ok && kid != "" {
			fragment = kid
		}
		vm := id + "#" + fragment
		doc = did.Document{
			ID:                 id,
			VerificationMethod: []did.VerificationMethod{{ID: vm, Type: "JsonWebKey2020", Controller: id, PublicKeyJWK: publicJWK(key.JWK)}},
			AssertionMethod:    []string{vm}, Authentication: []string{vm},
		}
	default:
		return "", nil
	}
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// identityOf turns the state into the contract message.
func identityOf(st identityState) *backendv1.IssuerIdentity {
	var key keyObject
	if err := json.Unmarshal(st.IssuerKey, &key); err != nil {
		key = keyObject{}
	}
	id := &backendv1.IssuerIdentity{
		X5C:      st.X5c,
		Metadata: &backendv1.IssuerIdentity_Metadata{DisplayName: st.DisplayName, LegalIdentifier: st.LegalIdentifier},
		Key:      &backendv1.IssuerIdentity_Key{Type: st.KeyType, Backend: st.KeyBackend},
	}
	if id.Key.Type == "" {
		id.Key.Type = keyTypeOf(key.JWK)
	}
	if id.Key.Backend == "" {
		id.Key.Backend = key.Type
	}
	if st.IssuerDid != "" {
		id.Identifiers = append(id.Identifiers, st.IssuerDid)
		if doc, err := didDocument(st.IssuerDid, key); err == nil {
			id.DidDocument = doc
		}
	}
	if st.X509Subject != "" {
		id.Identifiers = append(id.Identifiers, st.X509Subject)
	}
	return id
}

// loadStateFile reads the state file at start and hands its identity to
// the client. A pinned configuration wins over the file.
func (s *Service) loadStateFile() error {
	if s.identityFile == "" || s.client.Pinned() {
		return nil
	}
	st, ok, err := loadIdentity(s.identityFile)
	if err != nil || !ok {
		return err
	}
	s.client.SetIssuer(st.IssuerKey, st.IssuerDid, st.X5c)
	s.identity, s.hasIdentity = st, true
	return nil
}

// keep stores a new identity: in the client, in memory, and in the state
// file when the configuration names one.
func (s *Service) keep(st identityState) error {
	if s.identityFile != "" {
		if err := saveIdentity(s.identityFile, st); err != nil {
			return err
		}
	}
	s.client.SetIssuer(st.IssuerKey, st.IssuerDid, st.X5c)
	s.idMu.Lock()
	s.identity, s.hasIdentity = st, true
	s.idMu.Unlock()
	return nil
}

// keepOnboarded keeps a key that the first offer onboarded, so it
// survives a restart.
func (s *Service) keepOnboarded(key json.RawMessage, issuerDid string) {
	st := identityState{IssuerKey: key, IssuerDid: issuerDid, KeyType: "secp256r1", KeyBackend: DefaultKeyBackend}
	if err := s.keep(st); err != nil {
		// The key still signs in memory. The next start onboards again.
		s.idMu.Lock()
		s.identity, s.hasIdentity = st, true
		s.idMu.Unlock()
	}
}

// current returns the identity the adapter signs with, if any.
func (s *Service) current() (identityState, bool) {
	s.idMu.Lock()
	st, ok := s.identity, s.hasIdentity
	s.idMu.Unlock()
	if ok {
		return st, true
	}
	key, issuerDid, x5c := s.client.Issuer()
	if len(key) == 0 {
		return identityState{}, false
	}
	return identityState{IssuerKey: key, IssuerDid: issuerDid, X5c: x5c}, true
}

// identityGuard answers the calls that change the identity when the
// adapter cannot take them.
func (s *Service) identityGuard() error {
	if !s.client.HasIssuer() {
		return unimplemented("this adapter has no issuer URL, so it has no issuer identity")
	}
	if s.client.Pinned() {
		return connect.NewError(connect.CodeFailedPrecondition, errors.New(
			"the configuration pins the issuer key and DID; clear VCA_WALTID_ISSUER_KEY and VCA_WALTID_ISSUER_DID to change the identity"))
	}
	return nil
}

// GetIssuerIdentity returns the identity the adapter signs with.
func (s *Service) GetIssuerIdentity(
	context.Context, *connect.Request[backendv1.GetIssuerIdentityRequest],
) (*connect.Response[backendv1.GetIssuerIdentityResponse], error) {
	if !s.client.HasIssuer() {
		return nil, unimplemented("this adapter has no issuer URL, so it has no issuer identity")
	}
	out := &backendv1.GetIssuerIdentityResponse{}
	if st, ok := s.current(); ok {
		out.Identity = identityOf(st)
	}
	return connect.NewResponse(out), nil
}

// ProvisionIssuerIdentity makes a key and a DID through POST
// /onboard/issuer with the method and the key type of the request
// (ADR-046 decision 2).
func (s *Service) ProvisionIssuerIdentity(
	ctx context.Context, req *connect.Request[backendv1.ProvisionIssuerIdentityRequest],
) (*connect.Response[backendv1.ProvisionIssuerIdentityResponse], error) {
	if err := s.identityGuard(); err != nil {
		return nil, err
	}
	body, err := s.onboardRequest(req.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	key, issuerDid, err := s.client.Onboard(ctx, body)
	if err != nil {
		return nil, failed("onboard the issuer", err)
	}
	st := identityState{
		IssuerKey: key, IssuerDid: issuerDid, KeyType: body.Key.KeyType, KeyBackend: body.Key.Backend,
		DisplayName: strings.TrimSpace(req.Msg.GetDisplayName()), LegalIdentifier: strings.TrimSpace(req.Msg.GetLegalIdentifier()),
	}
	if err := s.keep(st); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&backendv1.ProvisionIssuerIdentityResponse{Identity: identityOf(st)}), nil
}

// onboardRequest checks a provision request against what the adapter
// makes and builds the walt.id body. The key goes to the external key
// store of the configuration unless the request names jwk.
func (s *Service) onboardRequest(m *backendv1.ProvisionIssuerIdentityRequest) (waltid.OnboardRequest, error) {
	var out waltid.OnboardRequest
	if !contains(DidMethods, m.GetMethod()) {
		return out, fmt.Errorf("the method %q is not one of %s", m.GetMethod(), strings.Join(DidMethods, ", "))
	}
	backend := m.GetKeyBackend()
	if backend == "" {
		backend = s.defaultBackend()
	}
	out.Key = waltid.OnboardKey{Backend: backend, KeyType: m.GetKeyType()}
	switch {
	case backend == DefaultKeyBackend:
	case s.keyStore != nil && backend == s.keyStore.Backend:
		out.Key.Config = s.keyStore.Config
	default:
		return out, fmt.Errorf("the key backend %q is not configured; set VCA_WALTID_KMS_BACKEND or import its key", backend)
	}
	if types := keyTypesOf(backend); !contains(types, m.GetKeyType()) {
		return out, fmt.Errorf("the key store %s makes no key type %q; it makes %s", backend, m.GetKeyType(), strings.Join(types, ", "))
	}
	out.Did.Method = strings.TrimPrefix(m.GetMethod(), "did:")
	switch m.GetMethod() {
	case "did:web":
		domain := strings.TrimSpace(m.GetDomain())
		if domain == "" || strings.ContainsAny(domain, "/ ") {
			return out, errors.New("a did:web needs the host of the issuer, such as issuer.example")
		}
		out.Did.Config = &waltid.OnboardDidConfig{Domain: domain}
	case "did:cheqd":
		if m.GetKeyType() != cheqdKeyType {
			return out, fmt.Errorf("a did:cheqd needs an %s key", cheqdKeyType)
		}
		out.Did.Config = &waltid.OnboardDidConfig{Network: s.cheqdNetwork}
	}
	return out, nil
}

// ImportIssuerIdentity binds a DID or an X.509 chain to a walt.id key
// object (ADR-046 decision 2). The community release reads the key in
// each request, so a jwk key stays in the state file and a reference to
// an external key store keeps the key out of the adapter.
func (s *Service) ImportIssuerIdentity(
	_ context.Context, req *connect.Request[backendv1.ImportIssuerIdentityRequest],
) (*connect.Response[backendv1.ImportIssuerIdentityResponse], error) {
	if err := s.identityGuard(); err != nil {
		return nil, err
	}
	st, err := importState(req.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := s.keep(st); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&backendv1.ImportIssuerIdentityResponse{Identity: identityOf(st)}), nil
}

// importState checks an import request and builds the state.
func importState(m *backendv1.ImportIssuerIdentityRequest) (identityState, error) {
	raw, key, err := parseKeyReference(strings.TrimSpace(m.GetKeyReference()))
	if err != nil {
		return identityState{}, err
	}
	st := identityState{
		IssuerKey: raw, KeyType: keyTypeOf(key.JWK), KeyBackend: key.Type,
		DisplayName: strings.TrimSpace(m.GetDisplayName()), LegalIdentifier: strings.TrimSpace(m.GetLegalIdentifier()),
	}
	switch subject := m.GetSubject().(type) {
	case *backendv1.ImportIssuerIdentityRequest_Did:
		id := strings.TrimSpace(subject.Did)
		if _, err := did.Method(id); err != nil {
			return identityState{}, fmt.Errorf("%q is not a DID: %w", id, err)
		}
		if err := matchKey(id, key); err != nil {
			return identityState{}, err
		}
		st.IssuerDid = id
	case *backendv1.ImportIssuerIdentityRequest_X509ChainPem:
		chain, err := parseChain(subject.X509ChainPem)
		if err != nil {
			return identityState{}, err
		}
		st.X509Subject = chain[0].Subject.String()
		for _, c := range chain {
			st.X5c = append(st.X5c, base64.StdEncoding.EncodeToString(c.Raw))
		}
	default:
		return identityState{}, errors.New("the request needs a DID or an X.509 chain")
	}
	return st, nil
}

// matchKey checks that a jwk key belongs to a did:key or a did:jwk. The
// document of such a DID carries its key, so a mismatch would sign
// credentials no verifier accepts.
func matchKey(id string, key keyObject) error {
	if len(key.JWK) == 0 || !strings.HasPrefix(id, "did:key:") && !strings.HasPrefix(id, "did:jwk:") {
		return nil
	}
	var doc did.Document
	var err error
	if strings.HasPrefix(id, "did:key:") {
		doc, err = did.KeyDocument(id)
	} else {
		doc, err = did.JWKDocument(id)
	}
	if err != nil {
		return fmt.Errorf("%q does not resolve: %w", id, err)
	}
	for _, vm := range doc.VerificationMethod {
		if vm.PublicKeyJWK["x"] == key.JWK["x"] && vm.PublicKeyJWK["y"] == key.JWK["y"] && vm.PublicKeyJWK["n"] == key.JWK["n"] {
			return nil
		}
	}
	return fmt.Errorf("the key of the reference is not the key of %q", id)
}

// parseChain reads a PEM chain, leaf first.
func parseChain(text string) ([]*x509.Certificate, error) {
	rest := []byte(text)
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("the chain holds a certificate that does not parse: %w", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("the chain holds no PEM certificate")
	}
	return out, nil
}

// contains reports whether list holds v.
func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
