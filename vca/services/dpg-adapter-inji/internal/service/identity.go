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
	"strings"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/inji"
)

// keyBackend names the key store of Certify: the MOSIP key manager. The
// stack keeps every private key (ADR-001 decision 3).
const keyBackend = "certify-keymanager"

// identityKey is the store key of the state of the identity: the key the
// last provision or import named, and the organisation.
const identityKey = "identity/state"

// identityState is what the adapter keeps of the identity. It holds no
// private key.
type identityState struct {
	Key             inji.KeyRef `json:"key"`
	DisplayName     string      `json:"display_name,omitempty"`
	LegalIdentifier string      `json:"legal_identifier,omitempty"`
	// Chain is the imported chain in PEM, leaf first.
	Chain string `json:"chain,omitempty"`
}

// verificationKeyTypes maps a verification method type of the DID
// document of Certify onto the key type of the contract.
var verificationKeyTypes = map[string]string{
	"Ed25519VerificationKey2020":        "Ed25519",
	"EcdsaSecp256r1VerificationKey2019": "secp256r1",
	"EcdsaSecp256k1VerificationKey2019": "secp256k1",
	"RsaVerificationKey2018":            "RSA",
}

// GetIssuerIdentity reads the did:web document Certify serves, and the
// certificate of the signing key from its key manager.
func (s *Service) GetIssuerIdentity(
	ctx context.Context, _ *connect.Request[backendv1.GetIssuerIdentityRequest],
) (*connect.Response[backendv1.GetIssuerIdentityResponse], error) {
	if s.certify == nil {
		return nil, unimplemented("this adapter has no Inji Certify URL, so it reads no issuer identity")
	}
	id, err := s.identity(ctx, s.identityState(ctx))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&backendv1.GetIssuerIdentityResponse{Identity: id}), nil
}

// ProvisionIssuerIdentity asks the key manager of Certify for the key of
// the chosen type. The key manager makes the key when it has none, and
// keeps it. Certify serves one did:web, which its configuration names,
// so did:web is the one method.
func (s *Service) ProvisionIssuerIdentity(
	ctx context.Context, req *connect.Request[backendv1.ProvisionIssuerIdentityRequest],
) (*connect.Response[backendv1.ProvisionIssuerIdentityResponse], error) {
	if s.certify == nil {
		return nil, unimplemented("this adapter has no Inji Certify URL, so it provisions no issuer identity")
	}
	m := req.Msg
	if method := m.GetMethod(); method != "" && method != didWeb {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("the stack serves the one did:web of its Certify configuration, not %s", method))
	}
	keyType := m.GetKeyType()
	if keyType == "" {
		keyType = "Ed25519"
	}
	ref, ok := inji.KeyRefOf(keyType)
	if !ok {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("the key manager of the stack has no key type %q", keyType))
	}
	if _, err := s.certify.Certificate(ctx, ref); err != nil {
		return nil, failed("make the key in the key manager", err)
	}
	state := identityState{Key: ref, DisplayName: m.GetDisplayName(), LegalIdentifier: m.GetLegalIdentifier()}
	if err := s.saveIdentity(ctx, state); err != nil {
		return nil, err
	}
	id, err := s.identity(ctx, state)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&backendv1.ProvisionIssuerIdentityResponse{Identity: id}), nil
}

// ImportIssuerIdentity puts a CA signed certificate on a key of the key
// manager. The CA certificates of the chain go to the trust store of the
// stack first. The key reference is a JSON object with applicationId
// and referenceId. Certify reads its DID from its configuration, so a
// DID import answers Unimplemented.
func (s *Service) ImportIssuerIdentity(
	ctx context.Context, req *connect.Request[backendv1.ImportIssuerIdentityRequest],
) (*connect.Response[backendv1.ImportIssuerIdentityResponse], error) {
	if s.certify == nil {
		return nil, unimplemented("this adapter has no Inji Certify URL, so it imports no issuer identity")
	}
	m := req.Msg
	if m.GetDid() != "" {
		return nil, unimplemented("Inji Certify reads its issuer DID from its configuration; import an X.509 chain for its key")
	}
	certs, err := parseChain(m.GetX509ChainPem())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	var ref inji.KeyRef
	if json.Unmarshal([]byte(m.GetKeyReference()), &ref) != nil || ref.AppID == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New(`the key reference must be a JSON object such as {"applicationId":"CERTIFY_VC_SIGN_ED25519","referenceId":"ED25519_SIGN"}`))
	}
	for _, ca := range certs[1:] {
		if uerr := s.certify.UploadCACertificate(ctx, ca, s.caDomain, s.now()); uerr != nil {
			return nil, keyError("upload the CA certificate", uerr)
		}
	}
	if uerr := s.certify.UploadCertificate(ctx, ref, certs[0], s.now()); uerr != nil {
		return nil, keyError("upload the certificate of the key", uerr)
	}
	state := identityState{Key: ref, DisplayName: m.GetDisplayName(), LegalIdentifier: m.GetLegalIdentifier(),
		Chain: strings.Join(certs, "")}
	if serr := s.saveIdentity(ctx, state); serr != nil {
		return nil, serr
	}
	id, err := s.identity(ctx, state)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&backendv1.ImportIssuerIdentityResponse{Identity: id}), nil
}

// didWeb is the one DID method of Certify.
const didWeb = "did:web"

// keyError maps a refusal of the key manager onto a Connect error that
// keeps its code.
func keyError(action string, err error) *connect.Error {
	var ae *inji.APIError
	if errors.As(err, &ae) {
		return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("%s: %w", action, err))
	}
	return failed(action, err)
}

// identityState reads the kept state, or the signing key of ldp_vc.
func (s *Service) identityState(ctx context.Context) identityState {
	state := identityState{Key: inji.KeyRef{AppID: s.profiles.Ldp.AppID, RefID: s.profiles.Ldp.RefID}}
	raw, err := s.store.Get(ctx, identityKey)
	if err == nil {
		var kept identityState
		if json.Unmarshal(raw, &kept) == nil && kept.Key.AppID != "" {
			state = kept
		}
	}
	return state
}

// saveIdentity keeps the state of the identity.
func (s *Service) saveIdentity(ctx context.Context, state identityState) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	if err := s.store.Put(ctx, identityKey, raw); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	return nil
}

// identity builds the identity from the DID document of Certify and the
// certificate chain of the key. A failed certificate call leaves the
// chain out.
func (s *Service) identity(ctx context.Context, state identityState) (*backendv1.IssuerIdentity, error) {
	doc, err := s.certify.ReadDIDDocument(ctx)
	if err != nil {
		return nil, failed("read the issuer DID document", err)
	}
	keyType := inji.KeyTypeOf(state.Key)
	for _, vm := range doc.VerificationMethod {
		if t, ok := verificationKeyTypes[vm.Type]; ok && keyType == "" {
			keyType = t
		}
	}
	id := &backendv1.IssuerIdentity{
		Identifiers: []string{doc.ID}, DidDocument: string(doc.Raw),
		Key: &backendv1.IssuerIdentity_Key{Type: keyType, Backend: keyBackend},
	}
	if state.DisplayName != "" || state.LegalIdentifier != "" {
		id.Metadata = &backendv1.IssuerIdentity_Metadata{DisplayName: state.DisplayName, LegalIdentifier: state.LegalIdentifier}
	}
	chain := state.Chain
	if chain == "" {
		if cert, cerr := s.certify.Certificate(ctx, state.Key); cerr == nil {
			chain = cert.Certificate
		}
	}
	for i, c := range pemCertificates(chain) {
		if i == 0 {
			id.Identifiers = append(id.Identifiers, c.Subject.String())
		}
		id.X5C = append(id.X5C, base64.StdEncoding.EncodeToString(c.Raw))
	}
	return id, nil
}

// parseChain splits a PEM chain into its certificates, leaf first.
func parseChain(text string) ([]string, error) {
	var out []string
	rest := []byte(text)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if _, err := x509.ParseCertificate(block.Bytes); block.Type != "CERTIFICATE" || err != nil {
			return nil, errors.New("the chain holds a block that is not a certificate")
		}
		out = append(out, string(pem.EncodeToMemory(block)))
	}
	if len(out) == 0 {
		return nil, errors.New("the chain holds no PEM certificate")
	}
	return out, nil
}

// pemCertificates parses the certificates of a PEM text. A block that
// does not parse stays out.
func pemCertificates(text string) []*x509.Certificate {
	var out []*x509.Certificate
	rest := []byte(text)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			out = append(out, c)
		}
	}
}
