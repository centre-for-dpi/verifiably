// SPDX-License-Identifier: Apache-2.0

package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/credebl"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// The X.509 issuer identity of the organisation of the adapter (P6-C9,
// ADR-068). The platform keeps each certificate of an organisation in a
// row, and the agent keeps its key. The platform imports a certificate
// only with its private key, so VCA never imports one. The operator
// makes or imports the certificate in the platform. The key reference
// of the import names that row: {"certificateId": "<id>"}. The adapter
// checks that the leaf of the chain is the certificate of the row and
// that the chain verifies. It then makes the row the active certificate
// of its key type, which the platform signs an X.509 template with. The
// platform keeps the leaf only, so the adapter keeps the chain for the
// identity page.

// x509KeyTypes maps a key type of the platform onto a key type of the
// pages.
var x509KeyTypes = map[string]string{credebl.X509KeyP256: "secp256r1", credebl.X509KeyEd25519: "Ed25519"}

// chainRecord is what the store keeps of the imported chain.
type chainRecord struct {
	// CertificateID is the row of the platform.
	CertificateID string `json:"certificateId"`
	// Chain is the chain, leaf first, as base64 DER.
	Chain []string `json:"chain"`
}

// chainKey is the store key of the chain of one organisation.
func chainKey(org string) string {
	sum := sha256.Sum256([]byte(org))
	return "x509/" + hex.EncodeToString(sum[:])
}

// parseChain reads a PEM chain, leaf first, and checks that each
// certificate signed the one before it.
func parseChain(text string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := []byte(text)
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
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("a certificate of the PEM chain does not parse: %w", err))
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the chain holds no PEM certificate"))
	}
	for i := 0; i+1 < len(certs); i++ {
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument,
				fmt.Errorf("the chain does not verify: certificate %d is not signed by certificate %d: %w", i+1, i+2, err))
		}
	}
	return certs, nil
}

// certificateRef reads the row id of a key reference.
func certificateRef(ref string) (string, error) {
	var out struct {
		ID string `json:"certificateId"`
	}
	if json.Unmarshal([]byte(ref), &out) != nil || strings.TrimSpace(out.ID) == "" {
		return "", connect.NewError(connect.CodeInvalidArgument, errors.New(
			`the key reference names the certificate row of the platform as {"certificateId": "<id>"}`))
	}
	return strings.TrimSpace(out.ID), nil
}

// certificateDER decodes the certificate of a row, which the platform
// keeps as base64 DER.
func certificateDER(v string) []byte {
	if block, _ := pem.Decode([]byte(v)); block != nil {
		return block.Bytes
	}
	return anyval.OrZero(base64.StdEncoding.DecodeString(strings.TrimSpace(v)))
}

// ImportIssuerIdentity binds an X.509 chain to a certificate row of the
// organisation. A DID import is not available. See importMessage.
func (s *Service) ImportIssuerIdentity(
	ctx context.Context, req *connect.Request[backendv1.ImportIssuerIdentityRequest],
) (*connect.Response[backendv1.ImportIssuerIdentityResponse], error) {
	text := req.Msg.GetX509ChainPem()
	if req.Msg.GetDid() != "" || text == "" {
		return nil, unimplemented(importMessage)
	}
	certs, err := parseChain(text)
	if err != nil {
		return nil, err
	}
	id, err := certificateRef(req.Msg.GetKeyReference())
	if err != nil {
		return nil, err
	}
	now := s.now()
	if leaf := certs[0]; now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("the leaf certificate is valid from %s to %s only",
			leaf.NotBefore.UTC().Format("2006-01-02"), leaf.NotAfter.UTC().Format("2006-01-02")))
	}
	org := s.client.OrgID()
	row, err := s.client.X509Certificate(ctx, org, id)
	switch {
	case errors.Is(err, credebl.ErrNoCertificate):
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("the organisation holds no certificate row %s", id))
	case err != nil:
		return nil, failed("read the certificate row", err)
	}
	if !bytes.Equal(certificateDER(row.CertificateBase64), certs[0].Raw) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New(
			"the leaf certificate of the chain differs from the certificate of the row"))
	}
	if aerr := s.activate(ctx, org, row); aerr != nil {
		return nil, aerr
	}
	rec := chainRecord{CertificateID: id}
	for _, c := range certs {
		rec.Chain = append(rec.Chain, base64.StdEncoding.EncodeToString(c.Raw))
	}
	if perr := s.store.Put(ctx, chainKey(org), anyval.Must(json.Marshal(rec))); perr != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("keep the chain: %w", perr))
	}
	identity, err := s.identity(ctx)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&backendv1.ImportIssuerIdentityResponse{Identity: identity}), nil
}

// activate makes a row the active certificate of its key type. The
// platform refuses a second active row whose dates meet, so the older
// active rows of the key type go out of use first.
func (s *Service) activate(ctx context.Context, org string, row credebl.X509Certificate) error {
	if row.Status == credebl.X509Active {
		return nil
	}
	active, err := s.client.X509Certificates(ctx, org, credebl.X509Active, row.KeyType)
	if err != nil {
		return failed("list the active certificates", err)
	}
	for _, other := range active {
		if other.ID == row.ID {
			continue
		}
		if _, err := s.client.DeactivateX509(ctx, org, other.ID); err != nil {
			return failed("take the older certificate out of use", err)
		}
	}
	if _, err := s.client.ActivateX509(ctx, org, row.ID); err != nil {
		return failed("activate the certificate", err)
	}
	return nil
}

// addChain adds the imported chain to an identity while its row is the
// active certificate. A row out of use leaves the identity as it is.
func (s *Service) addChain(ctx context.Context, org string, id *backendv1.IssuerIdentity) error {
	raw, err := s.store.Get(ctx, chainKey(org))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return connect.NewError(connect.CodeInternal, fmt.Errorf("read the chain: %w", err))
	}
	var rec chainRecord
	if json.Unmarshal(raw, &rec) != nil || len(rec.Chain) == 0 {
		return connect.NewError(connect.CodeInternal, errors.New("the record of the chain is damaged"))
	}
	row, err := s.client.X509Certificate(ctx, org, rec.CertificateID)
	switch {
	case errors.Is(err, credebl.ErrNoCertificate), err == nil && row.Status != credebl.X509Active:
		return nil
	case err != nil:
		return failed("read the certificate row", err)
	}
	leaf, err := x509.ParseCertificate(certificateDER(rec.Chain[0]))
	if err != nil {
		return connect.NewError(connect.CodeInternal, errors.New("the record of the chain is damaged"))
	}
	id.X5C = rec.Chain
	id.Identifiers = append(id.Identifiers, leaf.Subject.String())
	if id.Key == nil {
		id.Key = &backendv1.IssuerIdentity_Key{Backend: keyBackend}
	}
	if id.Key.Type == "" {
		id.Key.Type = x509KeyTypes[row.KeyType]
	}
	return nil
}
