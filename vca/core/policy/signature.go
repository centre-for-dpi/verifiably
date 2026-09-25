// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"errors"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/sdjwt"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

// notImplementedLDP is the detail of a Data Integrity proof. RDF
// canonicalisation is a follow-up, so the check reports SKIP
// (ADR-024 decision 2). See vca/docs/verifier-policy.md.
const notImplementedLDP = "not implemented: RDF canonicalisation"

// notImplementedMdoc is the detail of an ISO 18013-5 mdoc.
const notImplementedMdoc = "not implemented: mdoc COSE_Sign1 verification"

// signature checks the issuer signature of every credential. It does not
// look at the validity window, so the nbf and exp checks stay
// independent.
func signature(ctx context.Context, p Presentation, pc Context) []CheckResult {
	if len(p.Credentials) == 0 {
		return noCredentials(NameSignature)
	}
	out := make([]CheckResult, 0, len(p.Credentials))
	for i, c := range p.Credentials {
		out = append(out, signatureOf(ctx, i, c, pc))
	}
	return out
}

func signatureOf(ctx context.Context, index int, c Credential, pc Context) CheckResult {
	ev := map[string]string{"format": string(c.Format), "issuer": c.VC.Issuer}
	switch c.Format {
	case vc.FormatJSONLD:
		return result(NameSignature, Skip, index, notImplementedLDP, ev)
	case vc.FormatMdoc:
		return result(NameSignature, Skip, index, notImplementedMdoc, ev)
	case vc.FormatSDJWT, vc.FormatJWT:
	default:
		return result(NameSignature, Skip, index, "the credential carries no signed token", ev)
	}
	token, err := issuerToken(c)
	if err != nil {
		return result(NameSignature, Fail, index, "the credential is not a compact JWS", ev)
	}
	hdr, err := jose.PeekHeader(token)
	if err != nil {
		return result(NameSignature, Fail, index, "the token header does not parse", ev)
	}
	ev["alg"] = string(hdr.Alg)
	ev["kid"] = hdr.Kid
	if pc.Keys == nil {
		return result(NameSignature, Error, index, "the service has no key resolver", ev)
	}
	set, err := pc.Keys(ctx, c.VC.Issuer, hdr.Kid)
	if errors.Is(err, ErrStale) {
		return result(NameSignature, Fail, index, staleKeysDetail, stale(ev))
	}
	if err != nil {
		return result(NameSignature, Error, index, "the issuer keys are not available", ev)
	}
	_, _, err = jose.VerifyWithJWKS(token, set, jose.SigningAlgorithms)
	switch {
	case err == nil:
		return result(NameSignature, Pass, index, "the issuer signature is valid", ev)
	case errors.Is(err, jose.ErrNoKey):
		return result(NameSignature, Error, index, "the issuer publishes no key with this key id", ev)
	default:
		return result(NameSignature, Fail, index, "the issuer signature is not valid", ev)
	}
}

// issuerToken returns the compact JWS that carries the issuer claims.
func issuerToken(c Credential) (string, error) {
	if c.Format != vc.FormatSDJWT {
		return c.Token, nil
	}
	p, err := sdjwt.Parse(c.Token)
	if err != nil {
		return "", err
	}
	return p.IssuerJWT, nil
}
