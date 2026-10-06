// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"errors"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/sdjwt"
	"github.com/centre-for-dpi/vc-adapters/core/statuslist/token"
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
	case vc.FormatClaim169:
		return claim169SignatureOf(ctx, index, c, pc, ev)
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
	set, failed := issuerKeys(ctx, index, c.VC.Issuer, hdr.Kid, pc, ev)
	if failed != nil {
		return *failed
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

// issuerKeys resolves the keys of an issuer for one key id. It returns
// the result of the check when the keys are not there.
func issuerKeys(ctx context.Context, index int, issuer, kid string, pc Context, ev map[string]string) (jose.JWKS, *CheckResult) {
	fail := func(o Outcome, detail string, ev map[string]string) (jose.JWKS, *CheckResult) {
		r := result(NameSignature, o, index, detail, ev)
		return jose.JWKS{}, &r
	}
	if pc.Keys == nil {
		return fail(Error, "the service has no key resolver", ev)
	}
	set, err := pc.Keys(ctx, issuer, kid)
	if errors.Is(err, ErrStale) {
		return fail(Fail, staleKeysDetail, stale(ev))
	}
	if err != nil {
		return fail(Error, "the issuer keys are not available", ev)
	}
	return set, nil
}

// coseAlgorithms names the COSE algorithms of a Claim 169 code as the
// JOSE algorithms of the same keys (RFC 9053).
var coseAlgorithms = map[int64]jose.Algorithm{token.COSEAlgES256: jose.ES256, token.COSEAlgEdDSA: jose.EdDSA}

// claim169SignatureOf checks the COSE_Sign1 signature of a Claim 169
// code. The keys come from the issuer of the iss claim and the kid of the
// protected header, the same resolution as the issuer of a JWT.
func claim169SignatureOf(ctx context.Context, index int, c Credential, pc Context, ev map[string]string) CheckResult {
	s, err := vc.Claim169Signature([]byte(c.Token))
	if err != nil {
		return result(NameSignature, Fail, index, "the credential is not a signed CWT with claim 169", ev)
	}
	ev["alg"] = string(coseAlgorithms[s.Algorithm])
	ev["kid"] = s.KeyID
	set, failed := issuerKeys(ctx, index, c.VC.Issuer, s.KeyID, pc, ev)
	if failed != nil {
		return *failed
	}
	candidates := set.Keys
	if s.KeyID != "" {
		candidates = set.Key(s.KeyID)
	}
	if len(candidates) == 0 {
		return result(NameSignature, Error, index, "the issuer publishes no key with this key id", ev)
	}
	for _, k := range candidates {
		if token.KeyVerifier(k.Key)(s.Algorithm, nil, s.ToBeSigned, s.Signature) == nil {
			return result(NameSignature, Pass, index, "the issuer signature is valid", ev)
		}
	}
	return result(NameSignature, Fail, index, "the issuer signature is not valid", ev)
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
