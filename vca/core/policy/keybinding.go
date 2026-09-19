// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"encoding/json"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/sdjwt"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

// keyBinding checks the SD-JWT disclosure digests and the key binding
// JWT of every credential (ADR-024 decision 2, RFC 9901).
// The audience and the nonce of the key binding JWT are the work of the
// audience check and the nonce check, so this check ignores them.
func keyBinding(_ context.Context, p Presentation, pc Context) []CheckResult {
	if len(p.Credentials) == 0 {
		return noCredentials(NameKeyBinding)
	}
	out := make([]CheckResult, 0, len(p.Credentials))
	for i, c := range p.Credentials {
		out = append(out, keyBindingOf(i, c, pc))
	}
	return out
}

func keyBindingOf(index int, c Credential, pc Context) CheckResult {
	ev := map[string]string{"format": string(c.Format)}
	if c.Format != vc.FormatSDJWT {
		return result(NameKeyBinding, Skip, index, "the credential is not an SD-JWT", ev)
	}
	pres, presErr := sdjwt.Parse(c.Token)
	if presErr != nil {
		return result(NameKeyBinding, Fail, index, "the SD-JWT does not parse", ev)
	}
	payload, payloadErr := jose.PeekPayload(pres.IssuerJWT)
	if payloadErr != nil {
		return result(NameKeyBinding, Fail, index, "the issuer JWT payload does not parse", ev)
	}
	if _, err := sdjwt.Resolve(payload, pres.Disclosures); err != nil {
		return result(NameKeyBinding, Fail, index, "a disclosure digest does not match the credential", ev)
	}
	holder, ok := holderKey(payload)
	if pres.KeyBindingJWT == "" {
		if !ok {
			return result(NameKeyBinding, Skip, index, "the credential names no holder key", ev)
		}
		return result(NameKeyBinding, Fail, index, "the presentation carries no key binding JWT", ev)
	}
	if !ok {
		return result(NameKeyBinding, Fail, index, "the credential names no holder key", ev)
	}
	raw, hdr, err := jose.Verify(pres.KeyBindingJWT, holder.Key, jose.SigningAlgorithms)
	if err != nil {
		return result(NameKeyBinding, Fail, index, "the key binding signature is not valid", ev)
	}
	if hdr.Typ != sdjwt.TypeKB {
		ev["typ"] = hdr.Typ
		return result(NameKeyBinding, Fail, index, "the key binding JWT has the wrong type", ev)
	}
	var kb map[string]any
	if err := json.Unmarshal(raw, &kb); err != nil {
		return result(NameKeyBinding, Fail, index, "the key binding payload does not parse", ev)
	}
	if detail := checkDigest(pres, payload, kb); detail != "" {
		return result(NameKeyBinding, Fail, index, detail, ev)
	}
	iat, ok := kb["iat"].(float64)
	if !ok {
		return result(NameKeyBinding, Fail, index, "the key binding JWT has no iat claim", ev)
	}
	if time.Unix(int64(iat), 0).After(pc.At().Add(pc.Skew())) {
		return result(NameKeyBinding, Fail, index, "the key binding JWT is dated in the future", ev)
	}
	return result(NameKeyBinding, Pass, index, "the holder proved control of the key", ev)
}

// holderKey reads cnf.jwk from the issuer claims.
func holderKey(payload map[string]any) (jose.JWK, bool) {
	cnf, ok := payload["cnf"].(map[string]any)
	if !ok {
		return jose.JWK{}, false
	}
	m, ok := cnf["jwk"].(map[string]any)
	if !ok {
		return jose.JWK{}, false
	}
	k, err := jose.JWKFromMap(m)
	if err != nil {
		return jose.JWK{}, false
	}
	return k, true
}

// checkDigest compares sd_hash with the digest of the presented parts.
// It returns an empty string when the digest matches.
func checkDigest(pres sdjwt.Presentation, payload, kb map[string]any) string {
	alg := sdjwt.DefaultAlg
	if a, ok := payload["_sd_alg"].(string); ok {
		alg = a
	}
	want, err := sdjwt.Digest(alg, sdjwt.Serialize(sdjwt.Presentation{
		IssuerJWT: pres.IssuerJWT, Disclosures: pres.Disclosures,
	}))
	if err != nil {
		return "the credential names an unknown digest algorithm"
	}
	if got, _ := kb["sd_hash"].(string); got != want {
		return "the key binding JWT does not cover the disclosures"
	}
	return ""
}
