// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/did"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/sdjwt"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

// CarrierOID4VP is the carrier word of an OID4VP answer. Holder binding
// applies to such an answer only: a pasted or scanned credential is no
// presentation.
const CarrierOID4VP = "oid4vp"

// CarrierClaim169 is the carrier word of an identity QR code that holds
// a CWT with claim 169.
const CarrierClaim169 = "claim169"

// ParamRequireHolderBinding is the parameter of the key binding check
// that turns the holder binding rule on or off (ADR-083 decision 1).
const ParamRequireHolderBinding = "require_holder_binding"

// The details of the holder binding rule (ADR-083 decision 2).
const (
	// NoHolderBinding is the reason of an unbound answer.
	NoHolderBinding = "the presentation carries no holder binding"
	// StackCheckedBinding names a stack verifier that checked the
	// binding of an answer VCA cannot see.
	StackCheckedBinding = "the stack verifier checked the holder binding"
	// mdocDeviceSkip names an mDoc with a device signature.
	mdocDeviceSkip = "VCA does not check the device signature of an mDoc; the stack verifier does"
)

// keyBinding checks the holder binding of every credential (ADR-024
// decision 2, ADR-083, RFC 9901): the SD-JWT disclosure digests and key
// binding JWT, the VP JWT around a jwt_vc_json credential, and the
// device signature of an mDoc. An OID4VP answer in a format that can
// carry holder binding fails without it, unless the policy set turns
// the rule off. The audience and the nonce are the work of the audience
// check and the nonce check, so this check ignores them.
func keyBinding(_ context.Context, p Presentation, pc Context) []CheckResult {
	if len(p.Credentials) == 0 {
		return noCredentials(NameKeyBinding)
	}
	out := make([]CheckResult, 0, len(p.Credentials))
	for i, c := range p.Credentials {
		out = append(out, keyBindingOf(i, c, p, pc))
	}
	return out
}

// unbound decides an answer that carries no holder binding: a FAIL when
// the rule applies, the stack note when a stack verifier checked it,
// else the result of the format.
func unbound(index int, p Presentation, pc Context, ev map[string]string, otherwise CheckResult) CheckResult {
	if p.Carrier != CarrierOID4VP || pc.Param(ParamRequireHolderBinding, "true") == "false" {
		return otherwise
	}
	if p.Holder != nil && p.Holder.Confirmed {
		return result(NameKeyBinding, Skip, index, StackCheckedBinding, ev)
	}
	return result(NameKeyBinding, Fail, index, NoHolderBinding, ev)
}

func keyBindingOf(index int, c Credential, p Presentation, pc Context) CheckResult {
	ev := map[string]string{"format": string(c.Format)}
	switch c.Format {
	case vc.FormatSDJWT:
	case vc.FormatJWT:
		return vpBinding(index, c, p, pc, ev)
	case vc.FormatMdoc:
		if vc.MdocDeviceSigned([]byte(c.Token)) {
			return result(NameKeyBinding, Skip, index, mdocDeviceSkip, ev)
		}
		return unbound(index, p, pc, ev, result(NameKeyBinding, Skip, index, "the mDoc carries no device signature", ev))
	default:
		return result(NameKeyBinding, Skip, index, "the credential format carries no holder binding that VCA checks", ev)
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
			return unbound(index, p, pc, ev, result(NameKeyBinding, Skip, index, "the credential names no holder key", ev))
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

// vpBinding checks the VP JWT that carries a jwt_vc_json credential:
// the holder key of the credential signs it, it names the holder, and it
// is not dated in the future.
func vpBinding(index int, c Credential, p Presentation, pc Context, ev map[string]string) CheckResult {
	envelope, ok := envelopeOf(c, p)
	if !ok {
		return unbound(index, p, pc, ev, result(NameKeyBinding, Skip, index, "the answer carries the JWT credential without a VP JWT", ev))
	}
	key, holder, ok := jwtHolder(c)
	if !ok {
		return result(NameKeyBinding, Fail, index, "the credential names no holder key", ev)
	}
	raw, _, err := jose.Verify(envelope, key.Key, jose.SigningAlgorithms)
	if err != nil {
		return result(NameKeyBinding, Fail, index, "the presentation signature is not valid", ev)
	}
	var vp struct {
		Iss string  `json:"iss"`
		Iat float64 `json:"iat"`
	}
	// The envelope parsed once in envelopeOf, so its payload decodes.
	anyval.Discard(json.Unmarshal(raw, &vp))
	if holder != "" && vp.Iss != holder {
		return result(NameKeyBinding, Fail, index, "the presentation names another holder", ev)
	}
	if time.Unix(int64(vp.Iat), 0).After(pc.At().Add(pc.Skew())) {
		return result(NameKeyBinding, Fail, index, "the presentation is dated in the future", ev)
	}
	return result(NameKeyBinding, Pass, index, "the holder signed the presentation", ev)
}

// envelopeOf returns the VP JWT of the answer that carries the token of
// a credential.
func envelopeOf(c Credential, p Presentation) (string, bool) {
	for _, env := range p.Envelopes {
		payload, err := jose.PeekPayload(env)
		if err != nil {
			continue
		}
		vp, isMap := payload["vp"].(map[string]any)
		if isMap && slices.Contains(vc.AsStringSlice(vp["verifiableCredential"]), c.Token) {
			return env, true
		}
	}
	return "", false
}

// envelopeClaim reads one claim of the VP JWT that carries a JWT
// credential. An audience list gives its first entry that equals want.
func envelopeClaim(c Credential, p Presentation, name, want string) (string, bool) {
	env, ok := envelopeOf(c, p)
	if !ok {
		return "", false
	}
	// envelopeOf read the payload once, so it reads again.
	payload := anyval.Must(jose.PeekPayload(env))
	if list := vc.AsStringSlice(payload[name]); len(list) > 1 && slices.Contains(list, want) {
		return want, true
	}
	v, ok := payload[name].(string)
	return v, ok
}

// jwtHolder returns the holder key of a JWT credential and its holder
// id: cnf.jwk, else the key of a did:jwk or did:key subject.
func jwtHolder(c Credential) (jose.JWK, string, bool) {
	payload, err := jose.PeekPayload(c.Token)
	if err != nil {
		return jose.JWK{}, "", false
	}
	subject := c.VC.SubjectID
	if key, ok := holderKey(payload); ok {
		return key, subject, true
	}
	doc, err := did.KeyDocument(subject)
	if err != nil {
		if doc, err = did.JWKDocument(subject); err != nil {
			return jose.JWK{}, "", false
		}
	}
	// Both documents hold a JWK that parsed, so the key always reads.
	pub := anyval.Must(did.PublicKey(doc.VerificationMethod[0]))
	return jose.JWK{Key: pub}, subject, true
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
	if got := anyval.As[string](kb["sd_hash"]); got != want {
		return "the key binding JWT does not cover the disclosures"
	}
	return ""
}
