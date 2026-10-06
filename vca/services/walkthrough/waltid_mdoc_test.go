// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package walkthrough_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
)

// The mDoc part of the double of the walt.id issuer API 0.18.2:
//
//	POST /openid4vc/mdoc/issue
//	POST /draft13/credential with the format mso_mdoc
//
// walt.id takes no doctype in the issue request. The wallet names it in
// its credential request, from the entry of the issuer metadata, and
// the issuer API refuses a request whose doctype is not the one of the
// entry of the offer (CIProvider.findMatchingIssuanceRequest). It then
// signs the doctype of the request into the mobile security object, and
// the claims of mdocData under their namespaces. The issuer key must be
// an EC key, as walt.id turns it into a P-256 COSE key. The answer is
// the IssuerSigned structure as base64url (doGenerateMDoc), and the
// session event generated_mdoc carries the same bytes in hex.

// mdocConfiguration is the entry of the mDoc in the catalogue of vca
// setup.
const mdocConfiguration = "vca_mso_mdoc"

// catalogueDoctype reads the doctype of the mDoc entry from the
// catalogue fixture of the adapter, which follows the file vca setup
// writes.
func catalogueDoctype() (string, error) {
	raw, err := os.ReadFile(filepath.Join("..", "dpg-adapter-waltid", "testdata", "doc", "issuer-metadata-vca.json"))
	if err != nil {
		return "", err
	}
	var doc struct {
		Configurations map[string]struct {
			Doctype string `json:"doctype"`
		} `json:"credential_configurations_supported"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", err
	}
	if d := doc.Configurations[mdocConfiguration].Doctype; d != "" {
		return d, nil
	}
	return "", errors.New("the catalogue names no doctype for the mDoc entry")
}

// mdocCredential answers the credential request of an mDoc offer.
func (w *waltidIssuer) mdocCredential(rw http.ResponseWriter, o *waltidOffer, body []byte, holder map[string]any) {
	var req struct {
		Format  string `json:"format"`
		Doctype string `json:"doctype"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	want, err := catalogueDoctype()
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	if req.Format != "mso_mdoc" || req.Doctype != want {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		writeJSON(rw, map[string]any{"error": "invalid_request",
			"error_description": fmt.Sprintf("No matching issuance request found: the request names %q %q", req.Format, req.Doctype)})
		return
	}
	if holder == nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		writeJSON(rw, map[string]any{"error": "invalid_or_missing_proof"})
		return
	}
	signed, err := o.signMdoc(time.Now(), req.Doctype, holder)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	w.event(o, "generated_mdoc", map[string]any{"mdoc": hex.EncodeToString(signed)})
	w.event(o, "issuance_status", map[string]any{"status": "SUCCESSFUL"})
	writeJSON(rw, map[string]any{"credential": base64.RawURLEncoding.EncodeToString(signed), "credential_encoding": "issuer-signed"})
}

// signMdoc builds the IssuerSigned structure of ISO/IEC 18013-5: one
// IssuerSignedItem per claim of mdocData, and the mobile security object
// with the digest of each item, the device key of the holder, the
// doctype and the validity, signed with the issuer key as COSE_Sign1.
func (o *waltidOffer) signMdoc(now time.Time, doctype string, holder map[string]any) ([]byte, error) {
	jwk, err := jose.ParseJWK(o.request.IssuerKey.JWK)
	if err != nil {
		return nil, err
	}
	key, ok := jwk.Key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("walt.id signs an mDoc with an EC key, not %T", jwk.Key)
	}
	deviceKey, err := coseKey(holder)
	if err != nil {
		return nil, err
	}
	spaces := map[string][]cbor.Tag{}
	digests := map[string]map[uint64][]byte{}
	var id uint64
	for _, ns := range sortedKeys(o.request.MdocData) {
		digests[ns] = map[uint64][]byte{}
		for _, name := range sortedKeys(o.request.MdocData[ns]) {
			tag, encoded, ierr := signedItem(id, name, o.request.MdocData[ns][name])
			if ierr != nil {
				return nil, ierr
			}
			sum := sha256.Sum256(encoded)
			digests[ns][id] = sum[:]
			spaces[ns] = append(spaces[ns], tag)
			id++
		}
	}
	tdate := func(t time.Time) cbor.Tag { return cbor.Tag{Number: 0, Content: t.UTC().Format(time.RFC3339)} }
	mso, err := cbor.Marshal(map[string]any{
		"version": "1.0", "digestAlgorithm": "SHA-256", "valueDigests": digests,
		"deviceKeyInfo": map[string]any{"deviceKey": deviceKey}, "docType": doctype,
		"validityInfo": map[string]any{"signed": tdate(now), "validFrom": tdate(now), "validUntil": tdate(now.Add(365 * 24 * time.Hour))},
	})
	if err != nil {
		return nil, err
	}
	payload, err := cbor.Marshal(cbor.Tag{Number: 24, Content: mso})
	if err != nil {
		return nil, err
	}
	protected, err := cbor.Marshal(map[int]any{1: -7})
	if err != nil {
		return nil, err
	}
	toSign, err := cbor.Marshal([]any{"Signature1", protected, []byte{}, payload})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(toSign)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return cbor.Marshal(map[string]any{
		"nameSpaces": spaces,
		"issuerAuth": []any{protected, map[int]any{}, payload, sig},
	})
}

// signedItem returns one IssuerSignedItem with a random salt, as the
// tag 24 the namespaces hold and as the bytes of its digest.
func signedItem(id uint64, name string, value any) (cbor.Tag, []byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return cbor.Tag{}, nil, err
	}
	item, err := cbor.Marshal(map[string]any{"digestID": id, "random": salt, "elementIdentifier": name, "elementValue": value})
	if err != nil {
		return cbor.Tag{}, nil, err
	}
	tag := cbor.Tag{Number: 24, Content: item}
	encoded, err := cbor.Marshal(tag)
	return tag, encoded, err
}

// coseKey turns the P-256 JWK of a proof into a COSE key (RFC 9053).
func coseKey(jwk map[string]any) (map[int]any, error) {
	x, xerr := base64.RawURLEncoding.DecodeString(fmt.Sprint(jwk["x"]))
	y, yerr := base64.RawURLEncoding.DecodeString(fmt.Sprint(jwk["y"]))
	if jwk["kty"] != "EC" || jwk["crv"] != "P-256" || xerr != nil || yerr != nil {
		return nil, errors.New("the proof key is not an EC P-256 key")
	}
	return map[int]any{1: 2, -1: 1, -2: x, -3: y}, nil
}

// sortedKeys returns the keys of a map in order, so the items keep one
// order.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
