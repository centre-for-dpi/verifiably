package statuslist

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/piprate/json-gold/ld"
)

// contextFS bundles the JSON-LD @context documents the status list VC references
// so URDNA2015 canonicalization is OFFLINE and DETERMINISTIC — the distroless
// runtime can't dereference remote contexts, and a network fetch would make the
// signature depend on w3.org/w3id.org being reachable + unchanged.
//
//go:embed contexts/credentials-v2.jsonld contexts/ed25519-2020-v1.jsonld
var contextFS embed.FS

var bundledContexts = map[string]string{
	"https://www.w3.org/ns/credentials/v2":             "contexts/credentials-v2.jsonld",
	"https://w3id.org/security/suites/ed25519-2020/v1": "contexts/ed25519-2020-v1.jsonld",
}

// bundledLoader serves the embedded @context documents, delegating anything
// unknown to a fallback loader.
type bundledLoader struct{ fallback ld.DocumentLoader }

func (l *bundledLoader) LoadDocument(u string) (*ld.RemoteDocument, error) {
	if path, ok := bundledContexts[u]; ok {
		raw, err := contextFS.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, err
		}
		return &ld.RemoteDocument{DocumentURL: u, Document: doc}, nil
	}
	if l.fallback != nil {
		return l.fallback.LoadDocument(u)
	}
	return nil, fmt.Errorf("statuslist: no bundled JSON-LD context for %s", u)
}

// b58Alphabet is the Bitcoin/IPFS base58 alphabet used by multibase base58btc
// (the "z" prefix) for did:key identifiers and Ed25519Signature2020 proofValues.
const b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(b []byte) string {
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	num := new(big.Int).SetBytes(b)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)
	var out []byte
	for num.Cmp(zero) > 0 {
		num.DivMod(num, base, mod)
		out = append(out, b58Alphabet[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		out = append(out, b58Alphabet[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// LDSigner signs a JSON-LD BitstringStatusListCredential with an
// Ed25519Signature2020 Data-Integrity proof. External verifiers — notably MOSIP
// Inji Verify — verify the status list VC's proof (its vcverifier NPEs on an
// unsigned list: "getFromJsonLDObject(...) must not be null"), so the JSON-LD
// serialization must carry one. The key is a persistent Ed25519 key whose
// did:key is self-resolving (no network), and Ed25519Signature2020 is exactly
// the suite MOSIP already verifies on Inji-issued credentials.
type LDSigner struct {
	priv ed25519.PrivateKey
	did  string // did:key:z6Mk…
	vm   string // verificationMethod = did:key#z6Mk…
	proc *ld.JsonLdProcessor
	opts *ld.JsonLdOptions
}

type persistedKey struct {
	Seed string `json:"seed"` // hex/base64 of the ed25519 seed (32 bytes)
}

// NewLDSigner loads (or creates + persists) the status-list Ed25519 key and
// derives its did:key. A caching document loader means the JSON-LD @contexts are
// fetched at most once per process.
func NewLDSigner(stateDir string) (*LDSigner, error) {
	priv, err := loadOrCreateEd25519(filepath.Join(stateDir, "status-list-ld-key.json"))
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	// did:key for Ed25519: multicodec 0xed01 prefix + raw public key, base58btc,
	// multibase "z". The verificationMethod repeats the multibase as the fragment.
	mb := "z" + base58Encode(append([]byte{0xed, 0x01}, pub...))
	did := "did:key:" + mb
	proc := ld.NewJsonLdProcessor()
	opts := ld.NewJsonLdOptions("")
	opts.Format = "application/n-quads"
	opts.Algorithm = "URDNA2015"
	opts.DocumentLoader = &bundledLoader{fallback: ld.NewDefaultDocumentLoader(nil)}
	return &LDSigner{priv: priv, did: did, vm: did + "#" + mb, proc: proc, opts: opts}, nil
}

// DID returns the did:key that issues (and secures) the status list VC.
func (s *LDSigner) DID() string { return s.did }

func (s *LDSigner) canonicalize(doc map[string]any) (string, error) {
	// Round-trip through JSON so every value is the map[string]interface{} /
	// []interface{} / string type json-gold's processor expects. A Go-typed
	// slice (e.g. the @context or type []string) is otherwise rejected as an
	// "invalid local context".
	b, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}
	var normalized any
	if err := json.Unmarshal(b, &normalized); err != nil {
		return "", err
	}
	nq, err := s.proc.Normalize(normalized, s.opts)
	if err != nil {
		return "", err
	}
	str, _ := nq.(string)
	return str, nil
}

// Sign returns a copy of vc with an Ed25519Signature2020 proof (URDNA2015
// canonicalization of the proof config + document, SHA-256 each, concatenated
// proofConfig-hash then document-hash, Ed25519-signed, multibase-base58btc
// proofValue). The vc's @context MUST include the ed25519-2020 suite context so
// the proof terms canonicalize.
func (s *LDSigner) Sign(vc map[string]any) (map[string]any, error) {
	doc := map[string]any{}
	for k, v := range vc {
		if k != "proof" {
			doc[k] = v
		}
	}
	created := time.Now().UTC().Format(time.RFC3339)
	proofConfig := map[string]any{
		"@context":           vc["@context"],
		"type":               "Ed25519Signature2020",
		"created":            created,
		"verificationMethod": s.vm,
		"proofPurpose":       "assertionMethod",
	}
	canonProof, err := s.canonicalize(proofConfig)
	if err != nil {
		return nil, fmt.Errorf("canonicalize proof config: %w", err)
	}
	canonDoc, err := s.canonicalize(doc)
	if err != nil {
		return nil, fmt.Errorf("canonicalize document: %w", err)
	}
	ph := sha256.Sum256([]byte(canonProof))
	dh := sha256.Sum256([]byte(canonDoc))
	sig := ed25519.Sign(s.priv, append(ph[:], dh[:]...))
	out := map[string]any{}
	for k, v := range vc {
		out[k] = v
	}
	out["proof"] = map[string]any{
		"type":               "Ed25519Signature2020",
		"created":            created,
		"verificationMethod": s.vm,
		"proofPurpose":       "assertionMethod",
		"proofValue":         "z" + base58Encode(sig),
	}
	return out, nil
}

func loadOrCreateEd25519(path string) (ed25519.PrivateKey, error) {
	if raw, err := os.ReadFile(path); err == nil {
		var pk persistedKey
		if json.Unmarshal(raw, &pk) == nil {
			if seed, err := decodeSeed(pk.Seed); err == nil && len(seed) == ed25519.SeedSize {
				return ed25519.NewKeyFromSeed(seed), nil
			}
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	seed := priv.Seed()
	blob, _ := json.Marshal(persistedKey{Seed: encodeSeed(seed)})
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err == nil {
		_ = os.WriteFile(path, blob, 0o600)
	}
	return priv, nil
}

func encodeSeed(b []byte) string { return base58Encode(b) }

func decodeSeed(s string) ([]byte, error) {
	num := new(big.Int)
	for _, c := range s {
		idx := -1
		for i := 0; i < len(b58Alphabet); i++ {
			if rune(b58Alphabet[i]) == c {
				idx = i
				break
			}
		}
		if idx < 0 {
			return nil, fmt.Errorf("invalid base58 char %q", c)
		}
		num.Mul(num, big.NewInt(58))
		num.Add(num, big.NewInt(int64(idx)))
	}
	b := num.Bytes()
	// restore leading zero bytes (base58 leading '1's)
	zeros := 0
	for zeros < len(s) && s[zeros] == b58Alphabet[0] {
		zeros++
	}
	if zeros > 0 {
		b = append(make([]byte, zeros), b...)
	}
	return b, nil
}
