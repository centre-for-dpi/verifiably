// Command mdl-pki-gen generates the mdoc issuance certificate chain a
// deployment needs, on first deploy, and emits it in the shapes the rest of
// the stack consumes.
//
// It writes four things into -out:
//
//	iaca.pem          the trust anchor an operator imports into a wallet
//	dsc.pem           the x5chain leaf
//	dsc-key.pem       the DSC private key, PKCS#8
//	issuer2.env       VERIFIABLY_ISSUER2_KEY_X/_Y/_D for the issuer config
//	issuer2-aux.env   VERIFIABLY_ISSUER2_CI_TOKEN_KEY /
//	                  VERIFIABLY_ISSUER2_CRED_ENCRYPTION_KEY — issuer-api2's
//	                  two internal service keys, unrelated to the DSC/IACA
//	                  chain but required by a hard docker-compose guard before
//	                  issuer-api2 will start at all. Generated and gated
//	                  independently of the chain below (see ensureAuxKeys) so
//	                  a deployment migrating in from before these existed
//	                  still gets them on its next `up`.
//
// The single thing this command exists to guarantee is that the key in
// issuer2.env and the public key inside dsc.pem are the same key. ISO 18013-5
// gives a verifier no source for the signing public key other than the
// x5chain leaf certificate, so a mismatch means every credential issued fails
// signature verification at every conformant reader — while issuing cleanly,
// with HTTP 200s and nothing in any log. That failure has already reached a
// live deployment of this stack once. Generating the key here and certifying
// that exact key (pki.GenerateDSCForKey) makes the two match by construction.
//
// It refuses to overwrite existing material, so a redeploy neither regenerates
// nor invalidates credentials already issued, and a deployment that drops in
// its own real certificates keeps them.
//
// The output is proof-of-concept material: every subject carries
// O=POC-DO-NOT-TRUST (pki.POCOrganization).
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/verifiably/verifiably-go/internal/mdl/pki"
)

// Validity mirrors internal/mdl/serversigner.go: the Annex B cap is 457 days
// for the DSC, and the DSC must not outlive its IACA, so the IACA gets longer.
const (
	iacaValidity = 3 * 365 * 24 * time.Hour
	dscValidity  = 457 * 24 * time.Hour
)

// Filenames written into the output directory.
const (
	iacaCertFile = "iaca.pem"
	iacaKeyFile  = "iaca-key.pem"
	dscCertFile  = "dsc.pem"
	dscKeyFile   = "dsc-key.pem"
	envFile      = "issuer2.env"
	auxEnvFile   = "issuer2-aux.env"
)

func main() {
	out := flag.String("out", "", "directory to write the generated material into (required)")
	country := flag.String("country", "DO", "countryName (C) in the certificate subject; must equal the mdoc's issuing_country")
	province := flag.String("province", "DO-01", "stateOrProvinceName (ST); must equal the mdoc's issuing_jurisdiction")
	authority := flag.String("authority", "VERIFIABLY POC", "issuing authority name used in the certificate common names")
	flag.Parse()

	if *out == "" {
		fatal(fmt.Errorf("-out is required"))
	}
	if *country == "" {
		fatal(fmt.Errorf("-country is required: @animo-id/mdoc cross-checks the mdoc's issuing_country against countryName"))
	}
	if err := run(*out, *country, *province, *authority); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "mdl-pki-gen: %v\n", err)
	os.Exit(1)
}

// run generates the chain unless material is already present, then ensures
// the two auxiliary service keys issuer-api2 needs to boot at all exist.
//
// Idempotence for the chain is keyed on the DSC certificate: if it exists,
// this is a redeploy and regenerating would invalidate every credential
// already issued under the old key. Same posture as
// seed_credential_issuer_catalog's cp -n. The auxiliary keys are gated
// independently (auxEnvFile's own existence) so a deployment that already has
// a DSC from before these were added still gets them generated on its next
// `up`, instead of staying permanently stuck on the hard docker-compose
// `:?` guard that requires them.
func run(outDir, country, province, authority string) error {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", outDir, err)
	}

	if err := ensureAuxKeys(outDir); err != nil {
		return err
	}

	dscPath := filepath.Join(outDir, dscCertFile)
	if _, err := os.Stat(dscPath); err == nil {
		fmt.Printf("mdl-pki-gen: %s already exists — keeping it\n", dscPath)
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat %s: %w", dscPath, err)
	}

	iacaKey, iaca, err := pki.GenerateIACAWithSubject(
		authority+" IACA", country, province, iacaValidity)
	if err != nil {
		return err
	}

	// Generate the DSC signing key HERE so the same key can be both certified
	// below and written to issuer2.env. pki.GenerateDSC would mint its own key
	// and hand it back, which works too — but going through GenerateDSCForKey
	// makes the binding explicit and impossible to get wrong by reordering.
	dscKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate DSC key: %w", err)
	}
	dsc, err := pki.GenerateDSCForKey(iacaKey, iaca, &dscKey.PublicKey, authority+" DSC", dscValidity)
	if err != nil {
		return err
	}

	// Belt and braces: prove the certificate really carries the key we are
	// about to write into the issuer config, and that it chains. A silent
	// mismatch here is precisely the bug this command exists to prevent, so it
	// is cheaper to assert than to debug from a rejected credential.
	if err := verifyKeyMatchesCert(dscKey, dsc, iaca); err != nil {
		return err
	}

	if err := writePEM(filepath.Join(outDir, iacaCertFile), "CERTIFICATE", iaca.Raw, 0o644); err != nil {
		return err
	}
	if err := writeKey(filepath.Join(outDir, iacaKeyFile), iacaKey); err != nil {
		return err
	}
	if err := writePEM(dscPath, "CERTIFICATE", dsc.Raw, 0o644); err != nil {
		return err
	}
	if err := writeKey(filepath.Join(outDir, dscKeyFile), dscKey); err != nil {
		return err
	}
	if err := writeEnv(filepath.Join(outDir, envFile), dscKey); err != nil {
		return err
	}

	fmt.Printf("mdl-pki-gen: generated %s (C=%s, ST=%s, O=%s)\n",
		dscPath, country, province, pki.POCOrganization)
	fmt.Printf("mdl-pki-gen: IACA trust anchor: %s\n", filepath.Join(outDir, iacaCertFile))
	fmt.Printf("mdl-pki-gen: DSC expires %s (Annex B caps this at 457 days)\n",
		dsc.NotAfter.Format(time.RFC3339))
	return nil
}

// verifyKeyMatchesCert fails closed on the mismatch this command prevents.
func verifyKeyMatchesCert(key *ecdsa.PrivateKey, dsc, iaca *x509.Certificate) error {
	pub, ok := dsc.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("DSC public key is %T, want *ecdsa.PublicKey", dsc.PublicKey)
	}
	if !pub.Equal(&key.PublicKey) {
		return fmt.Errorf("generated DSC does not certify the generated key — " +
			"credentials signed with it would fail verification everywhere")
	}
	pool := x509.NewCertPool()
	pool.AddCert(iaca)
	if _, err := dsc.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("generated DSC does not chain to its IACA: %w", err)
	}
	return nil
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	buf := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if buf == nil {
		return fmt.Errorf("encode %s for %s", blockType, path)
	}
	if err := os.WriteFile(path, buf, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// writeKey writes a private key as PKCS#8, owner-readable only.
func writeKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal key for %s: %w", path, err)
	}
	return writePEM(path, "PRIVATE KEY", der, 0o600)
}

// writeEnv emits the three coordinates issuer2-profiles.conf substitutes into
// defaultIssuerKey.jwk.
//
// Three separate base64url variables, NOT one JWK JSON blob: that config needs
// defaultIssuerKey.jwk to be a HOCON object, and a substituted env var is
// always a string — HOCON never re-parses it as JSON. The blob form boots
// cleanly and shows up correctly in GET /issuer2/profiles, then fails every
// credential request with `500 {"error":"server_error"}`. See the comment
// above defaultIssuerKey in deploy/k8s/config/issuer2/issuer2-profiles.conf.
func writeEnv(path string, key *ecdsa.PrivateKey) error {
	// Left-pad to the P-256 field size: FillBytes gives fixed-width big-endian
	// coordinates, which is what JWK requires. Raw Bytes() would drop leading
	// zero bytes and produce a coordinate that some parsers reject.
	const coordLen = 32
	x := make([]byte, coordLen)
	y := make([]byte, coordLen)
	d := make([]byte, coordLen)
	key.X.FillBytes(x)
	key.Y.FillBytes(y)
	key.D.FillBytes(d)

	b64 := base64.RawURLEncoding.EncodeToString
	body := fmt.Sprintf(""+
		"VERIFIABLY_ISSUER2_KEY_X=%s\n"+
		"VERIFIABLY_ISSUER2_KEY_Y=%s\n"+
		"VERIFIABLY_ISSUER2_KEY_D=%s\n",
		b64(x), b64(y), b64(d))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// ensureAuxKeys generates issuer-api2's two service-signing/-encryption keys
// on first run and writes them to auxEnvFile — VERIFIABLY_ISSUER2_CI_TOKEN_KEY
// and VERIFIABLY_ISSUER2_CRED_ENCRYPTION_KEY, both required by a hard `:?`
// guard in docker-compose.yml before issuer-api2 will even start.
//
// Unlike the DSC signing key (writeEnv), these are NOT bound to anything a
// wallet or verifier ever inspects — issuer-api2 uses them purely internally
// (signing its own CI token, encrypting credential response payloads), so
// there is no cross-check requiring them to stay stable in the way the
// DSC/wallet trust relationship does. Skipping generation once auxEnvFile
// exists is still the right default (an operator who set these by hand in
// .env must not be silently overridden), matching the DSC gate's posture.
//
// Shape: each value is the FULL {"type":"jwk","jwk":{...}} wrapper object
// serialized to one JSON line — a HOCON string, not a bare JWK — see the
// shape comment on VERIFIABLY_ISSUER2_CI_TOKEN_KEY in
// deploy/compose/stack/.env.example for why. deploy.sh's set_env_var already
// quotes values it writes into .env, so the single-quoting that file's
// comment warns an operator to do by hand is not needed on this path.
func ensureAuxKeys(outDir string) error {
	path := filepath.Join(outDir, auxEnvFile)
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	ciTokenKey, err := jwkWrapper()
	if err != nil {
		return fmt.Errorf("generate ciTokenKey: %w", err)
	}
	credEncKey, err := jwkWrapper()
	if err != nil {
		return fmt.Errorf("generate credentialEncryptionKey: %w", err)
	}

	body := fmt.Sprintf(""+
		"VERIFIABLY_ISSUER2_CI_TOKEN_KEY=%s\n"+
		"VERIFIABLY_ISSUER2_CRED_ENCRYPTION_KEY=%s\n",
		ciTokenKey, credEncKey)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Printf("mdl-pki-gen: generated %s (issuer-api2 service keys)\n", path)
	return nil
}

// jwkWrapper generates one fresh EC P-256 key and serializes it as the
// {"type":"jwk","jwk":{...}} wrapper object issuer-api2's ciTokenKey and
// credentialEncryptionKey fields both expect, on one line, keys in a fixed
// order so the output is deterministic given the same key (not that anything
// currently depends on that, but it costs nothing and helps diffing).
func jwkWrapper() (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	const coordLen = 32
	x := make([]byte, coordLen)
	y := make([]byte, coordLen)
	d := make([]byte, coordLen)
	key.X.FillBytes(x)
	key.Y.FillBytes(y)
	key.D.FillBytes(d)
	b64 := base64.RawURLEncoding.EncodeToString

	type jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
		D   string `json:"d"`
	}
	type wrapper struct {
		Type string `json:"type"`
		JWK  jwk    `json:"jwk"`
	}
	out, err := json.Marshal(wrapper{
		Type: "jwk",
		JWK: jwk{
			Kty: "EC", Crv: "P-256",
			X: b64(x), Y: b64(y), D: b64(d),
		},
	})
	if err != nil {
		return "", err
	}
	return string(out), nil
}
