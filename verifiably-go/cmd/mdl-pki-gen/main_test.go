package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readEnvCoords parses the generated issuer2.env into its three coordinates.
func readEnvCoords(t *testing.T, dir string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, envFile))
	if err != nil {
		t.Fatalf("read env: %v", err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			t.Fatalf("malformed env line %q", line)
		}
		out[k] = v
	}
	return out
}

// readCert loads a PEM certificate written by the generator.
func readCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("%s is not a PEM certificate", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return cert
}

// TestGeneratedKeyMatchesTheCertifiedKey is the test this whole command exists
// for.
//
// The x5chain leaf is the ONLY place ISO 18013-5 lets a verifier get the
// signing public key. issuer-api2 signs with VERIFIABLY_ISSUER2_KEY_X/_Y/_D.
// If the key those coordinates describe is not the key inside dsc.pem, every
// credential issues cleanly and fails verification at every conformant reader,
// with no error logged anywhere. A live deployment shipped exactly that
// mismatch (walt.id's published example certificate over an operator key) and
// the only symptom was a wallet saying "No trusted certificate was found".
//
// So: reconstruct the public key from the env coordinates and require it to
// equal the certificate's.
func TestGeneratedKeyMatchesTheCertifiedKey(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "DO", "DO-01", "TEST AUTH"); err != nil {
		t.Fatalf("run: %v", err)
	}

	env := readEnvCoords(t, dir)
	decode := func(name string) *big.Int {
		b, err := base64.RawURLEncoding.DecodeString(env[name])
		if err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		if len(b) != 32 {
			t.Errorf("%s decodes to %d bytes, want 32 — JWK P-256 coordinates "+
				"must be fixed-width, left-padded", name, len(b))
		}
		return new(big.Int).SetBytes(b)
	}
	fromEnv := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     decode("VERIFIABLY_ISSUER2_KEY_X"),
		Y:     decode("VERIFIABLY_ISSUER2_KEY_Y"),
	}

	dsc := readCert(t, filepath.Join(dir, dscCertFile))
	certPub, ok := dsc.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("DSC public key is %T", dsc.PublicKey)
	}
	if !certPub.Equal(fromEnv) {
		t.Fatal("the key in issuer2.env is NOT the key certified by dsc.pem — " +
			"every credential signed with it would fail verification everywhere, silently")
	}

	// The private scalar must belong to the same key, or signing fails outright.
	d := decode("VERIFIABLY_ISSUER2_KEY_D")
	derivedX, derivedY := elliptic.P256().ScalarBaseMult(d.Bytes())
	if derivedX.Cmp(certPub.X) != 0 || derivedY.Cmp(certPub.Y) != 0 {
		t.Error("VERIFIABLY_ISSUER2_KEY_D is not the private scalar for the certified public key")
	}
}

// TestGeneratedChainVerifies pins that the DSC chains to the IACA an operator
// would import as a wallet trust anchor.
func TestGeneratedChainVerifies(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "DO", "DO-01", "TEST AUTH"); err != nil {
		t.Fatalf("run: %v", err)
	}
	iaca := readCert(t, filepath.Join(dir, iacaCertFile))
	dsc := readCert(t, filepath.Join(dir, dscCertFile))

	pool := x509.NewCertPool()
	pool.AddCert(iaca)
	if _, err := dsc.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Errorf("DSC must chain to the IACA an operator imports as trust anchor: %v", err)
	}
}

// TestSubjectCarriesCountryAndProvince guards the @animo-id/mdoc cross-check.
// Wallets compare issuing_country to countryName and issuing_jurisdiction to
// stateOrProvinceName; a mismatch is a rejection at accept time.
func TestSubjectCarriesCountryAndProvince(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "NL", "NL-ZH", "TEST AUTH"); err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, name := range []string{iacaCertFile, dscCertFile} {
		cert := readCert(t, filepath.Join(dir, name))
		if len(cert.Subject.Country) == 0 || cert.Subject.Country[0] != "NL" {
			t.Errorf("%s countryName = %v, want [NL]", name, cert.Subject.Country)
		}
		if len(cert.Subject.Province) == 0 || cert.Subject.Province[0] != "NL-ZH" {
			t.Errorf("%s stateOrProvinceName = %v, want [NL-ZH]", name, cert.Subject.Province)
		}
	}
}

// TestGeneratedMaterialIsMarkedPOC keeps generated certificates from being
// mistaken for a real PKI.
func TestGeneratedMaterialIsMarkedPOC(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "DO", "DO-01", "TEST AUTH"); err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, name := range []string{iacaCertFile, dscCertFile} {
		cert := readCert(t, filepath.Join(dir, name))
		found := false
		for _, o := range cert.Subject.Organization {
			if o == "POC-DO-NOT-TRUST" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s subject must carry O=POC-DO-NOT-TRUST, got %v", name, cert.Subject.Organization)
		}
	}
}

// TestSecondRunDoesNotRegenerate is the idempotence guard.
//
// Regenerating on a redeploy would swap the signing key under credentials
// already in citizens' wallets: those carry the OLD DSC in their x5chain and
// would keep verifying, but the issuer would start signing with a key no
// longer matching what it advertises. A deploy script runs on every deploy, so
// this has to hold.
func TestSecondRunDoesNotRegenerate(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "DO", "DO-01", "TEST AUTH"); err != nil {
		t.Fatalf("first run: %v", err)
	}
	before := readCert(t, filepath.Join(dir, dscCertFile))
	envBefore := readEnvCoords(t, dir)

	if err := run(dir, "DO", "DO-01", "TEST AUTH"); err != nil {
		t.Fatalf("second run: %v", err)
	}
	after := readCert(t, filepath.Join(dir, dscCertFile))
	envAfter := readEnvCoords(t, dir)

	if before.SerialNumber.Cmp(after.SerialNumber) != 0 {
		t.Error("second run replaced the DSC — credentials already issued would " +
			"be signed by a key the issuer no longer holds")
	}
	for k, v := range envBefore {
		if envAfter[k] != v {
			t.Errorf("second run changed %s", k)
		}
	}
}

// TestOperatorSuppliedCertificateIsNotOverwritten covers the deployment that
// brings its own real PKI. Generated material must never clobber it.
func TestOperatorSuppliedCertificateIsNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	own := []byte("-----BEGIN CERTIFICATE-----\nthe operator's real DSC\n-----END CERTIFICATE-----\n")
	if err := os.WriteFile(filepath.Join(dir, dscCertFile), own, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := run(dir, "DO", "DO-01", "TEST AUTH"); err != nil {
		t.Fatalf("run: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, dscCertFile))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != string(own) {
		t.Error("run() overwrote an operator-supplied certificate")
	}
	if _, err := os.Stat(filepath.Join(dir, envFile)); !os.IsNotExist(err) {
		t.Error("run() wrote issuer2.env alongside an operator-supplied certificate — " +
			"that would point the issuer at a key the operator's certificate does not cover")
	}
}

// readAuxEnv parses the generated issuer2-aux.env into its two JWK-wrapper values.
func readAuxEnv(t *testing.T, dir string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, auxEnvFile))
	if err != nil {
		t.Fatalf("read aux env: %v", err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("malformed aux env line %q", line)
		}
		out[k] = v
	}
	return out
}

// TestAuxKeysAreValidJWKWrappers pins the shape issuer-api2's HOCON config
// requires: {"type":"jwk","jwk":{"kty":"EC","crv":"P-256","x":...,"y":...,"d":...}}
// as one JSON string, not a bare JWK — see the shape comment on
// VERIFIABLY_ISSUER2_CI_TOKEN_KEY in deploy/compose/stack/.env.example for why
// getting this wrong fails HOCON parsing at boot in a way that looks unrelated.
func TestAuxKeysAreValidJWKWrappers(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "DO", "DO-01", "TEST AUTH"); err != nil {
		t.Fatalf("run: %v", err)
	}
	env := readAuxEnv(t, dir)
	for _, name := range []string{"VERIFIABLY_ISSUER2_CI_TOKEN_KEY", "VERIFIABLY_ISSUER2_CRED_ENCRYPTION_KEY"} {
		raw, ok := env[name]
		if !ok {
			t.Fatalf("%s missing from %s", name, auxEnvFile)
		}
		var w struct {
			Type string `json:"type"`
			JWK  struct {
				Kty, Crv, X, Y, D string
			} `json:"jwk"`
		}
		if err := json.Unmarshal([]byte(raw), &w); err != nil {
			t.Fatalf("%s is not valid JSON: %v — raw: %s", name, err, raw)
		}
		if w.Type != "jwk" {
			t.Errorf("%s: type = %q, want %q", name, w.Type, "jwk")
		}
		if w.JWK.Kty != "EC" || w.JWK.Crv != "P-256" {
			t.Errorf("%s: jwk.kty/crv = %q/%q, want EC/P-256", name, w.JWK.Kty, w.JWK.Crv)
		}
		for field, v := range map[string]string{"x": w.JWK.X, "y": w.JWK.Y, "d": w.JWK.D} {
			b, err := base64.RawURLEncoding.DecodeString(v)
			if err != nil {
				t.Errorf("%s: jwk.%s is not valid base64url: %v", name, field, err)
				continue
			}
			if len(b) != 32 {
				t.Errorf("%s: jwk.%s decodes to %d bytes, want 32", name, field, len(b))
			}
		}
	}
	if env["VERIFIABLY_ISSUER2_CI_TOKEN_KEY"] == env["VERIFIABLY_ISSUER2_CRED_ENCRYPTION_KEY"] {
		t.Error("ciTokenKey and credentialEncryptionKey must be independently generated keys, got identical values")
	}
}

// TestAuxKeysSurviveASecondRun is the idempotence guard for the two service
// keys, mirroring TestSecondRunDoesNotRegenerate for the DSC/IACA pair.
func TestAuxKeysSurviveASecondRun(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "DO", "DO-01", "TEST AUTH"); err != nil {
		t.Fatalf("first run: %v", err)
	}
	before := readAuxEnv(t, dir)

	if err := run(dir, "DO", "DO-01", "TEST AUTH"); err != nil {
		t.Fatalf("second run: %v", err)
	}
	after := readAuxEnv(t, dir)

	for k, v := range before {
		if after[k] != v {
			t.Errorf("second run changed %s — issuer-api2 would start signing/encrypting "+
				"with a different key than it advertised before", k)
		}
	}
}

// TestAuxKeysGeneratedForAnOperatorSuppliedCertificate covers the migration
// case the plan for this fix exists to close: a deployment that already has
// its own real DSC (predating issuer2-aux.env) must still get the two aux
// keys generated — unlike issuer2.env (see
// TestOperatorSuppliedCertificateIsNotOverwritten below), which is correctly
// skipped there because it is meaningless without a certificate covering it.
// The aux keys have no such relationship to the DSC, so gating them on it
// would leave that deployment permanently unable to satisfy docker-compose's
// hard VERIFIABLY_ISSUER2_CI_TOKEN_KEY / _CRED_ENCRYPTION_KEY requirement.
func TestAuxKeysGeneratedForAnOperatorSuppliedCertificate(t *testing.T) {
	dir := t.TempDir()
	own := []byte("-----BEGIN CERTIFICATE-----\nthe operator's real DSC\n-----END CERTIFICATE-----\n")
	if err := os.WriteFile(filepath.Join(dir, dscCertFile), own, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := run(dir, "DO", "DO-01", "TEST AUTH"); err != nil {
		t.Fatalf("run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, auxEnvFile)); err != nil {
		t.Errorf("%s not generated alongside an operator-supplied DSC — issuer-api2 "+
			"would refuse to start (docker-compose requires these keys unconditionally): %v",
			auxEnvFile, err)
	}
}

// TestPrivateKeyFilesAreNotWorldReadable — these are signing keys.
func TestPrivateKeyFilesAreNotWorldReadable(t *testing.T) {
	if os.Getenv("GOOS") == "windows" {
		t.Skip("POSIX modes are not meaningful on Windows")
	}
	dir := t.TempDir()
	if err := run(dir, "DO", "DO-01", "TEST AUTH"); err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, name := range []string{dscKeyFile, iacaKeyFile, envFile, auxEnvFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if mode := info.Mode().Perm(); mode&0o077 != 0 {
			t.Errorf("%s mode is %o, want no group/other access", name, mode)
		}
	}
}
