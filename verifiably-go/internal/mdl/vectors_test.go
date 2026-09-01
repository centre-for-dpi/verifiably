package mdl

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/verifiably/verifiably-go/internal/mdl/pki"
	"github.com/verifiably/verifiably-go/internal/signer"
)

// Validity of the certificates baked into the interop vectors.
//
// The first cut used 90/30 days, which meant the vectors — and the fixtures
// copied into cdpi-wallet and the reader app — would start failing about a
// month after generation, with a chain error that reads like a code
// regression rather than an expiry.
//
// The DSC gets the Annex B maximum of 457 days. It cannot get more: the cap
// is normative and internal/mdl/pki enforces it. So the vectors DO expire by
// design, and TestVectorsHaveUsefulRemainingLife below fails while there is
// still time to regenerate them, instead of leaving it to a downstream repo
// to discover.
//
// The IACA gets longer still, since GenerateDSC also refuses to issue a DSC
// that would outlive its issuer.
const (
	dscVectorValidity  = 457 * 24 * time.Hour
	iacaVectorValidity = 3 * 365 * 24 * time.Hour

	// minRemainingLife is how much validity the committed vectors must have
	// left before the guard test starts demanding a refresh.
	minRemainingLife = 60 * 24 * time.Hour
)

// TestGenerateVectors writes the interop vectors other repos consume as
// fixtures. Run it with MDL_WRITE_VECTORS=1 -run TestGenerateVectors to
// refresh them; it is skipped in normal runs so CI does not churn the files.
//
// Only public material is written: the two certificates and the mdoc. The
// IACA and DSC private keys stay in memory and die with the process.
func TestGenerateVectors(t *testing.T) {
	if os.Getenv("MDL_WRITE_VECTORS") == "" {
		t.Skip("set MDL_WRITE_VECTORS=1 to regenerate interop vectors")
	}

	dir := filepath.Join("testdata", "vectors")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	iacaKey, iaca, err := pki.GenerateIACA("CDPI POC IACA", "DO", iacaVectorValidity)
	if err != nil {
		t.Fatalf("generate IACA: %v", err)
	}
	dscKey, dsc, err := pki.GenerateDSC(iacaKey, iaca, "CDPI POC DSC", dscVectorValidity)
	if err != nil {
		t.Fatalf("generate DSC: %v", err)
	}
	s, err := signer.NewSoftwareSigner(dscKey, []*x509.Certificate{dsc, iaca})
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	deviceKey, err := LoadTestDeviceKey()
	if err != nil {
		t.Fatalf("load device key: %v", err)
	}

	d := sampleLicence()
	is, err := Issue(context.Background(), s, d, deviceKey, d.ExpiryDate)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	em, err := EncMode()
	if err != nil {
		t.Fatalf("enc mode: %v", err)
	}
	encoded, err := em.Marshal(is)
	if err != nil {
		t.Fatalf("marshal IssuerSigned: %v", err)
	}

	writeVector(t, filepath.Join(dir, "mdl_full.cbor"), encoded)
	writeVector(t, filepath.Join(dir, "iaca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: iaca.Raw}))
	writeVector(t, filepath.Join(dir, "dsc.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: dsc.Raw}))

	t.Logf("wrote interop vectors to %s", dir)
}

func writeVector(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestVectorsHaveUsefulRemainingLife fails while there is still time to do
// something about it, rather than letting the committed vectors expire and
// surface downstream as an inscrutable certificate-chain error.
//
// Annex B caps a DSC at 457 days, so expiry is not avoidable — only made
// visible. When this fails, regenerate:
//
//	MDL_WRITE_VECTORS=1 go test ./internal/mdl/... -run TestGenerateVectors
//
// and update the copies in cdpi-wallet and the reader app in the same change.
//
// Unlike TestGenerateVectors this is not gated behind MDL_WRITE_VECTORS: it
// must run in ordinary CI, which is the whole point.
func TestVectorsHaveUsefulRemainingLife(t *testing.T) {
	dir := filepath.Join("testdata", "vectors")
	for _, name := range []string{"iaca.pem", "dsc.pem"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s (regenerate the vectors): %v", name, err)
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			t.Fatalf("%s is not valid PEM", name)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		remaining := time.Until(cert.NotAfter)
		if remaining <= 0 {
			t.Errorf("%s expired %v ago; regenerate the interop vectors", name, -remaining.Round(24*time.Hour))
			continue
		}
		if remaining < minRemainingLife {
			t.Errorf("%s expires in %v, under the %v refresh threshold; regenerate the interop vectors",
				name, remaining.Round(24*time.Hour), minRemainingLife.Round(24*time.Hour))
		}
	}
}

// TestVectorMdocIsAnUntaggedCOSESign1 pins the wire-format fix that the
// @owf/mdoc harness uncovered, directly on the committed artefact.
//
// The Go-side assertion in sign_test.go covers freshly signed output; this
// covers the bytes other repos actually consume, so a stale vector
// regenerated by an older build cannot slip back in.
func TestVectorMdocIsAnUntaggedCOSESign1(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "vectors", "mdl_full.cbor"))
	if err != nil {
		t.Fatalf("read mdl_full.cbor (regenerate the vectors): %v", err)
	}
	var is IssuerSigned
	if err := cbor.Unmarshal(raw, &is); err != nil {
		t.Fatalf("vector must decode as an IssuerSigned: %v", err)
	}
	if len(is.IssuerAuth) == 0 {
		t.Fatal("vector carries no issuerAuth")
	}
	if is.IssuerAuth[0] == coseSign1TagByte {
		t.Error("issuerAuth in the committed vector is tag-18 wrapped; ISO 18013-5 wants an untagged COSE_Sign1")
	}
	if is.IssuerAuth[0] != 0x84 {
		t.Errorf("issuerAuth must be a 4-element array, got first byte %#x", is.IssuerAuth[0])
	}
}
