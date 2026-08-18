package mdl

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/verifiably/verifiably-go/internal/mdl/pki"
	"github.com/verifiably/verifiably-go/internal/signer"
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

	iacaKey, iaca, err := pki.GenerateIACA("CDPI POC IACA", "DO", 90*24*time.Hour)
	if err != nil {
		t.Fatalf("generate IACA: %v", err)
	}
	dscKey, dsc, err := pki.GenerateDSC(iacaKey, iaca, "CDPI POC DSC", 30*24*time.Hour)
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
