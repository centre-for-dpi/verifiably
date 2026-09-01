package mdl

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/verifiably/verifiably-go/internal/mdl/pki"
	"github.com/verifiably/verifiably-go/internal/signer"
)

// serverIACAValidity and serverDSCValidity mirror the choice already made for
// the interop vectors in Task 7 of the issuer plan: the Annex B cap is 457
// days for the DSC, and the DSC must not outlive its IACA, so the IACA needs
// a longer life. This is POC material — see pki.POCOrganization — not a
// production default.
const (
	serverIACAValidity = 3 * 365 * 24 * time.Hour
	serverDSCValidity  = 457 * 24 * time.Hour
)

// NewServerSigner generates a fresh self-signed IACA and a DSC under it, and
// wraps the DSC's key in a signer.Signer. Generated once per process start;
// this is the signer the mDL issuance endpoint signs with.
func NewServerSigner() (signer.Signer, error) {
	iacaKey, iaca, err := pki.GenerateIACA("verifiably POC IACA", "DO", serverIACAValidity)
	if err != nil {
		return nil, fmt.Errorf("mdl: generate server IACA: %w", err)
	}
	dscKey, dsc, err := pki.GenerateDSC(iacaKey, iaca, "verifiably POC DSC", serverDSCValidity)
	if err != nil {
		return nil, fmt.Errorf("mdl: generate server DSC: %w", err)
	}
	s, err := signer.NewSoftwareSigner(dscKey, []*x509.Certificate{dsc, iaca})
	if err != nil {
		return nil, fmt.Errorf("mdl: build server signer: %w", err)
	}
	return s, nil
}
