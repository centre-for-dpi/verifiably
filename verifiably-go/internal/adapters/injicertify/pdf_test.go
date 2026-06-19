package injicertify

import (
	"net/url"
	"testing"
)

// issuerDIDFromVC reads the issuer for the PDF's informational line — issuer may
// be a bare DID string or an {id,...} object; otherwise falls back.
func TestIssuerDIDFromVC(t *testing.T) {
	cases := []struct {
		name, vc, fallback, want string
	}{
		{"string issuer", `{"issuer":"did:web:x","type":["VerifiableCredential"]}`, "fb", "did:web:x"},
		{"object issuer", `{"issuer":{"id":"did:web:y","name":"Y Org"}}`, "fb", "did:web:y"},
		{"missing issuer falls back", `{"type":["VerifiableCredential"]}`, "did:web:fb", "did:web:fb"},
		{"invalid VC falls back", `not json`, "did:web:fb", "did:web:fb"},
		{"empty issuer string falls back", `{"issuer":""}`, "did:web:fb", "did:web:fb"},
		{"no issuer + no fallback uses default", `{}`, "", "Inji Certify (Pre-Auth)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := issuerDIDFromVC(c.vc, c.fallback); got != c.want {
				t.Errorf("issuerDIDFromVC(%q,%q) = %q, want %q", c.vc, c.fallback, got, c.want)
			}
		})
	}
}

// extractOfferDataURL unwraps the openid-credential-offer:// envelope and swaps
// the public host for the docker-internal one.
func TestExtractOfferDataURL(t *testing.T) {
	if _, err := extractOfferDataURL("", "http://internal:8090", "https://public"); err == nil {
		t.Error("empty offer URI should error")
	}
	inner := "https://public/v1/certify/credential-offer-data/abc"
	in := "openid-credential-offer://?credential_offer_uri=" + url.QueryEscape(inner)
	got, err := extractOfferDataURL(in, "http://internal:8090", "https://public")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "http://internal:8090/v1/certify/credential-offer-data/abc"
	if got != want {
		t.Errorf("extractOfferDataURL = %q, want %q", got, want)
	}
}
