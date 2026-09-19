// SPDX-License-Identifier: Apache-2.0

package detect_test

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/vc"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/detect"
)

// offerURI builds a credential offer URI with the offer object.
func offerURI(offer string) string {
	return "openid-credential-offer://?credential_offer=" + url.QueryEscape(offer)
}

const preAuthOffer = `{"credential_issuer":"https://issuer.example",
"credential_configuration_ids":["DriverLicence","Other"],
"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":
{"pre-authorized_code":"abc","tx_code":{"length":4}}}}`

func TestTextReadsPreAuthorizedOffer(t *testing.T) {
	got, err := detect.Text(offerURI(preAuthOffer), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != detect.Offer {
		t.Fatalf("kind = %v", got.Kind)
	}
	o := got.Offer
	if o.CredentialIssuer != "https://issuer.example" || !o.PreAuthorized || !o.NeedsPIN {
		t.Fatalf("offer = %+v", o)
	}
	if len(o.ConfigurationIDs) != 2 || o.ConfigurationIDs[0] != "DriverLicence" {
		t.Fatalf("ids = %v", o.ConfigurationIDs)
	}
	if !strings.Contains(detect.Explain(got), "code the issuer gave you") {
		t.Fatalf("explain = %q", detect.Explain(got))
	}
}

func TestTextReadsOfferForms(t *testing.T) {
	bare := `{"credential_issuer":"https://issuer.example","grants":{"authorization_code":{}}}`
	got, err := detect.Text(bare, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != detect.Offer || got.Offer.PreAuthorized || got.Offer.NeedsPIN {
		t.Fatalf("bare offer = %+v", got)
	}
	if !strings.Contains(detect.Explain(got), "Check the issuer") {
		t.Fatalf("explain = %q", detect.Explain(got))
	}
	ref, err := detect.Text("https://wallet.example/offer?credential_offer_uri=https://issuer.example/o/1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if ref.Kind != detect.Offer || !ref.Offer.ByReference {
		t.Fatalf("offer by reference = %+v", ref)
	}
	broken, err := detect.Text("openid-credential-offer://?credential_offer=%7Bnope", 0)
	if err != nil {
		t.Fatal(err)
	}
	if broken.Kind != detect.Offer || broken.Offer.CredentialIssuer != "" {
		t.Fatalf("broken offer = %+v", broken)
	}
	typed := `{"credential_issuer":1,"credential_configuration_ids":["a",2],"grants":{"x-pre-authorized_code":1}}`
	odd, err := detect.Text(typed, 0)
	if err != nil {
		t.Fatal(err)
	}
	if odd.Kind != detect.Offer || len(odd.Offer.ConfigurationIDs) != 1 || !odd.Offer.PreAuthorized {
		t.Fatalf("odd offer = %+v", odd.Offer)
	}
}

func TestTextReadsPresentationRequest(t *testing.T) {
	got, err := detect.Text("openid4vp://?client_id=x&request_uri=https://verifier.example/r/1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != detect.Request || got.RequestURI != "https://verifier.example/r/1" {
		t.Fatalf("request = %+v", got)
	}
	if !strings.Contains(detect.Explain(got), "Read the list") {
		t.Fatalf("explain = %q", detect.Explain(got))
	}
	inline := "openid4vp://?client_id=x&dcql_query=%7B%7D"
	direct, err := detect.Text(inline, 0)
	if err != nil {
		t.Fatal(err)
	}
	if direct.Kind != detect.Request || direct.RequestURI != inline {
		t.Fatalf("inline request = %+v", direct)
	}
	pd, err := detect.Text("https://verifier.example/vp?presentation_definition=%7B%7D", 0)
	if err != nil {
		t.Fatal(err)
	}
	if pd.Kind != detect.Request {
		t.Fatalf("pd request = %+v", pd)
	}
}

func TestTextReadsCredential(t *testing.T) {
	sdjwt := "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJEcml2ZXIifQ.c2ln~WyJzIiwiYSIsMV0~"
	got, err := detect.Text(sdjwt, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != detect.Credential || got.Format != commonv1.Format_FORMAT_DC_SD_JWT {
		t.Fatalf("credential = %+v", got)
	}
	if string(got.Credential) != sdjwt {
		t.Fatal("want the credential bytes")
	}
	if !strings.Contains(detect.Explain(got), "holds a credential") {
		t.Fatalf("explain = %q", detect.Explain(got))
	}
	ld := `{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"]}`
	jsonld, err := detect.Text(ld, 0)
	if err != nil {
		t.Fatal(err)
	}
	if jsonld.Kind != detect.Credential || jsonld.Format != commonv1.Format_FORMAT_LDP_VC {
		t.Fatalf("json-ld = %+v", jsonld)
	}
}

func TestTextRejects(t *testing.T) {
	if _, err := detect.Text("   ", 0); !errors.Is(err, detect.ErrEmpty) {
		t.Fatalf("empty: %v", err)
	}
	if _, err := detect.Text("hello there", 4); !errors.Is(err, detect.ErrTooLong) {
		t.Fatalf("long: %v", err)
	}
	got, err := detect.Text("just some words", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != detect.Unknown {
		t.Fatalf("kind = %v", got.Kind)
	}
	if !strings.Contains(detect.Explain(got), "does not know") {
		t.Fatalf("explain = %q", detect.Explain(got))
	}
	if !strings.Contains(detect.Explain(detect.Result{Kind: detect.Kind(9)}), "does not know") {
		t.Fatal("want the fallback sentence")
	}
	plain, err := detect.Text(`{"hello":"there"}`, 0)
	if err != nil || plain.Kind != detect.Unknown {
		t.Fatalf("plain json = %+v %v", plain, err)
	}
	if _, serr := detect.Text("openid4vp://%zz", 0); serr != nil {
		t.Fatalf("broken uri: %v", serr)
	}
	brace, err := detect.Text("{not json", 0)
	if err != nil || brace.Kind != detect.Unknown {
		t.Fatalf("broken object = %+v %v", brace, err)
	}
	control, err := detect.Text("openid-credential-offer://\x7f", 0)
	if err != nil || control.Kind != detect.Unknown {
		t.Fatalf("control characters = %+v %v", control, err)
	}
}

func TestFormatOf(t *testing.T) {
	cases := map[vc.Format]commonv1.Format{
		vc.FormatSDJWT:   commonv1.Format_FORMAT_DC_SD_JWT,
		vc.FormatJWT:     commonv1.Format_FORMAT_JWT_VC_JSON,
		vc.FormatJSONLD:  commonv1.Format_FORMAT_LDP_VC,
		vc.FormatMdoc:    commonv1.Format_FORMAT_MSO_MDOC,
		vc.FormatJSON:    commonv1.Format_FORMAT_UNSPECIFIED,
		vc.FormatUnknown: commonv1.Format_FORMAT_UNSPECIFIED,
		vc.Format("odd"): commonv1.Format_FORMAT_UNSPECIFIED,
	}
	for in, want := range cases {
		if got := detect.FormatOf(in); got != want {
			t.Fatalf("%s = %v, want %v", in, got, want)
		}
	}
}
