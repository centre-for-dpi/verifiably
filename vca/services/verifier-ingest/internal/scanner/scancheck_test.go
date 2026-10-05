// SPDX-License-Identifier: Apache-2.0

package scanner_test

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/fetchguard"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/pdf"
	"github.com/centre-for-dpi/vc-adapters/core/qr"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	shared "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/scanner"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/txn"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// failingPolicy finds a bad signature on every credential.
type failingPolicy struct{ err error }

func (f failingPolicy) Evaluate(_ context.Context, req *connect.Request[policyv1.EvaluateRequest]) (*connect.Response[policyv1.EvaluateResponse], error) {
	if f.err != nil {
		return nil, f.err
	}
	if req.Msg.GetNonce() != "" || req.Msg.GetPolicySetId() != "" {
		return nil, errors.New("a scanned credential answers no request")
	}
	return connect.NewResponse(&policyv1.EvaluateResponse{Verdict: policyv1.EvaluateResponse_VERDICT_INVALID, Checks: []*policyv1.CheckResult{
		{Name: "signature", Outcome: policyv1.Outcome_OUTCOME_FAIL, CredentialIndex: 0, Detail: "the issuer signature is not valid"},
	}}), nil
}

// shelf keeps the stored results.
type shelf struct {
	kept []*resultsv1.VerificationResult
}

func (s *shelf) Store(_ context.Context, req *connect.Request[resultsv1.StoreRequest]) (*connect.Response[resultsv1.StoreResponse], error) {
	r := req.Msg.GetResult()
	r.Id = "res-9"
	s.kept = append(s.kept, r)
	return connect.NewResponse(&resultsv1.StoreResponse{Result: r}), nil
}

// holderLink serves the credential behind a pasted link.
type holderLink struct{}

func (holderLink) Get(_ context.Context, link string) (fetchguard.Doc, error) {
	if link != "https://holder.example/credential" {
		return fetchguard.Doc{}, fetchguard.ErrRefused
	}
	return fetchguard.Doc{Body: []byte(sdjwtSample)}, nil
}

// checkingPage serves the camera page with the checks of VCA wired.
func checkingPage(t *testing.T, policy service.Evaluator) (*httptest.Server, *shelf) {
	t.Helper()
	store, err := txn.NewStore(shared.Memory())
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	kept := &shelf{}
	svc, err := service.New(service.Options{
		Store: store, SigningKey: key, BaseURL: "https://verify.example", Policy: policy, Results: kept,
		Now: func() time.Time { return time.Unix(1700000000, 0).UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	page, err := scanner.New(scanner.Options{Client: svc, Links: holderLink{}, Check: svc.Check})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	page.Register(mux)
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s, kept
}

// qrPNG draws the QR code of text as a PNG image.
func qrPNG(t *testing.T, text string) []byte {
	t.Helper()
	code, err := qr.Encode([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	bm := code.Bitmap(6, 4)
	img := image.NewGray(image.Rect(0, 0, bm.Width, bm.Height))
	stride := (bm.Width + 7) / 8
	for y := 0; y < bm.Height; y++ {
		for x := 0; x < bm.Width; x++ {
			v := uint8(0)
			if bm.Pixels[y*stride+x/8]&(0x80>>(x%8)) != 0 {
				v = 0xff
			}
			img.SetGray(x, y, color.Gray{Y: v})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// qrPDF puts the QR code of text on a one page document.
func qrPDF(t *testing.T, text string) []byte {
	t.Helper()
	code, err := qr.Encode([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	bm := code.Bitmap(4, 4)
	doc := pdf.New("Credential")
	doc.TextCentered(pdf.HelveticaBold, 18, 760, 0.1, "Proof of residence")
	if err := doc.Image(pdf.Image{Width: bm.Width, Height: bm.Height, Pixels: bm.Pixels}, 180, 300, 240); err != nil {
		t.Fatal(err)
	}
	return doc.Bytes()
}

// postParts sends one multipart form with fields and an optional file.
func postParts(t *testing.T, s *httptest.Server, fields map[string]string, name string, file []byte) string {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := w.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if file != nil {
		part, err := w.CreateFormFile("upload", name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(file); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.URL+"/scan/ingest", &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, %v", resp.StatusCode, err)
	}
	return string(body)
}

// TestScanOrUploadChecksThePresentedCredential is the "Scan or upload"
// tab of the verifier (spec: QR scanning, document uploads and link
// pasting; review finding 5). A QR image, a document with a QR code, a
// pasted link, pasted text and a camera scan each reach the checks of
// VCA. The page shows the verdict and links the stored result, which
// names how the credential arrived.
func TestScanOrUploadChecksThePresentedCredential(t *testing.T) {
	s, kept := checkingPage(t, failingPolicy{})
	pages := map[string]string{
		service.CarrierUpload + " image":    postParts(t, s, nil, "credential.png", qrPNG(t, sdjwtSample)),
		service.CarrierUpload + " document": postParts(t, s, nil, "credential.pdf", qrPDF(t, sdjwtSample)),
		service.CarrierScan:                 postParts(t, s, map[string]string{"payload": sdjwtSample, "source": "camera"}, "", nil),
	}
	_, pages[service.CarrierLink] = post(t, s, url.Values{"link": {"https://holder.example/credential"}}, nil)
	_, pages[service.CarrierPaste] = post(t, s, url.Values{"payload": {sdjwtSample}}, nil)
	for how, body := range pages {
		a11ytest.AssertPage(t, body)
		for _, want := range []string{`id="check-result"`, ">Not valid<", "the issuer signature is not valid", `href="/portal/results/res-9"`} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: the page lacks %q\n%s", how, want, body)
			}
		}
	}
	carriers := map[string]int{}
	for _, r := range kept.kept {
		carriers[r.GetCarrier()]++
		if len(r.GetCredentials()) != 1 || r.GetVerdict() != policyv1.EvaluateResponse_VERDICT_INVALID {
			t.Errorf("the stored result %+v", r)
		}
	}
	for carrier, n := range map[string]int{service.CarrierUpload: 2, service.CarrierScan: 1, service.CarrierLink: 1, service.CarrierPaste: 1} {
		if carriers[carrier] != n {
			t.Errorf("results with carrier %q: %d, want %d (%v)", carrier, carriers[carrier], n, carriers)
		}
	}
}

// TestScanWithoutAPolicyServiceSaysSo keeps the decoded answer and names
// why no check ran.
func TestScanWithoutAPolicyServiceSaysSo(t *testing.T) {
	s, kept := checkingPage(t, nil)
	_, body := post(t, s, url.Values{"payload": {sdjwtSample}}, nil)
	if !strings.Contains(body, "The service read the input") || !strings.Contains(body, "no policy service is configured") || len(kept.kept) != 0 {
		t.Fatalf("the page without a policy service:\n%s", body)
	}
	down, _ := checkingPage(t, failingPolicy{err: errors.New("down")})
	if _, b := post(t, down, url.Values{"payload": {sdjwtSample}}, nil); !strings.Contains(b, "the policy service did not check the credential") {
		t.Fatalf("the page with a policy service that fails:\n%s", b)
	}
}
