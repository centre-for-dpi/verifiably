// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"connectrpc.com/connect"

	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/service"
)

// TestBrowserCredentialMatchesBothSdJwtQueries is the scenario of a
// stack whose catalogue offers vc+sd-jwt: the browser store keeps the
// vc+sd-jwt credential it got, and a vc+sd-jwt query matches it, as a
// dc+sd-jwt query does.
func TestBrowserCredentialMatchesBothSdJwtQueries(t *testing.T) {
	text, _ := sdjwtFixture(t)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"vc+sd-jwt"}`))
	legacy := header + text[strings.Index(text, "."):]
	for _, format := range []string{"vc+sd-jwt", "dc+sd-jwt"} {
		raw := []byte(strings.Replace(string(requestObject()), `"format":"dc+sd-jwt"`, `"format":"`+format+`"`, 1))
		if !strings.Contains(string(raw), format) {
			t.Fatalf("the request object names no format: %s", raw)
		}
		svc := build(t, func(o *service.Options) {
			o.Fetch = func(context.Context, string) ([]byte, error) { return raw, nil }
		})
		if _, perr := svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: legacy})); perr != nil {
			t.Fatal(perr)
		}
		start, err := svc.PresentStart(ctx(), connect.NewRequest(&walletportalv1.PresentStartRequest{
			PresentationId: "openid4vp://?request_uri=https://verifier.example/r/1",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if got := start.Msg.GetRequested()[0].GetMatches(); len(got) != 1 {
			t.Errorf("a %s query: matches = %+v", format, got)
		}
	}
}
