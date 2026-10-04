// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/sdjwt"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/service"
)

// typedToken returns an SD-JWT of one type with the claims concealed.
// A non nil holder key binds it to the browser in cnf.jwk.
func typedToken(t *testing.T, vct string, claims map[string]any, holder *browserHolder) string {
	t.Helper()
	payload := map[string]any{"vct": vct, "iss": "did:web:issuer.example"}
	names := make([]string, 0, len(claims))
	for k, v := range claims {
		payload[k] = v
		names = append(names, k)
	}
	concealed, discs, err := sdjwt.Conceal(payload, names)
	if err != nil {
		t.Fatal(err)
	}
	if holder != nil {
		var jwk map[string]any
		if jerr := json.Unmarshal([]byte(holder.jwk), &jwk); jerr != nil {
			t.Fatal(jerr)
		}
		concealed["cnf"] = map[string]any{"jwk": jwk}
	}
	body, err := json.Marshal(concealed)
	if err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"dc+sd-jwt"}`)) + "." + base64.RawURLEncoding.EncodeToString(body) + ".sig"
	for _, d := range discs {
		token += "~" + d.Encoded
	}
	return token + "~"
}

// twoQueries is the request object of a combined query: a residence
// credential and a parking permit of the same resident.
func twoQueries(t *testing.T) []byte {
	t.Helper()
	doc := map[string]any{
		"client_id": "https://verifier.example", "nonce": "n-1", "state": "s-1",
		"response_uri": "https://verifier.example/direct_post", "response_mode": "direct_post",
		"dcql_query": map[string]any{
			"credentials": []any{
				map[string]any{"id": "residence", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []string{"Residence"}},
					"claims": []any{map[string]any{"path": []string{"residentNumber"}}}},
				map[string]any{"id": "permit", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []string{"ParkingPermit"}},
					"claims": []any{map[string]any{"path": []string{"residentNumber"}}}},
			},
			"credential_sets": []any{map[string]any{"options": []any{[]string{"residence", "permit"}}}},
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestBrowserStoreSendsEveryChosenCredential answers a combined query
// with every credential the holder chose, each bound with its own key
// binding, in one vp_token keyed by query id (OID4VP 1.0 section 8.1).
func TestBrowserStoreSendsEveryChosenCredential(t *testing.T) {
	for _, bound := range []bool{false, true} {
		var posted url.Values
		svc := build(t, func(o *service.Options) {
			o.Fetch = func(context.Context, string) ([]byte, error) { return twoQueries(t), nil }
			o.Post = func(_ context.Context, _ string, form url.Values) ([]byte, error) {
				posted = form
				return []byte(`{}`), nil
			}
		})
		var browser *browserHolder
		if bound {
			b := newBrowserHolder(t)
			browser = &b
		}
		claims := map[string]any{"residentNumber": "RES-1"}
		for _, vct := range []string{"Residence", "ParkingPermit"} {
			if _, err := svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: typedToken(t, vct, claims, browser)})); err != nil {
				t.Fatal(err)
			}
		}
		start, err := svc.PresentStart(ctx(), connect.NewRequest(&walletportalv1.PresentStartRequest{
			PresentationId: "openid4vp://?request_uri=https://verifier.example/r/1",
		}))
		if err != nil {
			t.Fatal(err)
		}
		req := &walletportalv1.PresentConfirmRequest{PresentationId: start.Msg.GetPresentationId(),
			SelectedCards: map[string]string{}, Disclosed: map[string]*walletportalv1.PresentConfirmRequest_ClaimPaths{}}
		for _, entry := range start.Msg.GetRequested() {
			if len(entry.GetMatches()) != 1 {
				t.Fatalf("%s: matches %v", entry.GetQueryId(), entry.GetMatches())
			}
			req.SelectedCards[entry.GetQueryId()] = entry.GetMatches()[0].GetId()
			req.Disclosed[entry.GetQueryId()] = &walletportalv1.PresentConfirmRequest_ClaimPaths{Paths: []string{"residentNumber"}}
		}
		if bound {
			inputs, ierr := svc.BindingInputs(ctx(), req)
			if ierr != nil || len(inputs) != 2 {
				t.Fatalf("BindingInputs = %v, %v", inputs, ierr)
			}
			signed := map[string]string{}
			for q, in := range inputs {
				signed[q] = in + "." + browser.sign(t, in)
			}
			raw, merr := json.Marshal(signed)
			if merr != nil {
				t.Fatal(merr)
			}
			req.KeyBinding = string(raw)
		}
		if _, err := svc.PresentConfirm(ctx(), connect.NewRequest(req)); err != nil {
			t.Fatalf("bound %v: PresentConfirm: %v", bound, err)
		}
		var token map[string][]string
		if err := json.Unmarshal([]byte(posted.Get("vp_token")), &token); err != nil || len(token["residence"]) != 1 || len(token["permit"]) != 1 {
			t.Fatalf("bound %v: vp_token = %s (%v), want both credentials keyed by query id", bound, posted.Get("vp_token"), err)
		}
		if bound && (strings.Count(token["residence"][0], "~") < 2 || strings.HasSuffix(token["permit"][0], "~")) {
			t.Errorf("a bound credential lacks its key binding: %v", token)
		}
	}
}
