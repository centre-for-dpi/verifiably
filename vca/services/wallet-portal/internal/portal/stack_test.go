// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/portal"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/service"
)

// brokenDocument is a credential id whose document the fake refuses.
const brokenDocument = "broken"

func (f *fakeHolder) GetCredentialDocument(_ context.Context, req *connect.Request[backendv1.GetCredentialDocumentRequest],
) (*connect.Response[backendv1.GetCredentialDocumentResponse], error) {
	if req.Msg.GetCredentialId() == brokenDocument {
		return nil, errors.New("down")
	}
	return connect.NewResponse(&backendv1.GetCredentialDocumentResponse{Content: []byte("%PDF-1.4"), MediaType: "application/pdf"}), nil
}

// injiDeployment is one live Inji holder pair whose adapter lists the
// features and names the address of Inji Web.
func injiDeployment(features ...backendv1.Feature) portal.Topology {
	own := holderPeer(configv1.Dpg_DPG_INJI)
	caps := &backendv1.GetCapabilitiesResponse{
		DpgInfo: &backendv1.DpgInfo{DisplayName: "Inji", Components: []*backendv1.Component{
			{Name: "mimoto", Version: "0.21.0"},
			{Name: "inji-web", Version: "0.16.0", Url: "http://localhost:17085"},
		}},
		Features: features,
	}
	snap := topology.Snapshot{Peers: []topology.Status{{Peer: own, State: topology.Live, Capabilities: caps}}}
	return portal.Topology{
		Peers:    []topology.Peer{own},
		Snapshot: func(context.Context) topology.Snapshot { return snap },
		JWKSURL:  own.Auth() + "/.well-known/jwks.json",
	}
}

// setupStack builds the portal beside a stack wallet that lists the
// credentials by name, as Mimoto does.
func setupStack(t *testing.T, features ...backendv1.Feature) *harness {
	t.Helper()
	topo := injiDeployment(features...)
	var pages func(context.Context) bool
	h := setupShell(t, func(o *service.Options) {
		o.Hybrid = func(ctx context.Context) bool { return pages != nil && pages(ctx) }
	}, topo)
	h.holder.credential = &backendv1.WalletCredential{Id: "c9d27f40", Type: "Farmer Credential", Issuer: "Ministry of Agriculture"}
	pages = func(context.Context) bool {
		for _, f := range features {
			if f == backendv1.Feature_FEATURE_WALLET_CLAIM_IN_STACK {
				return true
			}
		}
		return false
	}
	return h
}

// TestStackWalletHome shows the stack credentials by name with the PDF
// link, the card that sends the holder to Inji Web, and the browser
// store for what the holder loads here.
func TestStackWalletHome(t *testing.T) {
	h := setupStack(t, backendv1.Feature_FEATURE_WALLET_CLAIM_IN_STACK, backendv1.Feature_FEATURE_WALLET_DOCUMENT)
	body := h.get(t, "/wallet/").Body.String()
	for _, want := range []string{
		"Farmer Credential", "Ministry of Agriculture", `href="/wallet/document?id=c9d27f40"`, "Download the PDF",
		"Your Inji wallet claims in its own page.", `href="http://localhost:17085"`, "Open the Inji wallet",
		"Your browser keeps what you load here.", `id="wallet-paste-save"`,
		"Credentials you hold in the Inji wallet, and the credentials your browser keeps.",
		"Its document shows the dates.",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("the home page misses %s\n%s", want, body)
		}
	}
	if strings.Contains(body, "names no end date") {
		t.Fatal("a card the stack lists by name claims to know its dates")
	}
	claim := h.get(t, "/wallet/claim").Body.String()
	if !strings.Contains(claim, "Open the Inji wallet") || strings.Contains(claim, `id="claim-signin"`) {
		t.Fatalf("the claim page does not point at Inji Web\n%s", claim)
	}
	offer := h.post(t, "/wallet/claim/offer", url.Values{"offer": {pinOffer}}).Body.String()
	if !strings.Contains(offer, "claims this offer in its own page") || strings.Contains(offer, `action="/wallet/accept"`) {
		t.Fatalf("the offer page accepts into a stack that claims in its own page\n%s", offer)
	}
}

// TestStackWalletHiddenWithoutFeatures keeps the plain stack wallet: no
// PDF link, no Inji Web card, and no browser store.
func TestStackWalletHiddenWithoutFeatures(t *testing.T) {
	h := setupStack(t)
	body := h.get(t, "/wallet/").Body.String()
	for _, unwanted := range []string{"Download the PDF", "Open the Inji wallet", `id="wallet-paste-save"`} {
		if strings.Contains(body, unwanted) {
			t.Fatalf("the home page shows %s without the feature", unwanted)
		}
	}
	if rec := h.get(t, "/wallet/document?id=c9d27f40"); rec.Code != http.StatusNotFound {
		t.Fatalf("the document without the feature: status = %d", rec.Code)
	}
}

// TestDocumentDownload serves the PDF of a stack credential as a
// download, and a problem page when the stack refuses.
func TestDocumentDownload(t *testing.T) {
	h := setupStack(t, backendv1.Feature_FEATURE_WALLET_DOCUMENT)
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/document?id=c9d27f40", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/pdf" ||
		!strings.Contains(rec.Header().Get("Content-Disposition"), `filename="credential.pdf"`) ||
		!strings.HasPrefix(rec.Body.String(), "%PDF") {
		t.Fatalf("document: %d %v", rec.Code, rec.Header())
	}
	problem := h.get(t, "/wallet/document?id="+brokenDocument)
	if !strings.Contains(problem.Body.String(), "The wallet did not give the document.") {
		t.Fatalf("problem: %d %s", problem.Code, problem.Body.String())
	}
}
