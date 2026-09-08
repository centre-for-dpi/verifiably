package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/vctypes"
)

// walletAdapter fakes the holder-side adapter surface used by wallet.go.
type walletAdapter struct {
	backend.Adapter
	creds       []vctypes.Credential
	credsErr    error
	schemas     []vctypes.Schema
	schemasErr  error
	examples    []string
	examplesErr error
	parsed      vctypes.Credential
	parseErr    error
	claimErr    error
	holderDpgs  map[string]vctypes.DPG
	presentRes  backend.PresentCredentialResult
	presentErr  error
	deleteErr   error

	parsedURIs []string
	claimed    []vctypes.Credential
	presented  []backend.PresentCredentialRequest
	deleted    []string
	holderKeys []string // identity keys seen on ListWalletCredentials contexts
}

func (a *walletAdapter) ListWalletCredentials(ctx context.Context) ([]vctypes.Credential, error) {
	a.holderKeys = append(a.holderKeys, backend.HolderIdentityFromContext(ctx))
	return append([]vctypes.Credential(nil), a.creds...), a.credsErr
}
func (a *walletAdapter) ListAllSchemas(context.Context) ([]vctypes.Schema, error) {
	return a.schemas, a.schemasErr
}
func (a *walletAdapter) ListExampleOffers(context.Context) ([]string, error) {
	return a.examples, a.examplesErr
}
func (a *walletAdapter) ParseOffer(_ context.Context, uri string) (vctypes.Credential, error) {
	a.parsedURIs = append(a.parsedURIs, uri)
	return a.parsed, a.parseErr
}
func (a *walletAdapter) ClaimCredential(_ context.Context, c vctypes.Credential) (vctypes.Credential, error) {
	a.claimed = append(a.claimed, c)
	c.ID = "held-" + c.ID
	return c, a.claimErr
}
func (a *walletAdapter) ListHolderDpgs(context.Context) (map[string]vctypes.DPG, error) {
	return a.holderDpgs, nil
}
func (a *walletAdapter) PresentCredential(_ context.Context, req backend.PresentCredentialRequest) (backend.PresentCredentialResult, error) {
	a.presented = append(a.presented, req)
	return a.presentRes, a.presentErr
}
func (a *walletAdapter) DeleteWalletCredential(_ context.Context, id string) error {
	a.deleted = append(a.deleted, id)
	return a.deleteErr
}

// walletPreviewAdapter adds the optional PresentationPreviewer capability.
type walletPreviewAdapter struct {
	*walletAdapter
	preview    backend.PresentationPreview
	previewErr error
}

func (a *walletPreviewAdapter) PreviewPresentation(_ context.Context, req backend.PresentCredentialRequest) (backend.PresentationPreview, error) {
	return a.preview, a.previewErr
}

func walletH(t *testing.T, ad backend.Adapter, mutate func(*Session)) (*H, []*http.Cookie) {
	t.Helper()
	h := &H{Adapter: ad, Sessions: NewStore(), Templates: loadPageTemplates(t, "holder_wallet", "holder_present")}
	cookies := seedSession(t, h, func(s *Session) {
		s.HolderDpg = "Example Wallet"
		if mutate != nil {
			mutate(s)
		}
	})
	return h, cookies
}

func walletCred(id, title string) vctypes.Credential {
	return vctypes.Credential{ID: id, Title: title, Issuer: "did:web:issuer.example", Type: "PersonCredential", Format: "vc+sd-jwt", Fields: map[string]string{"name": "Ada"}}
}

func TestHolderCtxAndSessionWalletKey(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sess := &Session{ID: "sid", AuthProvider: "oidc", UserSubject: "sub-1", UserEmail: "a@example.org"}
	if got := backend.HolderIdentityFromContext(holderCtx(req, sess)); got != "oidc|sub-1" || sess.WalletUserKey != "oidc|sub-1" {
		t.Fatalf("holder identity=%q frozen=%q", got, sess.WalletUserKey)
	}
	sess.UserSubject = "changed"
	if got := sessionWalletKey(sess); got != "oidc|sub-1" {
		t.Fatalf("frozen key must not shift: %q", got)
	}
	if got := sessionWalletKey(&Session{ID: "sid", UserEmail: "a@example.org"}); got != "a@example.org" {
		t.Fatalf("email fallback: %q", got)
	}
	if got := sessionWalletKey(&Session{ID: "sid"}); got != "session-sid" {
		t.Fatalf("session fallback: %q", got)
	}
}

func TestShowWallet(t *testing.T) {
	t.Run("no holder DPG → redirect", func(t *testing.T) {
		h, cookies := walletH(t, &walletAdapter{}, func(s *Session) { s.HolderDpg = "" })
		rr := httptest.NewRecorder()
		h.ShowWallet(rr, issueGET("/holder/wallet", true, cookies))
		if rr.Header().Get("HX-Redirect") != "/holder/dpg" {
			t.Fatalf("HX-Redirect=%q", rr.Header().Get("HX-Redirect"))
		}
	})
	t.Run("adapter error → toast", func(t *testing.T) {
		h, cookies := walletH(t, &walletAdapter{credsErr: errors.New("wallet down")}, nil)
		rr := httptest.NewRecorder()
		h.ShowWallet(rr, issueGET("/holder/wallet", true, cookies))
		if !strings.Contains(rr.Header().Get("HX-Trigger"), "wallet down") {
			t.Fatalf("trigger=%q", rr.Header().Get("HX-Trigger"))
		}
	})
	t.Run("lazy-loads and caches credentials with issuer display", func(t *testing.T) {
		ad := &walletAdapter{creds: []vctypes.Credential{walletCred("c1", "Person")}, schemas: []vctypes.Schema{{Name: " person ", IssuerDisplayName: "Example Registry"}, {Name: "Other"}}}
		h, cookies := walletH(t, ad, func(s *Session) { s.UserEmail = "holder@example.org" })
		req := issueGET("/holder/wallet", false, cookies)
		rr := httptest.NewRecorder()
		h.ShowWallet(rr, req)
		body := rr.Body.String()
		if rr.Code != 200 || !strings.Contains(body, "<!DOCTYPE") || !strings.Contains(body, "Example Registry") || !strings.Contains(body, `data-title="Person"`) {
			t.Fatalf("status=%d body=%s", rr.Code, body)
		}
		if len(ad.holderKeys) != 1 || ad.holderKeys[0] != "holder@example.org" {
			t.Fatalf("holder keys=%v", ad.holderKeys)
		}
		h.ShowWallet(httptest.NewRecorder(), issueGET("/holder/wallet", true, cookies))
		if len(ad.holderKeys) != 1 {
			t.Fatal("second render must use the session cache")
		}
	})
}

func TestAttachIssuerDisplayToCreds(t *testing.T) {
	h := &H{Adapter: &walletAdapter{schemasErr: errors.New("down")}}
	creds := []vctypes.Credential{walletCred("c1", "Person")}
	h.attachIssuerDisplayToCreds(context.Background(), nil)
	h.attachIssuerDisplayToCreds(context.Background(), creds)
	if creds[0].IssuerDisplay != "" {
		t.Fatalf("schema error must leave display empty: %+v", creds[0])
	}
}

func TestScanOffer(t *testing.T) {
	post := func(h *H, cookies []*http.Cookie) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.ScanOffer(rr, formPost("/holder/wallet/scan", url.Values{}, cookies...))
		return rr
	}
	t.Run("errors", func(t *testing.T) {
		h, cookies := walletH(t, &walletAdapter{examplesErr: errors.New("no list")}, nil)
		if rr := post(h, cookies); !strings.Contains(rr.Header().Get("HX-Trigger"), "no list") {
			t.Fatalf("trigger=%q", rr.Header().Get("HX-Trigger"))
		}
		h, cookies = walletH(t, &walletAdapter{}, nil)
		if rr := post(h, cookies); !strings.Contains(rr.Header().Get("HX-Trigger"), "no example offers available") {
			t.Fatalf("trigger=%q", rr.Header().Get("HX-Trigger"))
		}
		h, cookies = walletH(t, &walletAdapter{examples: []string{"openid-credential-offer://a"}, parseErr: errors.New("bad offer")}, nil)
		if rr := post(h, cookies); !strings.Contains(rr.Header().Get("HX-Trigger"), "bad offer") {
			t.Fatalf("trigger=%q", rr.Header().Get("HX-Trigger"))
		}
	})
	t.Run("cycles examples and prepends the pending offer", func(t *testing.T) {
		ad := &walletAdapter{examples: []string{"openid-credential-offer://a", "openid-credential-offer://b"}, parsed: walletCred("", "Scanned")}
		h, cookies := walletH(t, ad, nil)
		rr := post(h, cookies)
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), "via scan") || !strings.Contains(rr.Body.String(), "<h4>Scanned</h4>") {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		post(h, cookies)
		post(h, cookies)
		if len(ad.parsedURIs) != 3 || ad.parsedURIs[0] != "openid-credential-offer://a" || ad.parsedURIs[1] != "openid-credential-offer://b" || ad.parsedURIs[2] != "openid-credential-offer://a" {
			t.Fatalf("parsed=%v", ad.parsedURIs)
		}
		sess := sessionOf(h, formPost("/", nil, cookies...))
		if len(sess.WalletPending) != 3 || !strings.HasPrefix(sess.WalletPending[0].ID, "pending-") || sess.WalletPending[0].Source != "scan" {
			t.Fatalf("pending=%+v", sess.WalletPending)
		}
	})
}

func TestExplainPasteError(t *testing.T) {
	if got := explainPasteError(backend.ErrNotLinked, "Example Wallet"); !strings.Contains(got, `"Example Wallet" requires an eSignet login`) {
		t.Fatalf("got %q", got)
	}
	if got := explainPasteError(errors.New("plain"), "x"); got != "plain" {
		t.Fatalf("got %q", got)
	}
}

func TestPasteOffer(t *testing.T) {
	post := func(h *H, uri string, cookies []*http.Cookie) (*httptest.ResponseRecorder, *Session) {
		req := formPost("/holder/wallet/paste", url.Values{"offer_uri": {uri}}, cookies...)
		rr := httptest.NewRecorder()
		h.PasteOffer(rr, req)
		return rr, sessionOf(h, req)
	}
	ad := &walletAdapter{parsed: walletCred("", "Pasted"), parseErr: backend.ErrNotLinked}
	h, cookies := walletH(t, ad, nil)
	cases := []struct{ uri, want string }{
		{"  ", "Paste an openid-credential-offer:// URI first"},
		{"ftp://x", "doesn't look like a credential offer URI"},
		{"https://localhost/offer", "Credential offer URL rejected:"},
		{"openid-credential-offer://x", "requires an eSignet login"},
	}
	for _, tc := range cases {
		rr, sess := post(h, tc.uri, cookies)
		if rr.Code != 200 || !strings.Contains(sess.LastWalletError, tc.want) || !strings.Contains(rr.Body.String(), `<p class="mono"`) {
			t.Fatalf("%q: status=%d err=%q", tc.uri, rr.Code, sess.LastWalletError)
		}
	}
	ad.parseErr = nil
	rr, sess := post(h, "openid-credential-offer://ok", cookies)
	if sess.LastWalletError != "" || len(sess.WalletPending) != 1 || sess.WalletPending[0].Source != "paste" || !strings.Contains(rr.Body.String(), "via paste") {
		t.Fatalf("err=%q pending=%+v", sess.LastWalletError, sess.WalletPending)
	}
}

func TestPrefillExample(t *testing.T) {
	get := func(h *H, cookies []*http.Cookie) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.PrefillExample(rr, issueGET("/holder/wallet/example", true, cookies))
		return rr
	}
	h, cookies := walletH(t, &walletAdapter{examplesErr: errors.New("nope")}, nil)
	if rr := get(h, cookies); !strings.Contains(rr.Header().Get("HX-Trigger"), "nope") {
		t.Fatalf("trigger=%q", rr.Header().Get("HX-Trigger"))
	}
	h, cookies = walletH(t, &walletAdapter{}, nil)
	if rr := get(h, cookies); !strings.Contains(rr.Header().Get("HX-Trigger"), "no example offers available") {
		t.Fatalf("trigger=%q", rr.Header().Get("HX-Trigger"))
	}
	h, cookies = walletH(t, &walletAdapter{examples: []string{`openid-credential-offer://x?a=<b>`}}, nil)
	rr := get(h, cookies)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `id="offer-paste"`) || !strings.Contains(rr.Body.String(), "&lt;b&gt;") || !strings.Contains(rr.Header().Get("HX-Trigger"), "Example offer URI pasted") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestAcceptAndRejectCred(t *testing.T) {
	pending := []vctypes.Credential{walletCred("pending-1", "One"), walletCred("pending-2", "Two")}
	ad := &walletAdapter{claimErr: errors.New("claim failed")}
	h, cookies := walletH(t, ad, func(s *Session) { s.WalletPending = append([]vctypes.Credential(nil), pending...) })
	do := func(fn func(http.ResponseWriter, *http.Request), id string) (*httptest.ResponseRecorder, *Session) {
		req := formPost("/holder/wallet/x", url.Values{"id": {id}}, cookies...)
		rr := httptest.NewRecorder()
		fn(rr, req)
		return rr, sessionOf(h, req)
	}
	if rr, _ := do(h.AcceptCred, "ghost"); !strings.Contains(rr.Header().Get("HX-Trigger"), "offer not found") {
		t.Fatalf("trigger=%q", rr.Header().Get("HX-Trigger"))
	}
	rr, sess := do(h.AcceptCred, "pending-1")
	if !strings.Contains(rr.Header().Get("HX-Trigger"), "claim failed") || len(sess.WalletPending) != 1 || len(sess.WalletCreds) != 0 {
		t.Fatalf("trigger=%q pending=%d", rr.Header().Get("HX-Trigger"), len(sess.WalletPending))
	}
	ad.claimErr = nil
	rr, sess = do(h.AcceptCred, "pending-2")
	if rr.Code != 200 || len(sess.WalletPending) != 0 || len(sess.WalletCreds) != 1 || sess.WalletCreds[0].ID != "held-pending-2" || !strings.Contains(rr.Body.String(), `data-title="Two"`) {
		t.Fatalf("status=%d creds=%+v", rr.Code, sess.WalletCreds)
	}
	sess.WalletPending = append([]vctypes.Credential(nil), pending...)
	if rr, _ := do(h.RejectCred, "ghost"); !strings.Contains(rr.Header().Get("HX-Trigger"), "offer not found") {
		t.Fatalf("trigger=%q", rr.Header().Get("HX-Trigger"))
	}
	rr, sess = do(h.RejectCred, "pending-1")
	if rr.Code != 200 || len(sess.WalletPending) != 1 || sess.WalletPending[0].ID != "pending-2" {
		t.Fatalf("status=%d pending=%+v", rr.Code, sess.WalletPending)
	}
}

func TestShowPresent(t *testing.T) {
	t.Run("redirect", func(t *testing.T) {
		h, cookies := walletH(t, &walletAdapter{}, func(s *Session) { s.HolderDpg = "" })
		rr := httptest.NewRecorder()
		h.ShowPresent(rr, issueGET("/holder/present", false, cookies))
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status=%d", rr.Code)
		}
	})
	t.Run("fresh list from the adapter with preselect + DPG limitation", func(t *testing.T) {
		ad := &walletAdapter{creds: []vctypes.Credential{walletCred("c1", "Person"), walletCred("c2", "Diploma")},
			holderDpgs: map[string]vctypes.DPG{"Example Wallet": {Capabilities: []vctypes.Capability{{Kind: "limitation", Title: "Limited", Body: "no mdoc"}}}}}
		h, cookies := walletH(t, ad, nil)
		rr := httptest.NewRecorder()
		h.ShowPresent(rr, issueGET("/holder/present?credential=c2", true, cookies))
		body := rr.Body.String()
		if rr.Code != 200 || !strings.Contains(body, `value="c2" data-format="vc&#43;sd-jwt" selected>`) || !strings.Contains(body, "no mdoc") {
			t.Fatalf("status=%d body=%s", rr.Code, body)
		}
	})
	t.Run("session cache wins; adapter failure leaves the picker empty", func(t *testing.T) {
		ad := &walletAdapter{credsErr: errors.New("down")}
		h, cookies := walletH(t, ad, nil)
		rr := httptest.NewRecorder()
		h.ShowPresent(rr, issueGET("/holder/present", true, cookies))
		if !strings.Contains(rr.Body.String(), `type="submit" disabled`) {
			t.Fatalf("body=%s", rr.Body.String())
		}
		h, cookies = walletH(t, ad, func(s *Session) { s.WalletCreds = []vctypes.Credential{walletCred("c9", "Cached")} })
		rr = httptest.NewRecorder()
		h.ShowPresent(rr, issueGET("/holder/present", true, cookies))
		if !strings.Contains(rr.Body.String(), `value="c9"`) || len(ad.holderKeys) != 1 {
			t.Fatalf("body=%s keys=%v", rr.Body.String(), ad.holderKeys)
		}
	})
}

func TestConfirmPresent(t *testing.T) {
	post := func(h *H, v url.Values, cookies []*http.Cookie) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.ConfirmPresent(rr, formPost("/holder/present/confirm", v, cookies...))
		return rr
	}
	full := url.Values{"credential_id": {"c1"}, "request_uri": {"openid4vp://req"}}
	t.Run("redirect and validation", func(t *testing.T) {
		h, cookies := walletH(t, &walletAdapter{}, func(s *Session) { s.HolderDpg = "" })
		if rr := post(h, full, cookies); rr.Header().Get("HX-Redirect") != "/holder/dpg" {
			t.Fatalf("redirect=%q", rr.Header().Get("HX-Redirect"))
		}
		h, cookies = walletH(t, &walletAdapter{}, nil)
		if rr := post(h, url.Values{"credential_id": {"c1"}}, cookies); !strings.Contains(rr.Header().Get("HX-Trigger"), "Pick a credential") {
			t.Fatalf("trigger=%q", rr.Header().Get("HX-Trigger"))
		}
	})
	t.Run("no previewer → fallback card titled from the session", func(t *testing.T) {
		h, cookies := walletH(t, &walletAdapter{}, func(s *Session) { s.WalletCreds = []vctypes.Credential{walletCred("c1", "Person")} })
		rr := post(h, full, cookies)
		// The fallback preview is not Compatible, so the card renders in its
		// incompatible state (no Disclose form with the request_uri).
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), ">Person</h3>") || !strings.Contains(rr.Body.String(), "present-consent incompatible") || strings.Contains(rr.Body.String(), `value="openid4vp://req"`) {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("previewer error and success", func(t *testing.T) {
		pa := &walletPreviewAdapter{walletAdapter: &walletAdapter{}, previewErr: errors.New("pd unreachable")}
		h, cookies := walletH(t, pa, nil)
		if rr := post(h, full, cookies); !strings.Contains(rr.Header().Get("HX-Trigger"), "pd unreachable") {
			t.Fatalf("trigger=%q", rr.Header().Get("HX-Trigger"))
		}
		pa.previewErr = nil
		pa.preview = backend.PresentationPreview{CredentialID: "c1", CredentialTitle: "Previewed", VerifierClientID: "verifier.example", Compatible: true, Disclosure: "required"}
		rr := post(h, full, cookies)
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), ">Previewed</h3>") || !strings.Contains(rr.Body.String(), "requested by verifier.example") || !strings.Contains(rr.Body.String(), `value="openid4vp://req"`) {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestSubmitPresent(t *testing.T) {
	post := func(h *H, v url.Values, cookies []*http.Cookie) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.SubmitPresent(rr, formPost("/holder/present", v, cookies...))
		return rr
	}
	full := url.Values{"credential_id": {"c1"}, "request_uri": {"openid4vp://req"}}
	h, cookies := walletH(t, &walletAdapter{}, func(s *Session) { s.HolderDpg = "" })
	if rr := post(h, full, cookies); rr.Header().Get("HX-Redirect") != "/holder/dpg" {
		t.Fatalf("redirect=%q", rr.Header().Get("HX-Redirect"))
	}
	ad := &walletAdapter{presentErr: errors.New("verifier rejected")}
	h, cookies = walletH(t, ad, func(s *Session) { s.WalletCreds = []vctypes.Credential{walletCred("c1", "Person")} })
	if rr := post(h, url.Values{"request_uri": {"x"}}, cookies); !strings.Contains(rr.Header().Get("HX-Trigger"), "Pick a credential") {
		t.Fatalf("trigger=%q", rr.Header().Get("HX-Trigger"))
	}
	if rr := post(h, full, cookies); !strings.Contains(rr.Header().Get("HX-Trigger"), "verifier rejected") {
		t.Fatalf("trigger=%q", rr.Header().Get("HX-Trigger"))
	}
	ad.presentErr = errors.New("policy failed: credential has been revoked")
	rr := post(h, full, cookies)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "<strong>Person</strong> can no longer be presented") || !strings.Contains(rr.Body.String(), "credential has been revoked") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	ad.presentErr = nil
	ad.presentRes = backend.PresentCredentialResult{Success: true, Method: "OID4VP · selective", SharedClaims: []string{"name"}, VerifierState: "st-9"}
	rr = post(h, full, cookies)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "Presentation sent") || !strings.Contains(rr.Body.String(), "st-9") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(ad.presented) != 3 || ad.presented[2].HolderDpg != "Example Wallet" || ad.presented[2].CredentialID != "c1" || ad.presented[2].RequestURI != "openid4vp://req" {
		t.Fatalf("presented=%+v", ad.presented)
	}
}

func TestIsRevocationErrorAndTitleLookup(t *testing.T) {
	if isRevocationError(nil) || isRevocationError(errors.New("other")) || !isRevocationError(errors.New("x: credential has been revoked")) {
		t.Fatal("isRevocationError wrong")
	}
	sess := &Session{WalletCreds: []vctypes.Credential{walletCred("c1", "Person")}}
	if credentialTitleFromSession(sess, "c1") != "Person" || credentialTitleFromSession(sess, "zz") != "" {
		t.Fatal("credentialTitleFromSession wrong")
	}
}

func TestDeclinePresent(t *testing.T) {
	h, _ := walletH(t, &walletAdapter{}, nil)
	rr := httptest.NewRecorder()
	h.DeclinePresent(rr, httptest.NewRequest(http.MethodPost, "/holder/present/decline", nil))
	if rr.Code != 200 || !strings.Contains(strings.ToLower(rr.Body.String()), "declined") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestDeleteCredential(t *testing.T) {
	post := func(h *H, id string, cookies []*http.Cookie) (*httptest.ResponseRecorder, *Session) {
		req := formPost("/holder/wallet/delete", url.Values{"credential_id": {id}}, cookies...)
		rr := httptest.NewRecorder()
		h.DeleteCredential(rr, req)
		return rr, sessionOf(h, req)
	}
	h, cookies := walletH(t, &walletAdapter{}, func(s *Session) { s.HolderDpg = "" })
	if rr, _ := post(h, "c1", cookies); rr.Header().Get("HX-Redirect") != "/holder/dpg" {
		t.Fatalf("redirect=%q", rr.Header().Get("HX-Redirect"))
	}
	ad := &walletAdapter{deleteErr: errors.New("locked"), creds: []vctypes.Credential{walletCred("c2", "Kept")}}
	h, cookies = walletH(t, ad, func(s *Session) {
		s.WalletCreds = []vctypes.Credential{walletCred("c1", "Gone"), walletCred("c2", "Kept")}
	})
	if rr, _ := post(h, "", cookies); !strings.Contains(rr.Header().Get("HX-Trigger"), "Missing credential id") {
		t.Fatalf("trigger=%q", rr.Header().Get("HX-Trigger"))
	}
	if rr, _ := post(h, "c1", cookies); !strings.Contains(rr.Header().Get("HX-Trigger"), "Delete failed: locked") {
		t.Fatalf("trigger=%q", rr.Header().Get("HX-Trigger"))
	}
	ad.deleteErr = nil
	rr, sess := post(h, "c1", cookies)
	if rr.Code != 200 || len(ad.deleted) != 2 || len(sess.WalletCreds) != 1 || sess.WalletCreds[0].ID != "c2" || strings.Contains(rr.Body.String(), `data-title="Gone"`) || !strings.Contains(rr.Body.String(), `data-title="Kept"`) {
		t.Fatalf("status=%d creds=%+v body=%s", rr.Code, sess.WalletCreds, rr.Body.String())
	}
}
