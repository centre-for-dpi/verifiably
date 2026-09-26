// SPDX-License-Identifier: Apache-2.0

package authz_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/authz"
)

// publishedKids returns the kids of the key set the server publishes,
// and checks that a cache may keep it one minute.
func (h *harness) publishedKids(srv *authz.Server) []string {
	h.t.Helper()
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if got := res.Header().Get("Cache-Control"); got != "max-age=60" {
		h.t.Errorf("the key set has Cache-Control %q, want max-age=60", got)
	}
	set, err := jose.ParseJWKS(res.Body.Bytes())
	if err != nil {
		h.t.Fatal(err)
	}
	var kids []string
	for _, k := range set.Keys {
		kids = append(kids, k.KeyID)
	}
	return kids
}

// tokenKid claims an offer and returns the kid of the access token.
func (h *harness) tokenKid(offer string) string {
	h.t.Helper()
	h.addOffer(offer, "amina@example.org")
	_, answer := h.claimToken(offer)
	hdr, err := jose.PeekHeader(anyval.As[string](answer["access_token"]))
	if err != nil {
		h.t.Fatal(err)
	}
	return hdr.Kid
}

// TestTheTokenKeyRotates is finding 9 of the review: the token key had
// no rotation. A rotation publishes the next key at once and signs with
// it once the key set cache of Certify has ended. The old key stays in
// the key set until its last token has expired (ADR-056 decision 6).
func TestTheTokenKeyRotates(t *testing.T) {
	h := newHarness(t)
	first := h.publishedKids(h.srv)
	if len(first) != 1 {
		t.Fatalf("kids = %v", first)
	}
	rot, err := h.srv.Rotate(context.Background(), false)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if rot.Kid == first[0] || !rot.ActiveFrom.Equal(h.clock().Add(authz.PublishLead)) || authz.PublishLead < 5*time.Minute {
		t.Fatalf("rotation = %+v", rot)
	}
	if kids := h.publishedKids(h.srv); strings.Join(kids, ",") != first[0]+","+rot.Kid {
		t.Fatalf("after the rotation kids = %v", kids)
	}
	if kid := h.tokenKid("offer-1"); kid != first[0] {
		t.Fatalf("a token before the switch has kid %s, want the old key", kid)
	}
	h.advance(authz.PublishLead)
	if kid := h.tokenKid("offer-2"); kid != rot.Kid {
		t.Fatalf("a token after the switch has kid %s, want the new key", kid)
	}
	if kids := h.publishedKids(h.srv); len(kids) != 2 {
		t.Fatalf("the old key left before its tokens expired: %v", kids)
	}
	// A second start reads the ring.
	again := h.build(t, h.kv)
	if kids := h.publishedKids(again); len(kids) != 2 {
		t.Fatalf("the restart published %v", kids)
	}
	h.advance(authz.TokenTTL + time.Minute)
	if kids := h.publishedKids(h.srv); strings.Join(kids, ",") != rot.Kid {
		t.Fatalf("after the tokens expired kids = %v", kids)
	}
	// The next rotation drops the retired key from the store.
	if _, err := h.srv.Rotate(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	raw := anyval.Must(h.kv.Get(context.Background(), "authz/keys"))
	if strings.Contains(string(raw), first[0]) {
		t.Fatal("the store keeps a retired key")
	}
}

// TestAnImmediateRotationDropsTheOldKey: after a compromise the next key
// signs at once and the old key leaves the key set.
func TestAnImmediateRotationDropsTheOldKey(t *testing.T) {
	h := newHarness(t)
	old := h.publishedKids(h.srv)[0]
	rot, err := h.srv.Rotate(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if kids := h.publishedKids(h.srv); strings.Join(kids, ",") != rot.Kid || rot.Kid == old {
		t.Fatalf("kids = %v, rotation = %+v", kids, rot)
	}
	if kid := h.tokenKid("offer-1"); kid != rot.Kid {
		t.Fatalf("kid = %s", kid)
	}
}

// TestAnotherReplicaPicksUpTheRotation: a second server on the same
// store reads the ring again at its sweep.
func TestAnotherReplicaPicksUpTheRotation(t *testing.T) {
	h := newHarness(t)
	replica := h.build(t, h.kv)
	rot, err := h.srv.Rotate(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if kids := h.publishedKids(replica); len(kids) != 1 {
		t.Fatalf("the replica knew the rotation before its sweep: %v", kids)
	}
	if _, err := replica.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if kids := h.publishedKids(replica); len(kids) != 2 || kids[1] != rot.Kid {
		t.Fatalf("the replica publishes %v", kids)
	}
}

// TestTheRotationEndpointNeedsTheRotationToken: the adapter serves the
// rotation on the compose network only. The caller proves that it holds
// the pair session key with a token derived from it.
func TestTheRotationEndpointNeedsTheRotationToken(t *testing.T) {
	h := newHarness(t)
	srv := httptest.NewServer(h.srv.RotationHandler())
	defer srv.Close()
	call := func(method, token string, q url.Values) (int, map[string]any) {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), method, srv.URL+"?"+q.Encode(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { anyval.Discard(res.Body.Close()) }()
		var out map[string]any
		anyval.Discard(json.NewDecoder(res.Body).Decode(&out))
		return res.StatusCode, out
	}
	good := authz.RotationToken([]byte(pairSeal))
	if status, _ := call(http.MethodPost, "", nil); status != http.StatusUnauthorized {
		t.Errorf("no token = %d", status)
	}
	if status, _ := call(http.MethodPost, authz.RotationToken([]byte("another pair key of 32 characters")), nil); status != http.StatusUnauthorized {
		t.Errorf("another token = %d", status)
	}
	if status, _ := call(http.MethodGet, good, nil); status != http.StatusMethodNotAllowed {
		t.Errorf("GET = %d", status)
	}
	status, out := call(http.MethodPost, good, url.Values{"immediate": {"true"}})
	if status != http.StatusOK || out["kid"] == "" || out["active_from"] == nil {
		t.Fatalf("rotation = %d %v", status, out)
	}
	if kids := h.publishedKids(h.srv); len(kids) != 1 || kids[0] != out["kid"] {
		t.Fatalf("kids = %v", kids)
	}
	// The token is the HMAC-SHA256 of a fixed label under the pair key.
	// vca dpg rotate-authz-key derives the same value.
	if got := authz.RotationToken([]byte("0123456789abcdef0123456789abcdef")); got != rotationVector {
		t.Fatalf("RotationToken = %s", got)
	}
}

// rotationVector is RotationToken of the pair key
// 0123456789abcdef0123456789abcdef, computed outside Go.
const rotationVector = "4c0348ddce94c73e91889f24f0332df15fa06b52c2a6878f3733b4449fe3b0b3"

// TestRotationFailures: a store that fails stops a rotation and a sweep,
// and the endpoint answers 500. A failed code whose issuer side fails
// is logged, and the server goes on.
func TestRotationFailures(t *testing.T) {
	kv := &brokenStore{KeyValue: storeMemory()}
	h := newHarnessWith(t, harnessOptions{kv: kv})
	kv.set("authz/keys")
	if _, err := h.srv.Rotate(context.Background(), false); err == nil {
		t.Error("Rotate worked on a broken store")
	}
	if _, err := h.srv.Sweep(context.Background()); err == nil {
		t.Error("Sweep worked on a broken store")
	}
	srv := httptest.NewServer(h.srv.RotationHandler())
	defer srv.Close()
	req := anyval.Must(http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, nil))
	req.Header.Set("Authorization", "Bearer "+authz.RotationToken([]byte(pairSeal)))
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	anyval.Discard(res.Body.Close())
	if res.StatusCode != http.StatusInternalServerError {
		t.Errorf("the endpoint = %d", res.StatusCode)
	}
	kv.set()
	// A ring that holds no key, or that is no JSON, stops the start.
	for _, raw := range []string{`{"keys":[]}`, "{"} {
		if err := kv.Put(context.Background(), "authz/keys", []byte(raw)); err != nil {
			t.Fatal(err)
		}
		if _, err := authz.New(context.Background(), h.options(kv)); err == nil || !strings.Contains(err.Error(), "open the token key") {
			t.Errorf("%s: New = %v", raw, err)
		}
		// A rotation adds a key to an empty ring, and fails on a broken one.
		if _, err := h.srv.Rotate(context.Background(), false); (err == nil) != (raw != "{") {
			t.Errorf("%s: Rotate = %v", raw, err)
		}
	}
}

// TestABurntCodeWithABrokenIssuerSideIsLogged: when the row cannot go or
// the offer cannot open, the server logs it and answers the wallet.
func TestABurntCodeWithABrokenIssuerSideIsLogged(t *testing.T) {
	h := newHarness(t)
	h.addOffer("offer-1", "amina@example.org")
	r := newRequest(publicClient, walletCallback)
	r.issuerState = "offer-1"
	back := h.signIn(r)
	h.issuer.mu.Lock()
	h.issuer.brokenReopen = true
	h.issuer.mu.Unlock()
	form := codeForm(r, back.Query().Get("code"))
	form.Set("redirect_uri", "https://wallet.example.org/other")
	if status, _ := h.token(form); status != http.StatusBadRequest {
		t.Fatalf("token = %d", status)
	}
	if logs := h.logs.String(); !strings.Contains(logs, "stays closed") || !strings.Contains(logs, "row of a failed code stays") {
		t.Fatalf("logs = %s", logs)
	}
}

// TestMetadataAtTheWellKnownPaths: the server names the RFC 8414 paths
// of its issuer and serves the metadata there and under the appended
// openid-configuration name (review finding 10).
func TestMetadataAtTheWellKnownPaths(t *testing.T) {
	h := newHarness(t)
	paths := h.srv.WellKnownPaths()
	if strings.Join(paths, " ") != "/.well-known/oauth-authorization-server/authz /.well-known/openid-configuration/authz" {
		t.Fatalf("paths = %v", paths)
	}
	for _, c := range []struct {
		handler http.Handler
		path    string
	}{
		{h.srv.MetadataHandler(), paths[0]},
		{h.srv.Handler(), "/.well-known/openid-configuration"},
	} {
		path := c.path
		res := httptest.NewRecorder()
		c.handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, path, nil))
		var meta map[string]any
		if err := json.Unmarshal(res.Body.Bytes(), &meta); err != nil || meta["issuer"] != h.web.URL+"/authz" {
			t.Errorf("%s = %d %s", path, res.Code, res.Body.String())
		}
	}
}
