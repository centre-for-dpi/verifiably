// SPDX-License-Identifier: Apache-2.0

package credebl

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

func TestSessionCallsReadTheDocumentedAnswers(t *testing.T) {
	f := fake.New("../../testdata")
	t.Cleanup(f.Close)
	c := New(Options{
		HTTP:       dpgclient.New(dpgclient.Options{BaseURL: f.URL(), HTTP: f.Client(), Retries: -1, Sleep: func(time.Duration) {}}),
		Account:    Account{Email: "e", Password: "p", CryptoKey: "k"},
		OrgID:      "org-1",
		RandomSalt: func() ([]byte, error) { return fixedSalt, nil },
	})
	ctx := context.Background()
	s, err := c.OfferSession(ctx, "a1b2c3d4-0000-4e5f-8a9b-000000000001")
	if err != nil || s.State != "OfferUriRetrieved" || s.ExpiresAt == nil || len(s.Metadata.Credentials) != 1 ||
		s.Metadata.Credentials[0].SupportedID != "RegistrationCertificate" {
		t.Errorf("OfferSession = %+v, %v", s, err)
	}
	all, err := c.OfferSessions(ctx)
	if err != nil || len(all) != 5 || all[0].State != SessionCompleted || all[2].State != SessionError || all[2].ErrorMessage == "" {
		t.Errorf("OfferSessions = %+v, %v", all, err)
	}
	// The revocable session names its status list entry (P6-C5b).
	if got := all[4].Metadata.StatusLists; len(got) != 1 || got[0].ListID == "" || got[0].Index != 4211 {
		t.Errorf("status lists = %+v", got)
	}
	if err := c.RevokeSession(ctx, all[4].ID); err != nil {
		t.Errorf("RevokeSession: %v", err)
	}
	if !slices.Contains(f.Calls(), "POST /v1/orgs/org-1/openid4vc/issuance-sessions/"+all[4].ID+"/revoke") {
		t.Errorf("calls = %v", f.Calls())
	}
}

func TestSessionCallsReportProblems(t *testing.T) {
	var none *Client
	ctx := context.Background()
	if _, err := none.OfferSession(ctx, "s"); !errors.Is(err, ErrNoPlatform) {
		t.Errorf("OfferSession = %v", err)
	}
	if _, err := none.OfferSessions(ctx); !errors.Is(err, ErrNoPlatform) {
		t.Errorf("OfferSessions = %v", err)
	}
	if err := none.RevokeSession(ctx, "s"); !errors.Is(err, ErrNoPlatform) {
		t.Errorf("RevokeSession = %v", err)
	}
	empty := orgServer(t, func(w http.ResponseWriter, _ *http.Request) { mustWrite(t, w, []byte(`{"data":{}}`)) })
	if _, err := newClient(empty, nil).OfferSession(ctx, "s"); err == nil {
		t.Error("a session answer with no id passed")
	}
	failing := orgServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) })
	fc := newClient(failing, nil)
	if _, err := fc.OfferSession(ctx, "s"); err == nil {
		t.Error("a failed session read passed")
	}
	if _, err := fc.OfferSessions(ctx); err == nil {
		t.Error("a failed session list passed")
	}
}
