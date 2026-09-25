// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit/uikittest"
	"github.com/centre-for-dpi/vc-adapters/ui"
)

// TestAppFailsOnBadThemeFile proves the service stops at start when the
// theme file fails a kit pairing, and that the error names the pairing.
func TestAppFailsOnBadThemeFile(t *testing.T) {
	path := uikittest.LowContrastFile(t)
	cfg := settings(t, nil)
	cfg.ThemeFile = path
	_, err := Build(cfg, testDeps())
	uikittest.AssertBadThemeError(t, err, path)
}

// cookieGet answers one GET, with the session cookie when token is set.
func cookieGet(a *App, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.AddCookie(&http.Cookie{Name: staffsession.IssuerCookie, Value: token})
	}
	rec := httptest.NewRecorder()
	a.Mux.ServeHTTP(rec, req)
	return rec
}

// TestSourcesPagesNeedSession proves the pages sit behind the guard of
// issuer-auth: no session goes to the sign in chooser, a session of
// issuer-auth opens the page, and the assets need no session.
func TestSourcesPagesNeedSession(t *testing.T) {
	issuer := staff(t)
	deps := testDeps()
	deps.SessionKeys = issuer.Keys()
	a, err := Build(settings(t, map[string]string{
		"VCA_DATASOURCE_LOGIN_URL":    "https://issuer.example/auth/",
		"VCA_DATASOURCE_SCHEMA_URL":   "http://schema-registry:8080",
		"VCA_DATASOURCE_ISSUANCE_URL": "http://issuance:8080",
	}), deps)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/sources/", "/sources/new?kind=http"} {
		rec := cookieGet(a, path, "")
		if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "https://issuer.example/auth/?return_to=") {
			t.Errorf("%s without a session: status %d location %q", path, rec.Code, rec.Header().Get("Location"))
		}
		if rec := cookieGet(a, path, issuer.Token(t, "kc|wanjiru", "issuer-operator")); rec.Code != http.StatusOK {
			t.Errorf("%s with a session: status %d %s", path, rec.Code, rec.Body.String())
		}
	}
	if rec := cookieGet(a, ui.Prefix+"vca.css", ""); rec.Code != http.StatusOK {
		t.Errorf("the stylesheet: status %d", rec.Code)
	}
}

// TestCsvUploadThroughTheGuard proves an upload passes the guard with
// its synchronizer token and lands as a file in the CSV directory, and
// that the guard refuses a body far over the cap.
func TestCsvUploadThroughTheGuard(t *testing.T) {
	issuer := staff(t)
	deps := testDeps()
	deps.SessionKeys = issuer.Keys()
	dir := filepath.Join(t.TempDir(), "csv")
	a, err := Build(settings(t, map[string]string{"VCA_DATASOURCE_CSV_DIR": dir, "VCA_DATASOURCE_CSV_MAX_BYTES": "2048"}), deps)
	if err != nil {
		t.Fatal(err)
	}
	token := issuer.Token(t, "kc|wanjiru", "issuer-operator")
	form := cookieGet(a, "/sources/new?kind=csv", token)
	m := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(form.Body.String())
	if m == nil {
		t.Fatalf("no token in the form: %s", form.Body.String())
	}
	send := func(file string) *httptest.ResponseRecorder {
		var body bytes.Buffer
		w := multipart.NewWriter(&body)
		for k, v := range map[string]string{"csrf_token": m[1], "name": "Farmers", "header": "yes"} {
			if werr := w.WriteField(k, v); werr != nil {
				t.Fatal(werr)
			}
		}
		part, perr := w.CreateFormFile("file", "farmers.csv")
		if perr != nil {
			t.Fatal(perr)
		}
		if _, werr := part.Write([]byte(file)); werr != nil {
			t.Fatal(werr)
		}
		if cerr := w.Close(); cerr != nil {
			t.Fatal(cerr)
		}
		req := httptest.NewRequest(http.MethodPost, "/sources/new/csv", &body)
		req.Header.Set("Content-Type", w.FormDataContentType())
		req.AddCookie(&http.Cookie{Name: staffsession.IssuerCookie, Value: token})
		rec := httptest.NewRecorder()
		a.Mux.ServeHTTP(rec, req)
		return rec
	}
	rec := send("name,farmer_id\nWanjiku Njeri,FM-0042\n")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 || !strings.HasSuffix(files[0].Name(), ".csv") {
		t.Fatalf("csv directory = %v, %v", files, err)
	}
	if rec := send(strings.Repeat("x", 2<<20)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("a body over the cap: status %d", rec.Code)
	}
}

func TestCsvSaverReportsAFailure(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := csvSaver(filepath.Join(file, "csv"))([]byte("a")); err == nil {
		t.Error("a directory under a file must fail")
	}
}
