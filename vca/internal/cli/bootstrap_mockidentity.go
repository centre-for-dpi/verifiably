// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/rand"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
)

// The eSignet of the Inji stack signs a holder in against the mock
// identity system 0.10.1. The CSV data provider of inji-certify-esignet
// reads the claims of a credential from the farmer data of the Certify
// release, by the individual id that the eSignet token carries. The
// bootstrap run adds each farmer of that file to the mock identity
// system, so a holder signs in with an individual id of the file and
// the one time code of the mock, and claims in Inji Web (P6-I7f).
const (
	// EnvBootstrapMockIdentityURL overrides the address of the mock
	// identity system. Empty means 127.0.0.1 and
	// INJI_MOCK_IDENTITY_HOST_PORT.
	EnvBootstrapMockIdentityURL = "VCA_BOOTSTRAP_MOCK_IDENTITY_URL"
	// mockIdentityDefaultPort is the host port of the stack file.
	mockIdentityDefaultPort = "17083"
	// mockIdentityPath is the identity API of the release.
	mockIdentityPath = "/v1/mock-identity-system/identity"
	// mockIdentityLanguage is the language code of the text fields.
	mockIdentityLanguage = "eng"
)

// sampleIdentitiesPath is the farmer data that the stack file mounts in
// inji-certify-esignet, beside the pair directories under deploy/.
func sampleIdentitiesPath(dir string) string {
	return filepath.Join(filepath.Dir(dir), "vca", "dpg", "inji", "certify", "farmer_identity_data.csv")
}

// addSampleIdentities adds each farmer of the sample data to the mock
// identity system. A farmer that the system holds counts as present, so
// a second run changes nothing. A deploy root without the stack file
// skips the step.
func addSampleIdentities(ctx context.Context, opts BootstrapOptions, result *BootstrapResult) error {
	path := sampleIdentitiesPath(opts.Dir)
	rows, err := readSampleIdentities(path)
	if errors.Is(err, fs.ErrNotExist) {
		result.step(opts.Out, "No sample identities at %s. The mock identity system keeps what it holds", path)
		return nil
	}
	if err != nil {
		return err
	}
	base := strings.TrimRight(opts.value(EnvBootstrapMockIdentityURL,
		"http://"+LoopbackAddress+":"+opts.value("INJI_MOCK_IDENTITY_HOST_PORT", mockIdentityDefaultPort)), "/")
	added, present := 0, 0
	for _, row := range rows {
		identity, ierr := mockIdentity(row)
		if ierr != nil {
			return ierr
		}
		body, merr := json.Marshal(map[string]any{
			"requestTime": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), "request": identity,
		})
		if merr != nil {
			return fmt.Errorf("encode the mock identity: %w", merr)
		}
		status, raw, derr := doStatus(ctx, opts.client(), http.MethodPost, base+mockIdentityPath, "", body)
		if derr != nil || status < 200 || status > 299 {
			return fmt.Errorf("add the identity %s to the mock identity system at %s (status %d): %w; set %s to its address",
				row["id"], base, status, derr, EnvBootstrapMockIdentityURL)
		}
		var answer struct {
			Errors []struct {
				ErrorCode string `json:"errorCode"`
			} `json:"errors"`
		}
		if uerr := json.Unmarshal(raw, &answer); uerr != nil {
			return fmt.Errorf("read the answer of the mock identity system: %w", uerr)
		}
		switch {
		case len(answer.Errors) == 0:
			added++
		case answer.Errors[0].ErrorCode == "duplicate_individual_id":
			present++
		default:
			return fmt.Errorf("add the identity %s to the mock identity system: %s", row["id"], answer.Errors[0].ErrorCode)
		}
	}
	result.step(opts.Out, "Mock identities: %d added, %d present. Sign in at the eSignet login page with an individual id of %s",
		added, present, path)
	return nil
}

// readSampleIdentities reads the rows of the farmer data by column name.
func readSampleIdentities(path string) ([]map[string]string, error) {
	f, err := os.Open(path) // #nosec G304 -- the path comes from the deploy root
	if err != nil {
		return nil, err
	}
	defer func() { anyval.Discard(f.Close()) }()
	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(records) < 2 {
		return nil, fmt.Errorf("read %s: no identity", path)
	}
	out := make([]map[string]string, 0, len(records)-1)
	for _, record := range records[1:] {
		row := map[string]string{}
		for i, name := range records[0] {
			if i < len(record) {
				row[name] = strings.TrimSpace(record[i])
			}
		}
		out = append(out, row)
	}
	return out, nil
}

// mockIdentity maps one farmer onto the identity schema of the mock
// identity system 0.10.1, which needs every field. The PIN and the
// password are random: a holder signs in with the one time code.
func mockIdentity(row map[string]string) (map[string]any, error) {
	pin, err := randomDigits(6)
	if err != nil {
		return nil, err
	}
	password, err := RandomSecret(rand.Reader)
	if err != nil {
		return nil, err
	}
	names := strings.Fields(row["fullName"])
	if row["id"] == "" || len(names) == 0 {
		return nil, fmt.Errorf("a sample identity has no id or no name: %v", row)
	}
	given, family := names[0], names[len(names)-1]
	text := func(v string) []map[string]string {
		return []map[string]string{{"language": mockIdentityLanguage, "value": v}}
	}
	return map[string]any{
		"individualId": row["id"], "pin": pin, "password": password, "preferredLang": mockIdentityLanguage,
		"fullName": text(row["fullName"]), "givenName": text(given), "familyName": text(family),
		"middleName": text(given), "nickName": text(given), "preferredUsername": text(given),
		"gender": text(row["gender"]), "dateOfBirth": mockDate(row["dateOfBirth"]),
		"streetAddress": text(row["villageOrTown"]), "locality": text(row["district"]), "region": text(row["state"]),
		// The farmers of the release live in states of India.
		"country": text("India"), "postalCode": row["postalCode"], "encodedPhoto": row["face"],
		"email": "farmer." + row["id"] + "@example.org", "phone": "+91" + row["mobileNumber"],
		"zoneInfo": "Asia/Kolkata", "locale": "en_IN",
	}, nil
}

// mockDate turns the day-month-year date of the farmer data into the
// year/month/day date of the mock identity system.
func mockDate(raw string) string {
	parsed, err := time.Parse("02-01-2006", raw)
	if err != nil {
		return raw
	}
	return parsed.Format("2006/01/02")
}

// randomDigits returns n random decimal digits.
func randomDigits(n int) (string, error) {
	var b strings.Builder
	for i := 0; i < n; i++ {
		d, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", fmt.Errorf("generate a PIN: %w", err)
		}
		b.WriteString(d.String())
	}
	return b.String(), nil
}
