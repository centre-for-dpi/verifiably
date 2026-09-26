// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"slices"
	"strings"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// P6-C3: the CREDEBL platform mails an out of band offer through the
// mail provider that the operator names in the stack .env. Setup keeps
// those values, and turns the email channel of the adapter on when the
// stack names a provider.

// TestStackEnvKeepsTheValuesOfTheOperator: a value the operator added to
// a stack .env survives a later setup run.
func TestStackEnvKeepsTheValuesOfTheOperator(t *testing.T) {
	existing := map[string]string{
		"EMAIL_PROVIDER": "smtp", "SMTP_HOST": "smtp.registry.gov.test", "SMTP_PASS": "operator-secret",
		StackSecretsSinceEnv: "2026-09-26T12:00:00Z",
	}
	text, err := StackEnv(configv1.Dpg_DPG_CREDEBL, existing, rand.Reader, secretsTime)
	if err != nil {
		t.Fatal(err)
	}
	values, err := ParseDotenv(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range existing {
		if values[name] != want {
			t.Errorf("%s = %q, want %q", name, values[name], want)
		}
	}
	// A generated value appears once.
	if strings.Count(text, "\nCRYPTO_PRIVATE_KEY=") != 1 || strings.Count(text, StackSecretsSinceEnv+"=") != 1 {
		t.Errorf("a value repeats:\n%s", text)
	}
	if !strings.Contains(text, "# The values of the operator.") {
		t.Errorf("no section for the values of the operator:\n%s", text)
	}
}

// TestCredeblPairGetsMailOffers: the adapter lists the email channel
// only when the stack .env names a mail provider.
func TestCredeblPairGetsMailOffers(t *testing.T) {
	stack := map[string]string{PlatformAdminEmailEnv: credeblAdmin, PlatformAdminPasswordEnv: "p", "CRYPTO_PRIVATE_KEY": "k"}
	if got := CredeblAdapterValues(credeblPair(commonv1.Role_ROLE_ISSUER), stack); got[CredeblMailOffersEnv] != "" {
		t.Errorf("mail offers on without a provider: %v", got)
	}
	stack["EMAIL_PROVIDER"] = "resend"
	if got := CredeblAdapterValues(credeblPair(commonv1.Role_ROLE_ISSUER), stack); got[CredeblMailOffersEnv] != "true" {
		t.Errorf("mail offers off with a provider: %v", got)
	}
}

// TestCredeblStackKeepsFilesOnAVolume: the platform keeps the
// invitations of an email offer and the files of a bulk issuance on one
// volume that every platform service shares, and the initialisation
// gives that volume to the user of the images.
func TestCredeblStackKeepsFilesOnAVolume(t *testing.T) {
	doc, _ := readCredeblStack(t)
	for name, svc := range doc.Services {
		if !strings.HasPrefix(svc.Image, "ghcr.io/credebl/") || name == credeblAgentService || name == "credebl-schema-file-server" {
			continue
		}
		if !slices.Contains(svc.Volumes, "credebl-files:/app/uploadedFiles") {
			t.Errorf("%s volumes = %v", name, svc.Volumes)
		}
		if svc.Environment["FILE_STORAGE_TYPE"] != "local" {
			t.Errorf("%s keeps files in %q", name, svc.Environment["FILE_STORAGE_TYPE"])
		}
	}
	if seed := strings.Join(doc.Services["credebl-seed"].Command, " "); !strings.Contains(seed, "chown 1001:1001 /app/uploadedFiles") ||
		!strings.Contains(seed, "prisma db seed") {
		t.Errorf("credebl-seed command = %q", seed)
	}
}
