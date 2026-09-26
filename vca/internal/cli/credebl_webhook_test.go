// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"

	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// P6-C0c and ADR-058 decision 4: the shared agent sends its events to
// /wh/<organisation> of the api gateway, with the organisation of the
// platform admin, so the platform records the state of each DIDComm and
// OID4VC exchange.

func TestBootstrapCredeblPointsTheAgentWebhook(t *testing.T) {
	state := &credeblState{}
	server := fakeCredebl(t, state)
	defer server.Close()
	var out bytes.Buffer
	opts := credeblOptions(t, server.URL, &out)
	var runs []string
	opts.Run = func(_ context.Context, name string, args []string) error {
		runs = append(runs, name+" "+strings.Join(args, " "))
		return nil
	}
	if _, err := BootstrapCredebl(context.Background(), opts); err != nil {
		t.Fatalf("BootstrapCredebl: %v", err)
	}
	deploy := filepath.Dir(opts.Dir)
	stack, err := ReadStackEnv(deploy, configv1.Dpg_DPG_CREDEBL)
	if err != nil {
		t.Fatal(err)
	}
	if stack[CredeblPlatformOrgIDEnv] != credeblPlatformOrgID {
		t.Errorf("%s = %q", CredeblPlatformOrgIDEnv, stack[CredeblPlatformOrgIDEnv])
	}
	want := "http://credebl-api-gateway:5000/wh/" + credeblPlatformOrgID
	if stack[CredeblAgentWebhookEnv] != want {
		t.Errorf("%s = %q, want %q", CredeblAgentWebhookEnv, stack[CredeblAgentWebhookEnv], want)
	}
	// The generated secrets stay.
	for _, name := range []string{"CRYPTO_PRIVATE_KEY", PlatformAdminPasswordEnv, SharedAgentAPIKeyEnv} {
		if len(stack[name]) != stackSecretLength {
			t.Errorf("the run lost %s", name)
		}
	}
	if len(runs) != 2 || !strings.Contains(runs[1], "up -d --no-deps "+credeblAgentService) {
		t.Fatalf("runs = %q, want the initialisation, then the restart of the agent", runs)
	}
	// The adapter of the pair works in the organisation of the
	// deployment, and restarts with it.
	pair, err := ReadExisting(deploy, opts.Pair)
	if err != nil {
		t.Fatal(err)
	}
	if pair[CredeblAdapterOrgIDEnv] != "id-vca-issuer" {
		t.Errorf("%s = %q", CredeblAdapterOrgIDEnv, pair[CredeblAdapterOrgIDEnv])
	}
	steps := out.String()
	for _, line := range []string{"CREDEBL agent webhook set to " + want, "CREDEBL adapter organisation set: vca-issuer"} {
		if !strings.Contains(steps, line) {
			t.Errorf("steps lack %q:\n%s", line, steps)
		}
	}
	// A second run finds both and restarts nothing.
	out.Reset()
	runs = nil
	if _, again := BootstrapCredebl(context.Background(), opts); again != nil {
		t.Fatalf("second BootstrapCredebl: %v", again)
	}
	if len(runs) != 0 {
		t.Errorf("the second run ran %q", runs)
	}
	for _, line := range []string{"CREDEBL agent webhook present", "CREDEBL adapter organisation present"} {
		if !strings.Contains(out.String(), line) {
			t.Errorf("steps lack %q:\n%s", line, out.String())
		}
	}
	// A later setup run keeps the values that the bootstrap run wrote.
	text, err := StackEnv(configv1.Dpg_DPG_CREDEBL, stack, rand.Reader, secretsTime)
	if err != nil {
		t.Fatal(err)
	}
	later, err := ParseDotenv(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{CredeblPlatformOrgIDEnv, CredeblAgentWebhookEnv} {
		if later[name] != stack[name] {
			t.Errorf("setup dropped %s", name)
		}
	}
}

// TestCredeblAgentReadsTheWebhook: the shared agent reads its webhook
// address from the stack .env, and runs without one before the first
// bootstrap run.
func TestCredeblAgentReadsTheWebhook(t *testing.T) {
	doc, _ := readCredeblStack(t)
	agent := doc.Services[credeblAgentService]
	if got := agent.Environment["AFJ_REST_WEBHOOK_URL"]; got != "${"+CredeblAgentWebhookEnv+":-}" {
		t.Errorf("AFJ_REST_WEBHOOK_URL = %q", got)
	}
}
