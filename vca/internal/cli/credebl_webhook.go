// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// The webhook of the shared agent (P6-C0c, ADR-058 decision 4). The
// Credo agent posts each event to <webhook>/<topic>, such as
// /credentials and /connections. The api gateway takes them at
// /wh/<organisation>/<topic> and finds the organisation of a tenant
// wallet from the context of the event. The shared agent belongs to the
// organisation of the platform admin, so its webhook names that
// organisation.
const (
	// CredeblPlatformOrgIDEnv holds the id of the organisation of the
	// platform admin in the stack .env.
	CredeblPlatformOrgIDEnv = "CREDEBL_PLATFORM_ORG_ID" //nolint:gosec // G101: a variable name, not a credential.
	// CredeblAgentWebhookEnv holds the webhook address of the shared
	// agent in the stack .env. The stack file passes it to the agent.
	CredeblAgentWebhookEnv = "CREDEBL_AGENT_WEBHOOK_URL" //nolint:gosec // G101: a variable name, not a credential.
	// CredeblAdapterOrgIDEnv holds the organisation of the adapter in the
	// .env of a CREDEBL pair.
	CredeblAdapterOrgIDEnv = "VCA_CREDEBL_ORG_ID" //nolint:gosec // G101: a variable name, not a credential.
	// credeblGatewayURL is the address of the api gateway on the network
	// of the stack.
	credeblGatewayURL = "http://credebl-api-gateway:5000" //nolint:gosec // G101: an address, not a credential.
	// credeblAgentService is the service of the shared agent.
	credeblAgentService = "credebl-agent" //nolint:gosec // G101: a service name, not a credential.
)

// credeblWebhookURL returns the webhook address of the shared agent for
// the organisation of the platform admin.
func credeblWebhookURL(platformOrg string) string {
	return credeblGatewayURL + "/wh/" + platformOrg
}

// pointAgentWebhook writes the webhook address of the shared agent into
// the stack .env. It reports whether the address changed, so the agent
// needs a restart. The generated values of the .env stay.
func pointAgentWebhook(opts BootstrapOptions, platformOrg string, result *BootstrapResult) (bool, error) {
	deploy := filepath.Dir(opts.Dir)
	stack, err := ReadStackEnv(deploy, configv1.Dpg_DPG_CREDEBL)
	if err != nil {
		return false, err
	}
	want := credeblWebhookURL(platformOrg)
	if stack[CredeblAgentWebhookEnv] == want && stack[CredeblPlatformOrgIDEnv] == platformOrg {
		result.step(opts.Out, "CREDEBL agent webhook present")
		return false, nil
	}
	stack[CredeblPlatformOrgIDEnv] = platformOrg
	stack[CredeblAgentWebhookEnv] = want
	text, err := StackEnv(configv1.Dpg_DPG_CREDEBL, stack, rand.Reader, time.Now())
	if err != nil {
		return false, err
	}
	path := filepath.Join(deploy, StackEnvFile(configv1.Dpg_DPG_CREDEBL))
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		return false, fmt.Errorf("write %s: %w", path, err)
	}
	result.step(opts.Out, "CREDEBL agent webhook set to %s", want)
	return true, nil
}

// setAdapterOrg writes the organisation of the deployment into the .env
// of the pair, where the adapter reads VCA_CREDEBL_ORG_ID. It reports
// whether the value changed. A pair without a .env gets the id printed.
func setAdapterOrg(opts BootstrapOptions, org credeblOrg, result *BootstrapResult) (bool, error) {
	path := filepath.Join(opts.Dir, EnvFileName)
	values, err := ReadExisting(filepath.Dir(opts.Dir), opts.Pair)
	if err != nil {
		return false, err
	}
	if _, statErr := os.Stat(path); errors.Is(statErr, fs.ErrNotExist) {
		result.step(opts.Out, "CREDEBL organisation %s has the id %s; set %s", org.Name, org.ID, CredeblAdapterOrgIDEnv)
		return false, nil
	}
	if strings.TrimSpace(values[CredeblAdapterOrgIDEnv]) == org.ID {
		result.step(opts.Out, "CREDEBL adapter organisation present")
		return false, nil
	}
	if err := SetEnvValueWith(path, CredeblAdapterOrgIDEnv, org.ID, "The organisation that vca dpg bootstrap credebl made."); err != nil {
		return false, err
	}
	result.step(opts.Out, "CREDEBL adapter organisation set: %s", org.Name)
	return true, nil
}

// restartCredebl recreates the named services of the pair, so they read
// the new values of the .env files.
func restartCredebl(ctx context.Context, opts BootstrapOptions, services []string) error {
	if len(services) == 0 {
		return nil
	}
	if opts.Run == nil {
		return errors.New("CREDEBL restart: no command runner")
	}
	root := filepath.Dir(filepath.Dir(opts.Dir))
	action := append([]string{"up", "-d", "--no-deps"}, services...)
	if err := opts.Run(ctx, "docker", ComposeArgs(root, opts.Pair, action)); err != nil {
		return fmt.Errorf("CREDEBL restart of %s: %w", strings.Join(services, ", "), err)
	}
	return nil
}
