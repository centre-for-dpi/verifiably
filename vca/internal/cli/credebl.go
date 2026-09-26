// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// The CREDEBL platform admin and the first data of the platform
// (ADR-055 decision 4, plan section 3.8). The database initialisation
// of the CREDEBL release makes the platform admin from
// PLATFORM_ADMIN_EMAIL, with the roles, the agent types and the ledgers
// of the platform. The API gateway runs the migrations only, so vca dpg
// bootstrap credebl runs the initialisation once.

const (
	// PlatformAdminEmailSetting is the setting that names the platform
	// admin. It has no default.
	PlatformAdminEmailSetting = "VCA_CREDEBL_PLATFORM_ADMIN_EMAIL"
	// PlatformAdminEmailEnv is the variable of the CREDEBL stack .env
	// that the database initialisation reads.
	PlatformAdminEmailEnv = "PLATFORM_ADMIN_EMAIL"
	// PlatformInitMarker is the file under the deploy root that records
	// the initialisation. A run that finds it skips the initialisation.
	PlatformInitMarker = "credebl/initialised"
	// platformInitService is the container whose image holds the
	// initialisation script of the release.
	platformInitService = "credebl-api-gateway"
	// platformInitCommand runs the initialisation of the release in its
	// folder. The release names the script so.
	platformInitCommand = "cd libs/prisma-service && npx prisma db seed"
)

// credeblPlatformAdmin returns the platform admin of a bootstrap run: the user
// of the environment, else the platform admin of the CREDEBL stack .env.
// No placeholder exists.
func credeblPlatformAdmin(opts BootstrapOptions) (string, error) {
	if user := opts.value(EnvBootstrapUser, ""); user != "" {
		return user, nil
	}
	stack, err := ReadStackEnv(filepath.Dir(opts.Dir), configv1.Dpg_DPG_CREDEBL)
	if err != nil {
		return "", err
	}
	if email := strings.TrimSpace(stack[PlatformAdminEmailEnv]); email != "" {
		return email, nil
	}
	return "", fmt.Errorf("CREDEBL sign in: run vca setup --role %s --dpg credebl with %s, or set %s",
		ShortName(opts.Pair.Role.String()), PlatformAdminEmailSetting, EnvBootstrapUser)
}

// initCredebl runs the database initialisation of the CREDEBL release
// once. The container of the API gateway reads the stack .env, so the
// script sees the platform admin and the generated secrets. A later run
// finds the marker and skips it. A failed run writes no marker.
func initCredebl(ctx context.Context, opts BootstrapOptions, result *BootstrapResult) error {
	deploy := filepath.Dir(opts.Dir)
	marker := filepath.Join(deploy, PlatformInitMarker)
	if _, err := os.Stat(marker); err == nil {
		result.step(opts.Out, "CREDEBL database initialisation present")
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read %s: %w", marker, err)
	}
	if opts.Run == nil {
		return errors.New("CREDEBL database initialisation: no command runner")
	}
	root := filepath.Dir(deploy)
	args := ComposeArgs(root, opts.Pair, []string{"run", "--rm", platformInitService, "sh", "-c", platformInitCommand})
	if err := opts.Run(ctx, "docker", args); err != nil {
		return fmt.Errorf("CREDEBL database initialisation: %w", err)
	}
	if err := makeReadableDir(filepath.Dir(marker)); err != nil {
		return err
	}
	stamp := time.Now().UTC().Format(time.RFC3339) + "\n"
	if err := os.WriteFile(marker, []byte(stamp), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", marker, err)
	}
	result.step(opts.Out, "CREDEBL database initialisation done")
	return nil
}
