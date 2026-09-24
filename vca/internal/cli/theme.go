// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/internal/themefile"
)

// ThemePath returns the theme file the CLI checks: the --file flag, else
// ThemeHostFileEnv, else deploy/vca/theme.yaml under the repository root.
// A relative value of the variable resolves against deploy/vca, as the
// bind mount of the compose file does, so one value serves both.
func ThemePath(root, flag string, getenv func(string) string) string {
	if flag != "" {
		return flag
	}
	if host := strings.TrimSpace(getenv(ThemeHostFileEnv)); host != "" {
		if filepath.IsAbs(host) {
			return host
		}
		return filepath.Join(root, "deploy", "vca", host)
	}
	return filepath.Join(root, themefile.ShippedPath)
}

// ThemeCheck validates the theme file at path and prints one line on
// success. The error names the path and every problem (ADR-032
// decision 6).
func ThemeCheck(path string, out io.Writer) error {
	if _, err := themefile.Load(path); err != nil {
		return err
	}
	anyval.DiscardWrite(fmt.Fprintf(out, "theme file %s: valid\n", path))
	return nil
}

// DeployedPairs lists the pairs that have a .env file under the deploy
// directory of root, in pair order.
func DeployedPairs(root string) []Pair {
	var out []Pair
	for _, p := range AllPairs() {
		if _, err := os.Stat(EnvPath(root, p)); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// ThemeOptions holds everything vca theme apply needs.
type ThemeOptions struct {
	// Root is the repository root that holds the deploy directory.
	Root string
	// Path is the theme file to check first.
	Path string
	// Out receives the printed output.
	Out io.Writer
	// Run runs docker compose.
	Run Runner
}

// ThemeApply checks the theme file, then restarts the services that draw
// pages in every deployed pair, so they read the file again (ADR-032
// decision 6). A service with no pages keeps running.
func ThemeApply(ctx context.Context, opts ThemeOptions) error {
	if err := ThemeCheck(opts.Path, opts.Out); err != nil {
		return err
	}
	if opts.Run == nil {
		return errors.New("theme apply: no command runner")
	}
	pairs := DeployedPairs(opts.Root)
	if len(pairs) == 0 {
		anyval.DiscardWrite(fmt.Fprintln(opts.Out, "theme apply: no deployed pair; run vca setup and vca deploy first"))
		return nil
	}
	for i, p := range pairs {
		action := []string{"restart"}
		for _, s := range ServicesFor(p) {
			if s.UI {
				action = append(action, composeServiceName(p, s))
			}
		}
		// A deployment scoped service runs once, so the first pair
		// restarts it (ADR-033 decision 2).
		if i == 0 {
			for _, s := range DeploymentServices() {
				if s.UI {
					action = append(action, DeploymentServiceName(s))
				}
			}
		}
		args := ComposeArgs(opts.Root, p, action)
		anyval.DiscardWrite(fmt.Fprintf(opts.Out, "docker %s\n", strings.Join(args, " ")))
		if err := opts.Run(ctx, "docker", args); err != nil {
			return fmt.Errorf("theme apply %s: %w", p.Name(), err)
		}
	}
	return nil
}

// WriteDefaultTheme writes the embedded default theme file at path when
// no file is there. It never replaces a file, so an edited look survives
// a second setup run. It reports whether it wrote the file. The mode lets
// the container user read the bind mount.
func WriteDefaultTheme(path string) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), readableDirMode); err != nil { //nolint:gosec // the container user reads the directory
		return false, fmt.Errorf("make %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, themefile.Default(), 0o644); err != nil { //nolint:gosec // the container user reads the file
		return false, fmt.Errorf("write %s: %w", path, err)
	}
	return true, nil
}
