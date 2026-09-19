// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
)

// Runner runs one command. The deploy commands take a Runner, so a test
// records the command instead of starting a container.
type Runner func(ctx context.Context, name string, args []string) error

// DeployOptions holds everything the lifecycle commands need.
type DeployOptions struct {
	// Root is the repository root that holds the deploy directory.
	Root string
	// Pairs lists the role and DPG pairs to act on.
	Pairs []Pair
	// DryRun prints the rendered compose file and the commands only
	// (ADR-008 decision 6).
	DryRun bool
	// Out receives the printed output.
	Out io.Writer
	// Run runs docker compose. A nil Runner means a dry run.
	Run Runner
}

// ErrNoPairs reports a lifecycle command with no role and DPG pair.
var ErrNoPairs = errors.New("deploy: name a role and a DPG, or use --all")

// ComposePath returns the path of the compose file under the root.
func ComposePath(root string) string { return filepath.Join(root, "deploy", "vca", "compose.yaml") }

// EnvPath returns the path of the .env file of a pair under the root.
func EnvPath(root string, p Pair) string {
	return filepath.Join(root, "deploy", p.Name(), EnvFileName)
}

// ComposeArgs builds the docker compose arguments of one pair and one
// action, for example up -d (ADR-008 decision 1).
func ComposeArgs(root string, p Pair, action []string) []string {
	args := []string{
		"compose",
		"--project-name", ComposeProject,
		"--file", ComposePath(root),
		"--env-file", EnvPath(root, p),
		"--profile", p.Name(),
	}
	return append(args, action...)
}

// Deploy starts every named pair (ADR-008 decisions 1 and 2).
func Deploy(ctx context.Context, opts DeployOptions) error {
	return lifecycle(ctx, opts, []string{"up", "-d"})
}

// Status shows the containers of every named pair (ADR-008 decision 6).
func Status(ctx context.Context, opts DeployOptions) error {
	return lifecycle(ctx, opts, []string{"ps"})
}

// Down stops every named pair. The volumes stay, so no data is lost
// (ADR-008 decision 6).
func Down(ctx context.Context, opts DeployOptions) error {
	return lifecycle(ctx, opts, []string{"down", "--remove-orphans"})
}

// lifecycle runs one action for every pair, or prints it on a dry run.
func lifecycle(ctx context.Context, opts DeployOptions, action []string) error {
	if len(opts.Pairs) == 0 {
		return ErrNoPairs
	}
	if opts.DryRun {
		return printDryRun(opts, action)
	}
	if opts.Run == nil {
		return errors.New("deploy: no command runner")
	}
	for _, p := range opts.Pairs {
		if err := checkEnvFile(opts.Root, p); err != nil {
			return err
		}
		args := ComposeArgs(opts.Root, p, action)
		anyval.DiscardWrite(fmt.Fprintf(opts.Out, "docker %s\n", strings.Join(args, " ")))
		if err := opts.Run(ctx, "docker", args); err != nil {
			return fmt.Errorf("deploy %s: %w", p.Name(), err)
		}
	}
	return nil
}

// printDryRun writes the rendered compose file and the commands.
func printDryRun(opts DeployOptions, action []string) error {
	if _, err := io.WriteString(opts.Out, RenderCompose()); err != nil {
		return fmt.Errorf("print the compose file: %w", err)
	}
	for _, p := range opts.Pairs {
		args := ComposeArgs(opts.Root, p, action)
		anyval.DiscardWrite(fmt.Fprintf(opts.Out, "\n# %s\ndocker %s\n", p.Name(), strings.Join(args, " ")))
	}
	return nil
}

// checkEnvFile reports a pair that has no .env file yet.
func checkEnvFile(root string, p Pair) error {
	path := EnvPath(root, p)
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("deploy %s: %s is missing; run vca setup --role %s --dpg %s first",
				p.Name(), path, ShortName(p.Role.String()), ShortName(p.Dpg.String()))
		}
		return fmt.Errorf("deploy %s: %w", p.Name(), err)
	}
	return nil
}

// ExecRunner runs a command and sends its output to out and errOut.
// The CLI uses it. A test uses its own Runner instead.
func ExecRunner(out, errOut io.Writer) Runner {
	return func(ctx context.Context, name string, args []string) error {
		return runCommand(ctx, name, args, out, errOut)
	}
}
