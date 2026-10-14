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
	// Build adds the build override file and the --build flag, so
	// compose builds every image from the source in this repository.
	Build bool
	// Out receives the printed output.
	Out io.Writer
	// Run runs docker compose. A nil Runner means a dry run.
	Run Runner
	// Output runs docker and returns its output. Deploy uses it to find
	// a container that holds a name the pair needs before compose starts
	// anything. A nil Output skips that check.
	Output OutputRunner
}

// ErrNoPairs reports a lifecycle command with no role and DPG pair.
var ErrNoPairs = errors.New("deploy: name a role and a DPG, or use --all")

// ComposePath returns the path of the compose file under the root.
func ComposePath(root string) string { return filepath.Join(root, "deploy", "vca", "compose.yaml") }

// EnvPath returns the path of the .env file of a pair under the root.
func EnvPath(root string, p Pair) string {
	return filepath.Join(root, "deploy", p.Name(), EnvFileName)
}

// LandingEnvPath returns the path of the .env file of the landing under
// the root (ADR-033 decision 2).
func LandingEnvPath(root string) string {
	return filepath.Join(root, "deploy", LandingDir, EnvFileName)
}

// ComposeArgs builds the docker compose arguments of one pair and one
// action, for example up -d (ADR-008 decision 1).
func ComposeArgs(root string, p Pair, action []string) []string {
	return ComposeArgsBuild(root, p, action, false)
}

// ComposeArgsBuild builds the docker compose arguments of one pair. A
// build run adds the committed override file, so compose builds every
// image from the source in this repository.
func ComposeArgsBuild(root string, p Pair, action []string, build bool) []string {
	args := []string{
		"compose",
		"--project-name", ComposeProject,
		"--file", ComposePath(root),
	}
	if build {
		args = append(args, "--file", ComposeBuildPath(root))
	}
	args = append(args,
		"--env-file", EnvPath(root, p),
		"--profile", p.Name(),
	)
	// eSignet runs only when the pair names a real authenticator
	// (ADR-053 decision 1).
	if esignetProfileOf(root, p) {
		args = append(args, "--profile", EsignetProfile)
	}
	return append(args, action...)
}

// Deploy starts every named pair (ADR-008 decisions 1 and 2). A build
// run adds --build, so compose builds the images first.
func Deploy(ctx context.Context, opts DeployOptions) error {
	action := []string{"up", "-d"}
	if opts.Build {
		action = append(action, "--build")
	}
	if err := lifecycle(ctx, opts, action); err != nil {
		return err
	}
	if !opts.DryRun {
		writeEntryReport(opts.Out, opts.Root, opts.Pairs)
	}
	return nil
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
	}
	if err := checkComposeRelease(opts.Root, opts.Build); err != nil {
		return err
	}
	if action[0] == "up" {
		if err := checkStackVolumes(ctx, opts); err != nil {
			return err
		}
	}
	for _, p := range opts.Pairs {
		if action[0] == "up" {
			if err := checkContainerNames(ctx, opts, p); err != nil {
				return err
			}
		}
		args := ComposeArgsBuild(opts.Root, p, action, opts.Build)
		anyval.DiscardWrite(fmt.Fprintf(opts.Out, "docker %s\n", strings.Join(args, " ")))
		if err := opts.Run(ctx, "docker", args); err != nil {
			if action[0] == "up" && !opts.Build {
				// Until a release publishes the images, a pull is the
				// first thing compose does and the first thing that fails.
				return fmt.Errorf("deploy %s: %w (if docker refused to pull an image, no release has published the images of this version yet: add --build to build them from this checkout, or set %s in deploy/%s/.env to a released tag)",
					p.Name(), err, VersionEnv, p.Name())
			}
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
	if opts.Build {
		if _, err := io.WriteString(opts.Out, "\n"+RenderComposeBuild()); err != nil {
			return fmt.Errorf("print the build override file: %w", err)
		}
	}
	for _, p := range opts.Pairs {
		args := ComposeArgsBuild(opts.Root, p, action, opts.Build)
		anyval.DiscardWrite(fmt.Fprintf(opts.Out, "\n# %s\ndocker %s\n", p.Name(), strings.Join(args, " ")))
	}
	return nil
}

// checkEnvFile reports a pair that has no .env file yet.
func checkEnvFile(root string, p Pair) error {
	paths := []string{EnvPath(root, p)}
	// The main compose file reads the .env of every stack for its stack
	// file. A deployment that an earlier setup wrote has none yet, and
	// compose would stop on the first secret it needs (ADR-055
	// consequence 2).
	for _, d := range StackDpgs() {
		paths = append(paths, filepath.Join(root, "deploy", StackEnvFile(d)))
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("deploy %s: %s is missing; run vca setup --role %s --dpg %s first",
					p.Name(), path, ShortName(p.Role.String()), ShortName(p.Dpg.String()))
			}
			return fmt.Errorf("deploy %s: %w", p.Name(), err)
		}
		if info.IsDir() {
			return fmt.Errorf("deploy %s: %s is a directory, not a file", p.Name(), path)
		}
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

// checkComposeRelease refuses a compose file that this binary did not
// render. A vca binary older or newer than the checkout writes a deploy
// tree that the compose file of the checkout cannot use, and compose
// then fails on the first file it misses. The check reads the file and
// compares it with the rendering of this binary, so the message names
// the cause instead of a missing file.
func checkComposeRelease(root string, build bool) error {
	files := []struct{ path, want string }{{ComposePath(root), RenderCompose()}}
	if build {
		files = append(files, struct{ path, want string }{ComposeBuildPath(root), RenderComposeBuild()})
	}
	for _, f := range files {
		got, err := os.ReadFile(f.path) // #nosec G304 -- the path is under the deploy directory of the root
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("deploy: %s is missing; run vca from the repository root, or check out the release of this binary (%s)", f.path, EffectiveVersion())
			}
			return fmt.Errorf("deploy: %w", err)
		}
		if string(got) != f.want {
			return fmt.Errorf("deploy: %s was written by another release of vca than this binary (%s); "+
				"rebuild vca from this checkout with go install ./cmd/vca, then run vca setup and vca deploy again",
				f.path, EffectiveVersion())
		}
	}
	return nil
}
