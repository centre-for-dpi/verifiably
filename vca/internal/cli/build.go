// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
)

// ComposeBuildFile is the path of the committed build override file,
// from the repository root. It adds a build block to every VCA service,
// so an operator runs the stack before the first tagged release
// (ADR-008 decision 1).
const ComposeBuildFile = "deploy/vca/compose.build.yaml"

// BuildContext is the build context of every service image, relative to
// the directory of the compose file.
const BuildContext = "../../vca"

// LocalTag is the image tag of a local build.
const LocalTag = "local"

// VersionEnv is the variable that carries the image tag into compose.
const VersionEnv = "VCA_VERSION"

// ComposeBuildPath returns the path of the build override file under the
// repository root.
func ComposeBuildPath(root string) string {
	return filepath.Join(root, "deploy", "vca", "compose.build.yaml")
}

// DockerfilePath returns the Dockerfile of one service, relative to the
// build context.
func DockerfilePath(s Service) string { return "services/" + s.Name + "/Dockerfile" }

// RenderComposeBuild renders the build override file. The same renderer
// writes the committed file and the --dry-run output, so the two never
// differ.
func RenderComposeBuild() string {
	var b strings.Builder
	b.WriteString("# SPDX-License-Identifier: Apache-2.0\n")
	b.WriteString("# The vca CLI generates this file. Do not edit it by hand.\n")
	b.WriteString("# Run: go test ./internal/cli/ to check that it is current.\n")
	b.WriteString("#\n")
	b.WriteString("# This file adds a build block to every VCA service. Use it before\n")
	b.WriteString("# the first release, when no image is in the registry yet.\n")
	b.WriteString("# Start one pair with: vca deploy --role <role> --dpg <dpg> --build\n")
	b.WriteString("# That runs docker compose with both files and with --build.\n")
	fmt.Fprintf(&b, "name: %s\n\n", ComposeProject)
	b.WriteString("services:\n")
	for _, p := range AllPairs() {
		fmt.Fprintf(&b, "\n  # Profile %s\n", p.Name())
		for _, a := range AssignPorts(p, nil) {
			fmt.Fprintf(&b, "  %s:\n", composeServiceName(p, a.Service))
			b.WriteString("    build:\n")
			fmt.Fprintf(&b, "      context: %s\n", BuildContext)
			fmt.Fprintf(&b, "      dockerfile: %s\n", DockerfilePath(a.Service))
		}
	}
	return b.String()
}

// ImageOptions holds everything one vca images build run needs.
type ImageOptions struct {
	// Root is the repository root.
	Root string
	// Pairs lists the role and DPG pairs whose services to build.
	Pairs []Pair
	// DryRun prints the commands only.
	DryRun bool
	// Out receives the printed output.
	Out io.Writer
	// Run runs docker build.
	Run Runner
}

// BuildServices lists every service of the pairs, once each, in service
// name order.
func BuildServices(pairs []Pair) []Service {
	seen := map[string]bool{}
	var out []Service
	for _, s := range Catalog() {
		for _, p := range pairs {
			for _, in := range ServicesFor(p) {
				if in.Name != s.Name || seen[s.Name] {
					continue
				}
				seen[s.Name] = true
				out = append(out, s)
			}
		}
	}
	return out
}

// LocalImage returns the local image reference of one service.
func LocalImage(s Service) string { return s.Image() + ":" + LocalTag }

// BuildArgs returns the docker build arguments of one service. The build
// context is the vca module, as the Dockerfile of each service states.
func BuildArgs(root string, s Service) []string {
	return []string{
		"build",
		"--file", filepath.Join(root, "vca", DockerfilePath(s)),
		"--tag", LocalImage(s),
		filepath.Join(root, "vca"),
	}
}

// BuildImages builds one image per service and sets VCA_VERSION=local in
// the .env file of every pair. The compose file then starts the local
// images (ADR-008 decision 1).
func BuildImages(ctx context.Context, opts ImageOptions) error {
	if len(opts.Pairs) == 0 {
		return ErrNoPairs
	}
	for _, s := range BuildServices(opts.Pairs) {
		args := BuildArgs(opts.Root, s)
		anyval.DiscardWrite(fmt.Fprintf(opts.Out, "docker %s\n", strings.Join(args, " ")))
		if opts.DryRun {
			continue
		}
		if opts.Run == nil {
			return fmt.Errorf("images build: no command runner")
		}
		if err := opts.Run(ctx, "docker", args); err != nil {
			return fmt.Errorf("build %s: %w", s.Name, err)
		}
	}
	for _, p := range opts.Pairs {
		path := EnvPath(opts.Root, p)
		if opts.DryRun {
			anyval.DiscardWrite(fmt.Fprintf(opts.Out, "# set %s=%s in %s\n", VersionEnv, LocalTag, path))
			continue
		}
		if err := SetEnvValue(path, VersionEnv, LocalTag); err != nil {
			return err
		}
		anyval.DiscardWrite(fmt.Fprintf(opts.Out, "set %s=%s in %s\n", VersionEnv, LocalTag, path))
	}
	return nil
}
