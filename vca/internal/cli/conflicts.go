// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// OutputRunner runs one command and returns its standard output. The
// deploy command takes one, so a test feeds it recorded output instead
// of a Docker daemon.
type OutputRunner func(ctx context.Context, name string, args []string) (string, error)

// ContainerConflict is a container that holds a name the compose file
// needs, but that the vca compose project did not create. Compose
// refuses to start a service over it (ADR-008 decision 1).
type ContainerConflict struct {
	// Name is the container name.
	Name string
	// Project is the compose project that owns the container. It is
	// empty when compose did not start the container.
	Project string
}

// composeConfig is the part of docker compose config --format json that
// the check reads.
type composeConfig struct {
	Services map[string]struct {
		ContainerName string `json:"container_name"`
	} `json:"services"`
}

// ComposeContainerNames reads the container names out of the JSON that
// docker compose config --format json prints. The names come sorted, so
// a message never changes between runs.
func ComposeContainerNames(configJSON string) ([]string, error) {
	var cfg composeConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return nil, fmt.Errorf("read the compose configuration: %w", err)
	}
	var out []string
	for _, s := range cfg.Services {
		if s.ContainerName != "" {
			out = append(out, s.ContainerName)
		}
	}
	sort.Strings(out)
	return out, nil
}

// ParseContainerOwners reads the output of docker ps with the format
// {{.Names}}\t{{.Label "com.docker.compose.project"}} into a map from
// container name to compose project. A container that compose did not
// start maps to an empty string.
func ParseContainerOwners(psOutput string) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(psOutput, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, project, _ := strings.Cut(line, "\t")
		name = strings.TrimPrefix(strings.TrimSpace(name), "/")
		if name == "" {
			continue
		}
		out[name] = strings.TrimSpace(project)
	}
	return out
}

// ContainerConflicts returns every name of the list that another
// container holds. A container of the vca project is not a conflict,
// because compose recreates its own containers.
func ContainerConflicts(names []string, owners map[string]string) []ContainerConflict {
	var out []ContainerConflict
	for _, name := range names {
		project, exists := owners[name]
		if !exists || project == ComposeProject {
			continue
		}
		out = append(out, ContainerConflict{Name: name, Project: project})
	}
	return out
}

// ConflictMessage renders the error text for one pair. It names every
// container, its owner, and the one command that removes them all.
func ConflictMessage(p Pair, conflicts []ContainerConflict) string {
	var b strings.Builder
	fmt.Fprintf(&b, "deploy %s: %d container name", p.Name(), len(conflicts))
	if len(conflicts) != 1 {
		b.WriteString("s are")
	} else {
		b.WriteString(" is")
	}
	b.WriteString(" in use outside the vca compose project\n")
	names := make([]string, 0, len(conflicts))
	for _, c := range conflicts {
		owner := "a container that compose did not start"
		if c.Project != "" {
			owner = "compose project " + c.Project
		}
		fmt.Fprintf(&b, "  %s  held by %s\n", c.Name, owner)
		names = append(names, c.Name)
	}
	b.WriteString("Remove them, then run the command again:\n")
	fmt.Fprintf(&b, "  docker rm -f %s", strings.Join(names, " "))
	return b.String()
}

// dockerPsArgs lists every container with the compose project that owns
// it.
var dockerPsArgs = []string{"ps", "--all", "--format", `{{.Names}}	{{.Label "com.docker.compose.project"}}`}

// checkContainerNames reads the container names of one pair from
// compose, reads the containers of the host, and reports a conflict
// before compose starts anything. A nil Output skips the check.
func checkContainerNames(ctx context.Context, opts DeployOptions, p Pair) error {
	if opts.Output == nil {
		return nil
	}
	configArgs := ComposeArgsBuild(opts.Root, p, []string{"config", "--format", "json"}, opts.Build)
	configJSON, err := opts.Output(ctx, "docker", configArgs)
	if err != nil {
		return fmt.Errorf("deploy %s: read the compose configuration: %w", p.Name(), err)
	}
	names, err := ComposeContainerNames(configJSON)
	if err != nil {
		return fmt.Errorf("deploy %s: %w", p.Name(), err)
	}
	psOutput, err := opts.Output(ctx, "docker", dockerPsArgs)
	if err != nil {
		return fmt.Errorf("deploy %s: list the containers: %w", p.Name(), err)
	}
	conflicts := ContainerConflicts(names, ParseContainerOwners(psOutput))
	if len(conflicts) == 0 {
		return nil
	}
	return &ConflictError{Pair: p, Conflicts: conflicts}
}

// ConflictError reports the container names that block one pair.
type ConflictError struct {
	// Pair is the role and DPG pair that compose could not start.
	Pair Pair
	// Conflicts lists the names and their owners.
	Conflicts []ContainerConflict
}

// Error renders the message with the fix.
func (e *ConflictError) Error() string { return ConflictMessage(e.Pair, e.Conflicts) }
