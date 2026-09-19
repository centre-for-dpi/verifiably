// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"io"
	"os/exec"
)

// runCommand starts one command and waits for it. It is the only place in
// the package that starts a process, so every other function stays pure
// and testable (ADR-004).
func runCommand(ctx context.Context, name string, args []string, out, errOut io.Writer) error {
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- the CLI builds the arguments
	cmd.Stdout = out
	cmd.Stderr = errOut
	return cmd.Run()
}
