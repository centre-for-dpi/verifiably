// SPDX-License-Identifier: Apache-2.0

// Command vca sets up, deploys, and administers the Verifiable
// Credentials Adapters (ADR-007, ADR-008, ADR-009).
//
// The command tree and every rule live in internal/cli, so the tests
// drive the whole tool. This file only passes the process state in.
//
// To write the man pages:
//
//	go run ./cmd/vca man --dir docs/man
package main

import (
	"os"

	"github.com/centre-for-dpi/vc-adapters/internal/cli"
)

func main() {
	os.Exit(cli.Execute(cli.Environment{Args: os.Args[1:]}))
}
