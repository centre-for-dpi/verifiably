// SPDX-License-Identifier: Apache-2.0

// Command verifier-policy serves vca.policy.v1.PolicyService (ADR-024).
// Run with -healthcheck to probe /readyz and exit.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/serve"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-policy/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-policy/internal/config"
)

// version is the build version. The Dockerfile sets it.
var version = "dev"

// healthcheckTimeout bounds the -healthcheck probe.
const healthcheckTimeout = 5 * time.Second

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

// run is the whole program. It returns the exit status. ctx ends the
// server. A signal ends it too.
func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("verifier-policy", flag.ContinueOnError)
	flags.SetOutput(stderr)
	healthcheck := flags.Bool("healthcheck", false, "GET /readyz on the configured port and exit")
	showVersion := flags.Bool("version", false, "print the version and exit")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}
	if err := serveOrProbe(ctx, *healthcheck, getenv, stdout); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func serveOrProbe(ctx context.Context, healthcheck bool, getenv func(string) string, stdout io.Writer) error {
	cfg, err := config.Load(getenv)
	if err != nil {
		return err
	}
	if healthcheck {
		ctx, cancel := context.WithTimeout(ctx, healthcheckTimeout)
		defer cancel()
		return serve.Healthcheck(ctx, cfg.Listen)
	}
	log := slog.New(slog.NewJSONHandler(stdout, nil))
	a, err := app.Build(cfg, app.Deps{Log: log})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serve.Run(ctx, serve.Options{
		Listen: cfg.Listen, Handler: a.Mux, Ready: a.Service.Ready, Log: log,
	})
}
