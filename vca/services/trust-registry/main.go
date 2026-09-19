// SPDX-License-Identifier: Apache-2.0

// Command trust-registry serves vca.trust.v1.TrustService and the signed
// trust lists (ADR-011). Run with -healthcheck to probe /readyz and exit.
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
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/config"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

// run is the whole program. It returns the exit status.
// ctx ends the server. A signal ends it too.
func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("trust-registry", flag.ContinueOnError)
	flags.SetOutput(stderr)
	healthcheck := flags.Bool("healthcheck", false, "GET /readyz on the configured port and exit")
	if err := flags.Parse(args); err != nil {
		return 2
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
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
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
		Listen:  cfg.Listen,
		Handler: a.Mux,
		Ready:   a.Service.Ready,
		Log:     log,
	})
}
