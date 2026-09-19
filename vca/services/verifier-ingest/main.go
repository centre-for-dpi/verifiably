// SPDX-License-Identifier: Apache-2.0

// Command verifier-ingest serves vca.ingest.v1.IngestService, the OID4VP
// wallet endpoints, and the camera page (ADR-023). Run it with
// -healthcheck to probe /readyz and exit.
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
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/config"
)

// version is the build version. The Dockerfile sets it.
var version = "dev"

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

// run is the whole program. It returns the exit status. ctx ends the
// server. A signal ends it too.
func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("verifier-ingest", flag.ContinueOnError)
	flags.SetOutput(stderr)
	healthcheck := flags.Bool("healthcheck", false, "GET /readyz on the configured port and exit")
	showVersion := flags.Bool("version", false, "print the version and exit")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		return printLine(stdout, version)
	}
	if err := serveOrProbe(ctx, *healthcheck, getenv, stdout); err != nil {
		printLine(stderr, err)
		return 1
	}
	return 0
}

// serveOrProbe runs the health probe or the server.
func serveOrProbe(ctx context.Context, healthcheck bool, getenv func(string) string, stdout io.Writer) error {
	cfg, err := config.Load(getenv)
	if err != nil {
		return err
	}
	if healthcheck {
		probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return serve.Healthcheck(probeCtx, cfg.Listen)
	}
	log := slog.New(slog.NewJSONHandler(stdout, nil))
	a, err := app.Build(cfg, app.Deps{Log: log})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	go a.Prune(ctx, log)
	return serve.Run(ctx, serve.Options{Listen: cfg.Listen, Handler: a.Mux, Ready: a.Service.Ready, Log: log})
}

// printLine writes one line to w. It returns the process exit status.
func printLine(w io.Writer, v any) int {
	if _, err := fmt.Fprintln(w, v); err != nil {
		return 1
	}
	return 0
}
