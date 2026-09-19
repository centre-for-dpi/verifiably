// SPDX-License-Identifier: Apache-2.0

// Command issuer-auth logs issuer staff in with OpenID Connect and issues
// ES256 session tokens (ADR-012).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/serve"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/server"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("issuer-auth", flag.ContinueOnError)
	healthcheck := fs.Bool("healthcheck", false, "call /healthz on the listen address and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	cfg, err := config.FromEnv(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if *healthcheck {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := serve.Healthcheck(ctx, cfg.Listen); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	log.Info("issuer-auth starting", "version", version, "public_url", cfg.PublicBaseURL)
	svc, err := server.Build(cfg, log)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	opts := serve.Options{
		Listen:       cfg.Listen,
		Handler:      server.Handler(svc),
		ReadyMessage: server.ReadyMessage(svc),
		Log:          log,
	}
	if err := serve.Run(ctx, opts); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
