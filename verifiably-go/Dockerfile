# syntax=docker/dockerfile:1

# ---- Build stage ----
FROM golang:1.25-alpine AS builder
WORKDIR /src

# Go sources + module graph.
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY backend ./backend
COPY internal ./internal
COPY vctypes ./vctypes

# Static binary — no cgo, no dynamic libs, safe to drop into distroless.
# -mod=mod lets Go resolve indirect deps that aren't yet listed in go.mod
# using the module cache already populated by `go mod download`.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -mod=mod \
    -trimpath -ldflags="-s -w" \
    -o /out/verifiably ./cmd/server

# ---- Runtime stage ----
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app

COPY --from=builder /out/verifiably /app/verifiably
COPY templates ./templates
COPY static ./static
COPY config ./config
# /docs browses markdown from this directory. Bundling the docs trees the
# container already cares about lets the in-app TOC work without mounting
# the repo at runtime. COPY layers are additive, so each docs source
# lands under docs-src/ preserving the repo's relative paths.
COPY docs ./docs-src/docs
COPY deploy ./docs-src/deploy
COPY testdata ./docs-src/testdata
COPY INTEGRATION.md /app/docs-src/INTEGRATION.md
COPY slim-plan.md   /app/docs-src/slim-plan.md

ENV VERIFIABLY_ADDR=:8080 \
    VERIFIABLY_ADAPTER=mock \
    VERIFIABLY_BACKENDS_FILE=/app/config/backends.json \
    VERIFIABLY_AUTH_PROVIDERS_FILE=/app/config/auth-providers.json \
    VERIFIABLY_LOCALES_DIR=/app/locales \
    VERIFIABLY_DOCS_ROOT=/app/docs-src
EXPOSE 8080
# /app/locales is writable via a volume mount in production so translation
# cache persists across container recreates.
VOLUME ["/app/locales"]
ENTRYPOINT ["/app/verifiably"]
