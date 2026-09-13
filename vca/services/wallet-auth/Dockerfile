# SPDX-License-Identifier: Apache-2.0
# Build from the vca/ directory:
#   docker build -f services/wallet-auth/Dockerfile -t ghcr.io/centre-for-dpi/vca-wallet-auth .
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/wallet-auth ./services/wallet-auth

FROM gcr.io/distroless/static-debian13:nonroot
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
LABEL org.opencontainers.image.title="vca-wallet-auth" \
      org.opencontainers.image.description="Citizen OIDC login and short lived ES256 session tokens (ADR-020)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.source="https://github.com/centre-for-dpi/verifiably" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/wallet-auth /wallet-auth
USER nonroot:nonroot
ENV VCA_WALLET_AUTH_LISTEN=:8083 \
    VCA_WALLET_AUTH_STATE_DIR=/state
VOLUME ["/state"]
EXPOSE 8083
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/wallet-auth", "-healthcheck"]
ENTRYPOINT ["/wallet-auth"]
