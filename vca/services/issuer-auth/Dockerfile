# SPDX-License-Identifier: Apache-2.0
# Build from the vca/ directory:
#   docker build -f services/issuer-auth/Dockerfile -t ghcr.io/centre-for-dpi/vca-issuer-auth .
FROM golang:1.25 AS build
WORKDIR /src
# go.sum is absent until "make tidy" runs on a networked machine.
COPY go.mod go.su[m] ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/issuer-auth ./services/issuer-auth

FROM gcr.io/distroless/static-debian13:nonroot
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
LABEL org.opencontainers.image.title="vca-issuer-auth" \
      org.opencontainers.image.description="Issuer staff OIDC login and ES256 session tokens (ADR-012)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.source="https://github.com/centre-for-dpi/verifiably" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/issuer-auth /issuer-auth
USER nonroot:nonroot
ENV VCA_ISSUER_AUTH_LISTEN=:8081 \
    VCA_ISSUER_AUTH_STATE_DIR=/state
VOLUME ["/state"]
EXPOSE 8081
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/issuer-auth", "-healthcheck"]
ENTRYPOINT ["/issuer-auth"]
