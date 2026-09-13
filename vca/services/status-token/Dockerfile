# SPDX-License-Identifier: Apache-2.0
# Build from the vca/ directory:
#   docker build -f services/status-token/Dockerfile -t ghcr.io/centre-for-dpi/vca-status-token .
FROM golang:1.25 AS build
WORKDIR /src
# go.sum is absent until "make tidy" runs on a networked machine.
COPY go.mod go.su[m] ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/status-token ./services/status-token

FROM gcr.io/distroless/static-debian13:nonroot
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
LABEL org.opencontainers.image.title="vca-status-token" \
      org.opencontainers.image.description="IETF Token Status List service (ADR-019)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.source="https://github.com/centre-for-dpi/verifiably" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/status-token /status-token
USER nonroot:nonroot
# The file system is read only. Mount a volume at /state for the lists
# and the signing keys.
ENV VCA_STATUS_TOKEN_LISTEN=:8085 \
    VCA_STATUS_TOKEN_STATE_DIR=/state
VOLUME ["/state"]
EXPOSE 8085
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/status-token", "-healthcheck"]
ENTRYPOINT ["/status-token"]
