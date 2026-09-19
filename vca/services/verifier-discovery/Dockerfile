# SPDX-License-Identifier: Apache-2.0
# Build from the vca/ directory:
#   docker build -f services/verifier-discovery/Dockerfile -t ghcr.io/centre-for-dpi/vca-verifier-discovery .
FROM golang:1.25 AS build
WORKDIR /src
# go.sum is absent until "make tidy" runs on a networked machine.
COPY go.mod go.su[m] ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/verifier-discovery ./services/verifier-discovery

FROM gcr.io/distroless/static-debian13:nonroot
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
LABEL org.opencontainers.image.title="vca-verifier-discovery" \
      org.opencontainers.image.description="Crawler of trusted issuers, credential catalogue, and presentation templates in DCQL (ADR-022)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.source="https://github.com/centre-for-dpi/verifiably" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/verifier-discovery /verifier-discovery
USER nonroot:nonroot
# The file system is read only. Mount a volume at /data for the catalogue
# and the templates.
ENV VCA_DISCOVERY_LISTEN=:8090 \
    VCA_DISCOVERY_STATE_DIR=/data
VOLUME ["/data"]
EXPOSE 8090
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/verifier-discovery", "-healthcheck"]
ENTRYPOINT ["/verifier-discovery"]
