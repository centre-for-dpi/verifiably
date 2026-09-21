# SPDX-License-Identifier: Apache-2.0
# Build from the vca module root:
#   docker build -f services/wallet-portal/Dockerfile -t ghcr.io/centre-for-dpi/vca-wallet-portal .
FROM golang:1.25 AS build
WORKDIR /src
# go.sum is absent until "make tidy" runs on a networked machine.
COPY go.mod go.su[m] ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/wallet-portal ./services/wallet-portal
RUN mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
LABEL org.opencontainers.image.title="vca-wallet-portal" \
      org.opencontainers.image.description="Citizen wallet portal with discovery, claim, present, and browser storage (ADR-021)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.source="https://github.com/centre-for-dpi/verifiably" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/wallet-portal /wallet-portal
# The volume mount point exists in the image and belongs to the nonroot
# user, so a new named volume copies that ownership and the service
# can write. A container that mounts a root owned volume cannot.
COPY --from=build --chown=65532:65532 /out/data /data
USER nonroot:nonroot
# The file system is read only. Mount a volume at /data for the state.
ENV VCA_WALLET_PORTAL_LISTEN=:8092 \
    VCA_WALLET_PORTAL_STATE_DIR=/data
VOLUME ["/data"]
EXPOSE 8092
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/wallet-portal", "-healthcheck"]
ENTRYPOINT ["/wallet-portal"]
