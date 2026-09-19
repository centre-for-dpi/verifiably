# SPDX-License-Identifier: Apache-2.0
# Build from the vca module root: docker build -f services/admin/Dockerfile .
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w" -o /out/admin ./services/admin

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="vca-admin" \
      org.opencontainers.image.description="Super admin API and portal of the Verifiable Credentials Adapters" \
      org.opencontainers.image.source="https://github.com/centre-for-dpi/verifiably" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/admin /admin
USER nonroot:nonroot
EXPOSE 8093
ENV VCA_ADMIN_LISTEN=:8093
# The file system is read only. Mount a volume at /data for the records
# and set VCA_ADMIN_STATE_DIR=/data.
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/admin", "-healthcheck"]
ENTRYPOINT ["/admin"]
