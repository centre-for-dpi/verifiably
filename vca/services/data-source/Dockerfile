# SPDX-License-Identifier: Apache-2.0
# Build from the vca/ directory:
#   docker build -f services/data-source/Dockerfile -t ghcr.io/centre-for-dpi/vca-data-source .
FROM golang:1.25 AS build
WORKDIR /src
# go.sum is absent until "make tidy" runs on a networked machine.
COPY go.mod go.su[m] ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/data-source ./services/data-source

FROM gcr.io/distroless/static-debian13:nonroot
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
LABEL org.opencontainers.image.title="vca-data-source" \
      org.opencontainers.image.description="CSV, HTTP, and SQL data sources with field maps (ADR-015)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.source="https://github.com/centre-for-dpi/verifiably" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/data-source /data-source
USER nonroot:nonroot
# The file system is read only. Mount a volume at /data for the store
# file and the uploaded CSV files.
ENV VCA_DATASOURCE_LISTEN=:8083 \
    VCA_DATASOURCE_STORE_FILE=/data/sources.json \
    VCA_DATASOURCE_CSV_DIR=/data/csv
VOLUME ["/data"]
EXPOSE 8083
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/data-source", "-healthcheck"]
ENTRYPOINT ["/data-source"]
