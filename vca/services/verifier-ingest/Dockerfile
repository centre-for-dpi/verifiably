# SPDX-License-Identifier: Apache-2.0
# Build from the vca/ directory:
#   docker build -f services/verifier-ingest/Dockerfile -t ghcr.io/centre-for-dpi/vca-verifier-ingest .
FROM golang:1.25 AS build
WORKDIR /src
# go.sum is absent until "make tidy" runs on a networked machine.
COPY go.mod go.su[m] ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/verifier-ingest ./services/verifier-ingest

FROM gcr.io/distroless/static-debian13:nonroot
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
LABEL org.opencontainers.image.title="vca-verifier-ingest" \
      org.opencontainers.image.description="Multi format ingestion of presentations with OID4VP transactions and a camera page (ADR-023)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.source="https://github.com/centre-for-dpi/verifiably" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/verifier-ingest /verifier-ingest
USER nonroot:nonroot
# The file system is read only. Mount a volume at /data for the
# transactions. Mount the request object key as a read only secret.
ENV VCA_INGEST_LISTEN=:8091 \
    VCA_INGEST_STATE_DIR=/data
VOLUME ["/data"]
EXPOSE 8091
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/verifier-ingest", "-healthcheck"]
ENTRYPOINT ["/verifier-ingest"]
