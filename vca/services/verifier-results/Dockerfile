# SPDX-License-Identifier: Apache-2.0
# Build from the vca module root:
#   docker build -f services/verifier-results/Dockerfile -t ghcr.io/centre-for-dpi/vca-verifier-results .
FROM golang:1.25 AS build
WORKDIR /src
# go.sum is absent until "make tidy" runs on a networked machine.
COPY go.mod go.su[m] ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/verifier-results ./services/verifier-results

FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
LABEL org.opencontainers.image.title="vca-verifier-results" \
      org.opencontainers.image.description="Verifier presentation result manager with cards, query, export, and retention (ADR-025)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.source="https://github.com/centre-for-dpi/verifiably" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/verifier-results /verifier-results
USER nonroot:nonroot
# The file system is read only. Mount a volume at /data for the results.
ENV VCA_VERIFIER_RESULTS_LISTEN=:8087 \
    VCA_VERIFIER_RESULTS_STATE_DIR=/data
VOLUME ["/data"]
EXPOSE 8087
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/verifier-results", "-healthcheck"]
ENTRYPOINT ["/verifier-results"]
