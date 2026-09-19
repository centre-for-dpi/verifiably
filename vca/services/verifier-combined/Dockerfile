# SPDX-License-Identifier: Apache-2.0
# Build from the vca module root:
#   docker build -f services/verifier-combined/Dockerfile -t ghcr.io/centre-for-dpi/vca-verifier-combined .
FROM golang:1.25 AS build
WORKDIR /src
# go.sum is absent until "make tidy" runs on a networked machine.
COPY go.mod go.su[m] ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/verifier-combined ./services/verifier-combined

FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
LABEL org.opencontainers.image.title="vca-verifier-combined" \
      org.opencontainers.image.description="Verifier multi credential combined presentation with DCQL credential sets and cross credential rules (ADR-026)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.source="https://github.com/centre-for-dpi/verifiably" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/verifier-combined /verifier-combined
USER nonroot:nonroot
# The file system is read only. Mount a volume at /data for the templates.
ENV VCA_VERIFIER_COMBINED_LISTEN=:8088 \
    VCA_VERIFIER_COMBINED_STATE_DIR=/data
VOLUME ["/data"]
EXPOSE 8088
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/verifier-combined", "-healthcheck"]
ENTRYPOINT ["/verifier-combined"]
