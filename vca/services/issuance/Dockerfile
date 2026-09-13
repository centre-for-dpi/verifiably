# SPDX-License-Identifier: Apache-2.0
# Build from the vca module root:
#   docker build -f services/issuance/Dockerfile .
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w" -o /out/issuance ./services/issuance

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="issuance" \
      org.opencontainers.image.description="Verifiable Credentials Adapters: issuance service" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/centre-for-dpi/verifiably"
COPY --from=build /out/issuance /issuance
USER nonroot:nonroot
EXPOSE 8080
ENV VCA_ISSUANCE_LISTEN=:8080
# The file system is read only. Mount a volume at /data and set
# VCA_ISSUANCE_STORE_FILE=/data/issuance to keep the offers and the
# batch jobs. The file sender writes into VCA_ISSUANCE_DELIVERY_DIR,
# so point it at the same volume.
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/issuance", "-healthcheck"]
ENTRYPOINT ["/issuance"]
