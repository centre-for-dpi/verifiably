# SPDX-License-Identifier: Apache-2.0
# Build from the vca module root:
#   docker build -f services/dpg-adapter-credebl/Dockerfile .
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w" -o /out/dpg-adapter-credebl ./services/dpg-adapter-credebl

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="dpg-adapter-credebl" \
      org.opencontainers.image.description="Verifiable Credentials Adapters: CREDEBL DPG adapter" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/centre-for-dpi/verifiably"
COPY --from=build /out/dpg-adapter-credebl /dpg-adapter-credebl
USER nonroot:nonroot
EXPOSE 8080
ENV VCA_CREDEBL_LISTEN=:8080
# The file system is read only. Mount a volume at /data and set
# VCA_CREDEBL_STORE_FILE=/data/credebl to keep the verifier id.
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/dpg-adapter-credebl", "-healthcheck"]
ENTRYPOINT ["/dpg-adapter-credebl"]
