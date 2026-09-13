# SPDX-License-Identifier: Apache-2.0
# Build from the vca module root: docker build -f services/trust-registry/Dockerfile .
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w" -o /out/trust-registry ./services/trust-registry

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/trust-registry /trust-registry
USER nonroot:nonroot
EXPOSE 8080
ENV VCA_TRUST_LISTEN=:8080
# The file system is read only. Mount a volume at /data for the store file
# and set VCA_TRUST_STORE_FILE=/data/trust.json.
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/trust-registry", "-healthcheck"]
ENTRYPOINT ["/trust-registry"]
