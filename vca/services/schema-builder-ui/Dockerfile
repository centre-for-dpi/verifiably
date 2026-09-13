# SPDX-License-Identifier: Apache-2.0
# Build from the vca module root: docker build -f services/schema-builder-ui/Dockerfile .
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w" -o /out/schema-builder-ui ./services/schema-builder-ui

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/schema-builder-ui /schema-builder-ui
USER nonroot:nonroot
EXPOSE 8081
ENV VCA_SCHEMABUILDER_LISTEN=:8081
# The file system is read only. The service keeps no state on disk.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/schema-builder-ui", "-healthcheck"]
ENTRYPOINT ["/schema-builder-ui"]
