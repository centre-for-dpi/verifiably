# SPDX-License-Identifier: Apache-2.0
# Build from the vca module root: docker build -f services/landing/Dockerfile .
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w" -o /out/landing ./services/landing

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/landing /landing
USER nonroot:nonroot
EXPOSE 8080
ENV VCA_LANDING_LISTEN=:8080
# The file system is read only. The service keeps no state on disk.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/landing", "-healthcheck"]
ENTRYPOINT ["/landing"]
