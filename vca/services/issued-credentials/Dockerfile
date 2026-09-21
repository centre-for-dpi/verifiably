# SPDX-License-Identifier: Apache-2.0
# Build from the vca/ directory:
#   docker build -f services/issued-credentials/Dockerfile -t ghcr.io/centre-for-dpi/vca-issued-credentials .
FROM golang:1.25 AS build
WORKDIR /src
# go.sum is absent until "make tidy" runs on a networked machine.
COPY go.mod go.su[m] ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/issued-credentials ./services/issued-credentials
RUN mkdir -p /out/data

FROM gcr.io/distroless/static-debian13:nonroot
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
LABEL org.opencontainers.image.title="vca-issued-credentials" \
      org.opencontainers.image.description="Tamper evident log of issued credentials with revoke, export, and a signed chain head (ADR-017)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.source="https://github.com/centre-for-dpi/verifiably" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/issued-credentials /issued-credentials
# The volume mount point exists in the image and belongs to the nonroot
# user, so a new named volume copies that ownership and the service
# can write. A container that mounts a root owned volume cannot.
COPY --from=build --chown=65532:65532 /out/data /data
USER nonroot:nonroot
# The file system is read only. Mount a volume at /data for the log.
# Mount the salt and the head signing key as read only secrets.
ENV VCA_ISSUED_LISTEN=:8084 \
    VCA_ISSUED_STORE_FILE=/data/issued.json
VOLUME ["/data"]
EXPOSE 8084
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/issued-credentials", "-healthcheck"]
ENTRYPOINT ["/issued-credentials"]
