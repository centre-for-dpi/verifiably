# SPDX-License-Identifier: Apache-2.0
# Build from the vca/ directory:
#   docker build -f services/verifier-auth/Dockerfile -t ghcr.io/centre-for-dpi/vca-verifier-auth .
FROM golang:1.25 AS build
WORKDIR /src
# go.sum is absent until "make tidy" runs on a networked machine.
COPY go.mod go.su[m] ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/verifier-auth ./services/verifier-auth
RUN mkdir -p /out/data

FROM gcr.io/distroless/static-debian13:nonroot
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
LABEL org.opencontainers.image.title="vca-verifier-auth" \
      org.opencontainers.image.description="Verifier staff OIDC login and ES256 session tokens (ADR-036)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.source="https://github.com/centre-for-dpi/verifiably" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/verifier-auth /verifier-auth
# The volume mount point exists in the image and belongs to the nonroot
# user, so a new named volume copies that ownership and the service
# can write. A container that mounts a root owned volume cannot.
COPY --from=build --chown=65532:65532 /out/data /data
USER nonroot:nonroot
ENV VCA_VERIFIER_AUTH_LISTEN=:8081 \
    VCA_VERIFIER_AUTH_STATE_DIR=/data
VOLUME ["/data"]
EXPOSE 8081
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/verifier-auth", "-healthcheck"]
ENTRYPOINT ["/verifier-auth"]
