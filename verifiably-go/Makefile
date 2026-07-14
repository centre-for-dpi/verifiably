# Makefile — verifiably-go developer + CI tasks.
#
# Image targets are designed to be runnable both locally (where REGISTRY may
# be unset) and in CI (where REGISTRY is the GHCR / ECR target). The image
# tag defaults to the current git SHA so pushes are immutable.

REGISTRY ?= ghcr.io/$(shell git config --get remote.origin.url | sed -E 's@.*[:/]([^/]+)/[^/]+(\.git)?$$@\1@' | tr 'A-Z' 'a-z')
IMAGE_NAME ?= verifiably-go
GIT_SHA := $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
IMAGE_TAG ?= $(GIT_SHA)
IMAGE_REF := $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
IMAGE_LATEST := $(REGISTRY)/$(IMAGE_NAME):latest

GO_IMAGE ?= golang:1.25-alpine

.PHONY: test test-pkg image image-push image-scan image-tag-latest \
        k8s-up k8s-down k8s-status k8s-logs help

help:
	@echo "Targets:"
	@echo "  test             Run all unit tests via Docker (no local Go required)"
	@echo "  test-pkg PKG=x   Run tests for a specific package, e.g. PKG=./internal/handlers/"
	@echo "  image            Build container image as $$REGISTRY/$$IMAGE_NAME:$$GIT_SHA"
	@echo "  image-push       Push the SHA-tagged image"
	@echo "  image-scan       Run Trivy filesystem + image scan"
	@echo "  image-tag-latest Tag $$GIT_SHA as :latest and push (used by CI on main only)"
	@echo "  k8s-up           ./deploy/k8s/scripts/k8s-deploy.sh up waltid"
	@echo "  k8s-down         ./deploy/k8s/scripts/k8s-deploy.sh down waltid"
	@echo "  k8s-status       ./deploy/k8s/scripts/k8s-deploy.sh status"
	@echo "  k8s-logs SVC=x   tail logs for a service"

test:
	docker run --rm \
	    -v "$(shell pwd):/src" \
	    -w /src \
	    $(GO_IMAGE) \
	    go test -count=1 ./...

test-pkg:
	@test -n "$(PKG)" || { echo "usage: make test-pkg PKG=./internal/handlers/"; exit 2; }
	docker run --rm \
	    -v "$(shell pwd):/src" \
	    -w /src \
	    $(GO_IMAGE) \
	    go test -count=1 -v $(PKG)

image:
	docker build -t $(IMAGE_REF) -t $(IMAGE_NAME):local .
	@echo "built $(IMAGE_REF)"

image-push:
	docker push $(IMAGE_REF)

image-scan:
	@command -v trivy >/dev/null || { echo "trivy not installed"; exit 1; }
	trivy fs --severity HIGH,CRITICAL --exit-code 1 .
	trivy image --severity HIGH,CRITICAL --exit-code 0 $(IMAGE_REF)

image-tag-latest:
	docker tag $(IMAGE_REF) $(IMAGE_LATEST)
	docker push $(IMAGE_LATEST)

k8s-up:
	./deploy/k8s/scripts/k8s-deploy.sh up waltid

k8s-down:
	./deploy/k8s/scripts/k8s-deploy.sh down waltid

k8s-status:
	./deploy/k8s/scripts/k8s-deploy.sh status

k8s-logs:
	@test -n "$(SVC)" || { echo "usage: make k8s-logs SVC=<service>"; exit 2; }
	./deploy/k8s/scripts/k8s-deploy.sh logs $(SVC)
