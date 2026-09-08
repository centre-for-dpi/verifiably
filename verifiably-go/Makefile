# Makefile — verifiably-go developer + CI tasks.
#
# Image targets are designed to be runnable both locally (where REGISTRY may
# be unset) and in CI (where REGISTRY is the GHCR / ECR target). The image
# tag defaults to the current git SHA so pushes are immutable.
#
# Deploy targets are thin pass-throughs to ./deploy.sh so deploy.sh stays the
# single source of truth. See docs/deploy-reproducibility.md for the full
# repeatable nuke -> clone -> up runbook (VPS/EC2 and localhost).

REGISTRY ?= ghcr.io/$(shell git config --get remote.origin.url | sed -E 's@.*[:/]([^/]+)/[^/]+(\.git)?$$@\1@' | tr 'A-Z' 'a-z')
IMAGE_NAME ?= verifiably-go
GIT_SHA := $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
IMAGE_TAG ?= $(GIT_SHA)
IMAGE_REF := $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
IMAGE_LATEST := $(REGISTRY)/$(IMAGE_NAME):latest
# Go image for the containerised test/cover targets (matches CI + Dockerfile).
GO_IMAGE ?= golang:1.25-alpine

.PHONY: image image-push image-scan image-tag-latest \
        k8s-up k8s-down k8s-status k8s-logs \
        setup up-all down-all reset nuke status \
        waltid-up waltid-down inji-up inji-down credebl-up credebl-down \
        test test-pkg cover-gate help

help:
	@echo "Image / k8s:"
	@echo "  image            Build container image as $$REGISTRY/$$IMAGE_NAME:$$GIT_SHA"
	@echo "  image-push       Push the SHA-tagged image"
	@echo "  image-scan       Run Trivy filesystem + image scan"
	@echo "  image-tag-latest Tag $$GIT_SHA as :latest and push (used by CI on main only)"
	@echo "  k8s-up           ./deploy/k8s/scripts/k8s-deploy.sh up waltid"
	@echo "  k8s-down         ./deploy/k8s/scripts/k8s-deploy.sh down waltid"
	@echo "  k8s-status       ./deploy/k8s/scripts/k8s-deploy.sh status"
	@echo "  k8s-logs SVC=x   tail logs for a service"
	@echo ""
	@echo "Compose deploy (wraps ./deploy.sh; see docs/deploy-reproducibility.md):"
	@echo "  setup            First-run .env wizard (host/domain/LE)"
	@echo "  up-all           Bring up the whole stack           (./deploy.sh up all)"
	@echo "  waltid-up        Bring up the walt.id DPG            (./deploy.sh up waltid)"
	@echo "  inji-up          Bring up the Inji DPG              (./deploy.sh up inji)"
	@echo "  credebl-up       Bring up the CREDEBL DPG           (./deploy.sh up credebl)"
	@echo "  <dpg>-down       Tear down a DPG                    (./deploy.sh down <dpg>)"
	@echo "  down-all         Tear down the whole stack"
	@echo "  reset            Tear down + wipe volumes           (./deploy.sh reset)"
	@echo "  nuke             TOTAL docker nuke (ALL projects' containers/images/volumes)"
	@echo "  status           Show running services"
	@echo ""
	@echo "Tests (run inside $$GO_IMAGE):"
	@echo "  test             go test -count=1 ./..."
	@echo "  test-pkg PKG=x   go test -count=1 -v PKG"
	@echo "  cover-gate       per-function 100% coverage gate for internal/handlers"
	@echo ""
	@echo "Per-role targets (waltid-issuer-up, inji-authcode-up, ...) are a documented"
	@echo "follow-on — deploy.sh currently deploys at DPG granularity. See"
	@echo "docs/deploy-reproducibility.md."

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

# Per-function statement-coverage gate (scripts/ci/coverage-gate.sh is POSIX
# sh, so it runs in alpine without installing bash).
cover-gate:
	docker run --rm \
	    -v "$(shell pwd):/src" \
	    -w /src \
	    $(GO_IMAGE) \
	    sh scripts/ci/coverage-gate.sh

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

# --- Compose deploy (single source of truth: ./deploy.sh) ---
setup:       ; ./deploy.sh setup
up-all:      ; ./deploy.sh up all
down-all:    ; ./deploy.sh down all
reset:       ; ./deploy.sh reset
status:      ; ./deploy.sh status
waltid-up:   ; ./deploy.sh up waltid
waltid-down: ; ./deploy.sh down waltid
inji-up:     ; ./deploy.sh up inji
inji-down:   ; ./deploy.sh down inji
credebl-up:  ; ./deploy.sh up credebl
credebl-down:; ./deploy.sh down credebl

# TOTAL docker nuke — wipes EVERY project's containers/images/volumes/networks
# on this host (see docs/deploy-reproducibility.md). Guarded behind a confirm.
nuke:
	@printf 'This wipes ALL docker containers/images/volumes/networks on this host. Continue? [y/N] '; \
	read ans; [ "$$ans" = y ] || [ "$$ans" = Y ] || { echo aborted; exit 1; }; \
	docker rm -f $$(docker ps -aq) 2>/dev/null; \
	docker rmi -f $$(docker images -aq) 2>/dev/null; \
	docker volume rm $$(docker volume ls -q) 2>/dev/null; \
	docker network rm $$(docker network ls -q --filter type=custom) 2>/dev/null; \
	docker system prune -a --volumes -f
