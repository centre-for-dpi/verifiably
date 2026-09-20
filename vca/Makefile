# Verifiable Credentials Adapters build entry points.
# Every target works on a restricted network after "make bootstrap".
GO ?= go
export PATH := $(HOME)/.cache/vca-mirrors/bin:$(PATH)
ifneq ($(wildcard go.work),)
export GOPROXY := off
export GOSUMDB := off
export GOFLAGS :=
endif
COVERAGE_FLOOR ?= 90

GOBIN ?= $(HOME)/go/bin

.PHONY: bootstrap gen lint test cover tidy build install doctor

bootstrap: ## install buf plugins (mirrors when the network is restricted)
	./hack/bootstrap.sh

gen: ## generate Go code from proto
	buf generate
	buf lint

lint: ## proto and Go lint
	buf lint
	$(GO) vet ./...
	gofmt -l . | tee /dev/stderr | test -z "$$(cat)"

test: ## unit tests with race detector
	$(GO) test -race -count=1 ./...

cover: ## enforce per-package coverage floor
	./hack/coverage.sh $(COVERAGE_FLOOR)

tidy: ## regenerate go.sum on a networked machine
	rm -f go.work go.work.sum
	$(GO) mod tidy

build: ## build every service and the CLI
	$(GO) build ./...

install: ## build the vca CLI into GOBIN
	$(GO) build -o $(GOBIN)/vca ./cmd/vca
	@echo "installed $(GOBIN)/vca; add that directory to PATH"

doctor: ## check that this host meets every prerequisite
	$(GO) run ./cmd/vca doctor --all --dpg waltid --from-source
ste-lint: ## Simplified Technical English check on docs and proto comments
	./hack/ste-lint.sh $$(ls docs/*.md | grep -v adr.md) README.md $$(find proto -name "*.proto")
