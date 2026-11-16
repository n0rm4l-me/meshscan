BINARY  := meshscan
PKG     := github.com/n0rm4l-me/meshscan
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.Date=$(DATE)

.DEFAULT_GOAL := help
.PHONY: help build install fmt vet lint test cover tidy tidy-check check docker clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-z-]+:.*## / {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build ./meshscan with version information
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/meshscan

install: ## Install meshscan into GOBIN with version information
	go install -trimpath -ldflags '$(LDFLAGS)' ./cmd/meshscan

fmt: ## Format all Go files
	gofmt -w .

vet: ## Run go vet
	go vet ./...

lint: ## Run golangci-lint (formatting is checked as well)
	golangci-lint run

test: ## Run the tests with the race detector
	go test -race -count=1 ./...

cover: ## Run the tests and print coverage per function
	go test -race -count=1 -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

tidy: ## Tidy go.mod and go.sum
	go mod tidy

tidy-check: ## Fail when go.mod or go.sum are not tidy
	go mod tidy
	git diff --exit-code go.mod go.sum

check: vet lint test ## Everything CI runs, except the vulnerability scan

docker: ## Build the container image
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) -t $(BINARY):$(VERSION) .

clean: ## Remove build output
	rm -rf $(BINARY) dist coverage.out
