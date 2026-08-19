BINARY = meshscan
GOMODCACHE ?= $(HOME)/go/pkg/mod
GOCACHE    ?= $(HOME)/.cache/go-build

GO_ENV = GOMODCACHE=$(GOMODCACHE) GOCACHE=$(GOCACHE)

.PHONY: build tidy lint test clean

build:
	$(GO_ENV) go build -o $(BINARY) ./cmd/meshscan/

tidy:
	$(GO_ENV) go mod tidy

lint:
	$(GO_ENV) go vet ./...

test:
	$(GO_ENV) go test ./...

clean:
	rm -f $(BINARY)
