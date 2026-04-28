GOCACHE ?= /tmp/scrubd-gocache
GO ?= go
DOCKER ?= docker
BINARY ?= scrubd
VERSION ?= dev
DIST_DIR ?= dist
IMAGE ?= scrubd:latest
PLATFORMS ?= linux/amd64,linux/arm64

.PHONY: all fmt test vet build dist dist-linux-amd64 dist-linux-arm64 check run scan scan-json scan-docker sudo-scan sudo-scan-json sudo-scan-docker docker-build leak-create leak-status leak-cleanup linux-validate clean

all: check build

fmt:
	GOCACHE=$(GOCACHE) $(GO) fmt ./...

test:
	GOCACHE=$(GOCACHE) $(GO) test ./...

vet:
	GOCACHE=$(GOCACHE) $(GO) vet ./...

build:
	GOCACHE=$(GOCACHE) $(GO) build -o $(BINARY) ./cmd/scrubd

dist: dist-linux-amd64 dist-linux-arm64

dist-linux-amd64:
	mkdir -p $(DIST_DIR)/$(BINARY)_$(VERSION)_linux_amd64
	GOCACHE=$(GOCACHE) CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags="-s -w" -o $(DIST_DIR)/$(BINARY)_$(VERSION)_linux_amd64/$(BINARY) ./cmd/scrubd

dist-linux-arm64:
	mkdir -p $(DIST_DIR)/$(BINARY)_$(VERSION)_linux_arm64
	GOCACHE=$(GOCACHE) CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags="-s -w" -o $(DIST_DIR)/$(BINARY)_$(VERSION)_linux_arm64/$(BINARY) ./cmd/scrubd

check: fmt test vet

run:
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/scrubd scan

scan: build
	./$(BINARY) scan

scan-json:
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/scrubd scan --json

scan-docker: build
	./$(BINARY) scan --runtime docker

sudo-scan: build
	sudo ./$(BINARY) scan

sudo-scan-json: build
	sudo ./$(BINARY) scan --json

sudo-scan-docker: build
	sudo ./$(BINARY) scan --runtime docker

docker-build:
	$(DOCKER) buildx build --platform $(PLATFORMS) -t $(IMAGE) .

leak-create:
	sudo ./hack/leak-lab.sh create

leak-status:
	sudo ./hack/leak-lab.sh status

leak-cleanup:
	sudo ./hack/leak-lab.sh cleanup

linux-validate:
	$(MAKE) check
	$(MAKE) build
	$(MAKE) leak-create
	$(MAKE) sudo-scan
	$(MAKE) sudo-scan-json
	$(MAKE) sudo-scan-docker
	$(MAKE) leak-cleanup
	$(MAKE) sudo-scan-docker

clean:
	rm -f $(BINARY)
	rm -rf $(DIST_DIR)
