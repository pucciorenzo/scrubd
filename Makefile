GOCACHE ?= /tmp/scrubd-gocache
GO ?= go
DOCKER ?= docker
BINARY ?= scrubd
IMAGE ?= scrubd:latest
PLATFORMS ?= linux/amd64,linux/arm64

.PHONY: all fmt test vet build check run scan-json docker-build leak-create leak-status leak-cleanup clean

all: check build

fmt:
	GOCACHE=$(GOCACHE) $(GO) fmt ./...

test:
	GOCACHE=$(GOCACHE) $(GO) test ./...

vet:
	GOCACHE=$(GOCACHE) $(GO) vet ./...

build:
	GOCACHE=$(GOCACHE) $(GO) build -o $(BINARY) ./cmd/scrubd

check: fmt test vet

run:
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/scrubd scan

scan-json:
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/scrubd scan --json

docker-build:
	$(DOCKER) buildx build --platform $(PLATFORMS) -t $(IMAGE) .

leak-create:
	sudo ./hack/leak-lab.sh create

leak-status:
	sudo ./hack/leak-lab.sh status

leak-cleanup:
	sudo ./hack/leak-lab.sh cleanup

clean:
	rm -f $(BINARY)
