PLUGIN_NAME ?= vault-plugin-secrets-xai
BIN_DIR ?= bin
GO ?= go

VAULT_VERSION ?= 2.1.2
CONTAINER_ENGINE ?= docker
IMAGE_NAME ?= vault-xai
DIST ?= docker/dist

.PHONY: build test test-integration clean linux-bins docker docker-community docker-enterprise

build:
	CGO_ENABLED=0 $(GO) build -trimpath -o $(BIN_DIR)/$(PLUGIN_NAME) ./cmd/$(PLUGIN_NAME)

test:
	$(GO) test ./...

test-integration:
	$(GO) test -tags=integration -count=1 ./plugin

clean:
	rm -rf $(BIN_DIR) $(DIST)

linux-bins:
	mkdir -p $(DIST)/amd64 $(DIST)/arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -o $(DIST)/amd64/$(PLUGIN_NAME) ./cmd/$(PLUGIN_NAME)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -o $(DIST)/arm64/$(PLUGIN_NAME) ./cmd/$(PLUGIN_NAME)
	shasum -a 256 $(DIST)/amd64/$(PLUGIN_NAME) | awk '{print $$1}' > $(DIST)/amd64/$(PLUGIN_NAME).sha256
	shasum -a 256 $(DIST)/arm64/$(PLUGIN_NAME) | awk '{print $$1}' > $(DIST)/arm64/$(PLUGIN_NAME).sha256

docker: docker-community docker-enterprise

docker-community: linux-bins
	$(CONTAINER_ENGINE) build --platform linux/amd64 \
		--build-arg BASE_IMAGE=hashicorp/vault:$(VAULT_VERSION) \
		-t $(IMAGE_NAME):$(VAULT_VERSION)-amd64 \
		-f Dockerfile .
	$(CONTAINER_ENGINE) build --platform linux/arm64 \
		--build-arg BASE_IMAGE=hashicorp/vault:$(VAULT_VERSION) \
		-t $(IMAGE_NAME):$(VAULT_VERSION)-arm64 \
		-f Dockerfile .
	-$(CONTAINER_ENGINE) manifest rm $(IMAGE_NAME):$(VAULT_VERSION)
	$(CONTAINER_ENGINE) rmi $(IMAGE_NAME):$(VAULT_VERSION) >/dev/null 2>&1 || true
	$(CONTAINER_ENGINE) manifest create $(IMAGE_NAME):$(VAULT_VERSION) \
		$(IMAGE_NAME):$(VAULT_VERSION)-amd64 \
		$(IMAGE_NAME):$(VAULT_VERSION)-arm64

docker-enterprise: linux-bins
	$(CONTAINER_ENGINE) build --platform linux/amd64 \
		--build-arg BASE_IMAGE=hashicorp/vault-enterprise:$(VAULT_VERSION)-ent \
		-t $(IMAGE_NAME):$(VAULT_VERSION)-ent-amd64 \
		-f Dockerfile .
	$(CONTAINER_ENGINE) build --platform linux/arm64 \
		--build-arg BASE_IMAGE=hashicorp/vault-enterprise:$(VAULT_VERSION)-ent \
		-t $(IMAGE_NAME):$(VAULT_VERSION)-ent-arm64 \
		-f Dockerfile .
	-$(CONTAINER_ENGINE) manifest rm $(IMAGE_NAME):$(VAULT_VERSION)-ent
	$(CONTAINER_ENGINE) rmi $(IMAGE_NAME):$(VAULT_VERSION)-ent >/dev/null 2>&1 || true
	$(CONTAINER_ENGINE) manifest create $(IMAGE_NAME):$(VAULT_VERSION)-ent \
		$(IMAGE_NAME):$(VAULT_VERSION)-ent-amd64 \
		$(IMAGE_NAME):$(VAULT_VERSION)-ent-arm64
