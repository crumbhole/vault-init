.PHONY: docker-build-multi docker-build-multi-push docker-buildx-setup help

IMAGE_NAME := jpz13/vault-init
PLATFORMS := linux/amd64,linux/arm64
BUILDER_NAME := vault-init-builder

help: ## Show this help message
	@echo "Available targets:"
	@echo "  docker-buildx-setup      - Create and setup buildx builder for multi-arch builds"
	@echo "  docker-build-multi       - Build multi-arch Docker image (arm64, amd64) and load to local Docker"
	@echo "  docker-build-multi-push  - Build and push multi-arch Docker image to registry"

docker-buildx-setup: ## Create and setup buildx builder for multi-platform builds
	@docker buildx ls | grep -q $(BUILDER_NAME) || \
		(docker buildx create --name $(BUILDER_NAME) --driver docker-container --bootstrap && \
		echo "Created buildx builder: $(BUILDER_NAME)")
	@docker buildx use $(BUILDER_NAME)
	@echo "Using buildx builder: $(BUILDER_NAME)"

docker-build-multi: docker-buildx-setup ## Build multi-architecture Docker image for arm64 and amd64
	docker buildx build \
		--builder $(BUILDER_NAME) \
		--platform $(PLATFORMS) \
		--tag $(IMAGE_NAME):latest \
		--load \
		.

docker-build-multi-push: docker-buildx-setup ## Build and push multi-architecture Docker image for arm64 and amd64
	docker buildx build \
		--builder $(BUILDER_NAME) \
		--platform $(PLATFORMS) \
		--tag $(IMAGE_NAME):latest \
		--push \
		.
