APP_NAME ?= spring-boot-template
COMPOSE_FILE ?= docker/docker-compose.yml

compose-up:
	docker compose -f $(COMPOSE_FILE) up --build

compose-down:
	docker compose -f $(COMPOSE_FILE) down

compose-aot:
	docker compose -f $(COMPOSE_FILE) --profile aot up --build

compose-cds:
	docker compose -f $(COMPOSE_FILE) --profile cds up --build

compose-native:
	docker compose -f $(COMPOSE_FILE) --profile native up --build

docker-build:
	docker build -f docker/Dockerfile -t $(APP_NAME):latest .

docker-build-aot:
	docker build -f docker/Dockerfile.aot -t $(APP_NAME):aot .

docker-build-cds:
	docker build -f docker/Dockerfile.cds -t $(APP_NAME):cds .

docker-build-native:
	docker build \
		-f docker/Dockerfile.native \
		--build-arg IMAGE_NAME=$(APP_NAME) \
		-t $(APP_NAME):native .


help:
	@echo "make compose-up        Run default JVM"
	@echo "make compose-aot       Run AOT profile"
	@echo "make compose-cds       Run CDS profile"
	@echo "make compose-native    Run Native profile"