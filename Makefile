SHELL := /bin/bash

GO ?= go
COMPOSE ?= docker compose
GOLANGCI_LINT_VERSION ?= v2.15.0
GOLANGCI_LINT := $(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

.PHONY: help dev up down clean logs ps run build test test-race test-integration \
	lint fmt fmt-check vet migrate migrate-down migrate-version migrate-force ci

help:
	@echo "Targets:"
	@echo "  dev               Build and run the stack in the foreground"
	@echo "  up                Build and run the stack in the background"
	@echo "  down              Stop containers (keeps the PostgreSQL volume)"
	@echo "  clean             Stop containers and REMOVE the PostgreSQL volume"
	@echo "  logs              Follow application logs"
	@echo "  ps                Show container status"
	@echo "  run               Run the server on the host (loads .env if present)"
	@echo "  build             Compile all Go packages"
	@echo "  test              Run unit tests"
	@echo "  test-race         Run unit tests with the race detector"
	@echo "  test-integration  Run tests tagged integration against Compose PostgreSQL"
	@echo "  lint              Run golangci-lint $(GOLANGCI_LINT_VERSION)"
	@echo "  fmt               Format Go sources with gofmt"
	@echo "  fmt-check         Fail if any Go source is not formatted"
	@echo "  vet               Run go vet"
	@echo "  migrate           Apply pending migrations explicitly"
	@echo "  migrate-down      Roll back one migration"
	@echo "  migrate-version   Show the applied migration version"
	@echo "  migrate-force     Set a version without running SQL (VERSION=<n>)"
	@echo "  ci                Run the local CI checks"

dev:
	$(COMPOSE) up --build

up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

clean:
	$(COMPOSE) down -v --remove-orphans

logs:
	$(COMPOSE) logs -f app

ps:
	$(COMPOSE) ps

run:
	@set -a; if [ -f .env ]; then . ./.env; fi; set +a; $(GO) run ./cmd/server

build:
	$(GO) build ./...

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

test-integration:
	$(COMPOSE) up -d --wait postgres
	@set -a; if [ -f .env ]; then . ./.env; fi; set +a; \
		TEST_DATABASE_URL="$${TEST_DATABASE_URL:-postgres://$${POSTGRES_USER:-lds}:$${POSTGRES_PASSWORD:-lds_dev_password}@localhost:$${POSTGRES_PORT:-5432}/$${POSTGRES_DB:-lds_user_service}?sslmode=disable}" \
		$(GO) test -tags=integration ./...

lint:
	$(GOLANGCI_LINT) run ./...

fmt:
	$(GO) fmt ./...

fmt-check:
	@files="$$(find . -name '*.go' -not -path './.git/*')"; \
	if [ -n "$$files" ]; then \
		unformatted="$$(gofmt -l $$files)"; \
		if [ -n "$$unformatted" ]; then \
			echo "Unformatted files:"; \
			echo "$$unformatted"; \
			exit 1; \
		fi; \
	fi

vet:
	$(GO) vet ./...

migrate:
	$(COMPOSE) --profile tools run --rm migrate up

migrate-down:
	$(COMPOSE) --profile tools run --rm migrate down 1

migrate-version:
	$(COMPOSE) --profile tools run --rm migrate version

migrate-force:
	@if [ -z "$(VERSION)" ]; then echo "VERSION is required"; exit 1; fi
	$(COMPOSE) --profile tools run --rm migrate force $(VERSION)

ci: fmt-check vet build test lint
