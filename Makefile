# ABOUTME: Main Makefile for hikma-av antivirus service
# ABOUTME: Build, test, lint, and development workflow automation

# Safety headers
SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

.DEFAULT_GOAL := help

# ==============================================================================
# Variables
# ==============================================================================

# Project
PROJECT_NAME := hikma-av
MODULE := github.com/hikmaai-io/hikma-av
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_SHA := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

# Go
GO := go
GOFLAGS ?=
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION) -X main.gitSHA=$(GIT_SHA) -X main.buildTime=$(BUILD_TIME)"

# Directories
BIN_DIR := ./bin
CMD_DIR := ./cmd/hikma-av
COVERAGE_DIR := ./coverage

# Docker
DOCKER_IMAGE := hikmaai/hikma-av
DOCKER_TAG ?= $(VERSION)

# Tools
GOLANGCI_LINT_VERSION := v1.62.0

# Colors
CYAN := \033[0;36m
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
BOLD := \033[1m
NC := \033[0m

# ==============================================================================
# Macros
# ==============================================================================

define log_info
	@printf "$(CYAN)[INFO]$(NC) %s\n" "$(1)"
endef

define log_success
	@printf "$(GREEN)[OK]$(NC) %s\n" "$(1)"
endef

define log_warn
	@printf "$(YELLOW)[WARN]$(NC) %s\n" "$(1)"
endef

define log_error
	@printf "$(RED)[ERROR]$(NC) %s\n" "$(1)"
endef

define log_step
	@printf "$(BOLD)>>> %s$(NC)\n" "$(1)"
endef

# ==============================================================================
# Targets
# ==============================================================================

##@ General

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} \
		/^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: version
version: ## Show version information
	@echo "Version:    $(VERSION)"
	@echo "Git SHA:    $(GIT_SHA)"
	@echo "Build Time: $(BUILD_TIME)"

##@ Development

.PHONY: deps
deps: ## Download dependencies
	$(call log_step,Downloading dependencies)
	@$(GO) mod download
	@$(GO) mod verify
	$(call log_success,Dependencies downloaded)

.PHONY: tidy
tidy: ## Tidy go modules
	$(call log_step,Tidying modules)
	@$(GO) mod tidy
	$(call log_success,Modules tidied)

.PHONY: fmt
fmt: ## Format code
	$(call log_step,Formatting code)
	@$(GO) fmt ./...
	@goimports -w -local $(MODULE) .
	$(call log_success,Code formatted)

.PHONY: generate
generate: ## Run go generate
	$(call log_step,Running go generate)
	@$(GO) generate ./...
	$(call log_success,Generation complete)

##@ Build

.PHONY: build
build: ## Build the binary
	$(call log_step,Building $(PROJECT_NAME))
	@mkdir -p $(BIN_DIR)
	@$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BIN_DIR)/$(PROJECT_NAME) $(CMD_DIR)
	$(call log_success,Binary built: $(BIN_DIR)/$(PROJECT_NAME))

.PHONY: build-race
build-race: ## Build with race detector
	$(call log_step,Building with race detector)
	@mkdir -p $(BIN_DIR)
	@$(GO) build -race $(GOFLAGS) $(LDFLAGS) -o $(BIN_DIR)/$(PROJECT_NAME)-race $(CMD_DIR)
	$(call log_success,Race binary built)

.PHONY: install
install: ## Install the binary
	$(call log_step,Installing $(PROJECT_NAME))
	@$(GO) install $(GOFLAGS) $(LDFLAGS) $(CMD_DIR)
	$(call log_success,Installed)

.PHONY: clean
clean: ## Clean build artifacts
	$(call log_step,Cleaning)
	@rm -rf $(BIN_DIR)
	@rm -rf $(COVERAGE_DIR)
	@rm -f coverage.out coverage.html
	$(call log_success,Cleaned)

##@ Testing

.PHONY: test
test: ## Run tests
	$(call log_step,Running tests)
	@$(GO) test -race -v ./...
	$(call log_success,Tests passed)

.PHONY: test-short
test-short: ## Run short tests only
	$(call log_step,Running short tests)
	@$(GO) test -short -race ./...
	$(call log_success,Short tests passed)

.PHONY: test-cover
test-cover: ## Run tests with coverage
	$(call log_step,Running tests with coverage)
	@mkdir -p $(COVERAGE_DIR)
	@$(GO) test -race -coverprofile=$(COVERAGE_DIR)/coverage.out -covermode=atomic ./...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/coverage.out | tail -1
	$(call log_success,Coverage report: $(COVERAGE_DIR)/coverage.html)

.PHONY: test-bench
test-bench: ## Run benchmarks
	$(call log_step,Running benchmarks)
	@$(GO) test -bench=. -benchmem ./...
	$(call log_success,Benchmarks complete)

##@ Quality

.PHONY: lint
lint: ## Run linters
	$(call log_step,Running linters)
	@golangci-lint run --config .golangci.yaml ./...
	$(call log_success,Linting passed)

.PHONY: lint-fix
lint-fix: ## Run linters with auto-fix
	$(call log_step,Running linters with fix)
	@golangci-lint run --config .golangci.yaml --fix ./...
	$(call log_success,Linting complete)

.PHONY: vet
vet: ## Run go vet
	$(call log_step,Running go vet)
	@$(GO) vet ./...
	$(call log_success,Vet passed)

.PHONY: check
check: fmt vet lint test ## Run all checks (fmt, vet, lint, test)
	$(call log_success,All checks passed)

##@ Docker

.PHONY: docker-build
docker-build: ## Build Docker image
	$(call log_step,Building Docker image)
	@docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) -f deploy/docker/Dockerfile .
	$(call log_success,Image built: $(DOCKER_IMAGE):$(DOCKER_TAG))

.PHONY: docker-push
docker-push: ## Push Docker image
	$(call log_step,Pushing Docker image)
	@docker push $(DOCKER_IMAGE):$(DOCKER_TAG)
	$(call log_success,Image pushed)

##@ Tools

.PHONY: tools
tools: ## Install development tools
	$(call log_step,Installing tools)
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	@go install golang.org/x/tools/cmd/goimports@latest
	$(call log_success,Tools installed)

##@ Run

.PHONY: run
run: build ## Run the daemon in foreground
	$(call log_step,Running daemon)
	@$(BIN_DIR)/$(PROJECT_NAME) daemon

.PHONY: run-scan
run-scan: build ## Run a scan (usage: make run-scan HASH=<hash>)
	@$(BIN_DIR)/$(PROJECT_NAME) scan $(HASH)
