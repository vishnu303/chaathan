# Chaathan - Pentesting Recon Framework
# Makefile for build, install, and development tasks

BINARY_NAME := chaathan
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GOFLAGS := -buildvcs=false -ldflags "-s -w -X github.com/vishnu303/chaathan/cli.Version=$(VERSION) -X github.com/vishnu303/chaathan/cli.BuildTime=$(BUILD_TIME)"
INSTALL_DIR := /usr/local/bin

.PHONY: all build install uninstall clean test vet lint setup tools-check help dev version

help: ## Show this help message with dynamic target listings
	@echo "Chaathan Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make <target>"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

all: build install setup ## Build, install, and setup all external tools (all-in-one bootstrap)

build: ## Build the chaathan binary with version flags
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	@go build $(GOFLAGS) -o $(BINARY_NAME) .
	@echo "✅ Built: ./$(BINARY_NAME)"

install: build ## Build and install the chaathan binary to the system path
	@echo "Installing to $(INSTALL_DIR)/$(BINARY_NAME)..."
	@sudo mkdir -p $(INSTALL_DIR)
	@sudo install -m 0755 $(BINARY_NAME) $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "✅ Installed: $(INSTALL_DIR)/$(BINARY_NAME)"

uninstall: ## Remove the chaathan binary from the system path
	@echo "Removing $(INSTALL_DIR)/$(BINARY_NAME)..."
	@sudo rm -f $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "✅ Uninstalled"

clean: ## Remove compiled binaries and temporary build artifacts
	@echo "Cleaning..."
	@rm -f $(BINARY_NAME) chaathan-flow chaathan-test main
	@go clean
	@echo "✅ Clean"

test: ## Run the Go unit test suite
	@echo "Running tests..."
	@go test ./... -v -count=1
	@echo "✅ Tests passed"

vet: ## Run static code analysis with go vet
	@echo "Running go vet..."
	@go vet ./...
	@echo "✅ No issues found"

lint: ## Run code linting audits with golangci-lint
	@echo "Running linter..."
	@which golangci-lint > /dev/null 2>&1 || (echo "Install golangci-lint first: https://golangci-lint.run/usage/install/" && exit 1)
	@golangci-lint run ./...
	@echo "✅ Lint passed"

setup: build ## Build and execute the environment installer for third-party tools
	@echo "Running tool setup..."
	@./$(BINARY_NAME) setup
	@echo "✅ Setup complete"

tools-check: build ## Verify the path installation status of all 30 external tools
	@./$(BINARY_NAME) tools check

dev: build ## Run status check command under development mode
	@./$(BINARY_NAME) status

version: build ## Print compile-time build version details
	@./$(BINARY_NAME) version
