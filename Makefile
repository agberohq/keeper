APP_NAME  := keeper
BUILD_DIR := bin
SRC_DIR   := ./cmd/keeper

# Remote for pushing tags
REMOTE ?= origin

# Release version (required for tag/release targets)
RELEASE_VERSION ?=

# Version injection — falls back gracefully when not in a git repo
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -s -w \
  -X "main.version=$(VERSION)" \
  -X "main.commit=$(COMMIT)" \
  -X "main.date=$(DATE)"

# Install directory — same precedence logic as agbero
GO_ENV_GOPATH := $(shell go env GOPATH)
GO_ENV_GOBIN  := $(shell go env GOBIN)

ifdef PREFIX
  BINDIR := $(PREFIX)/bin
else ifneq ($(GO_ENV_GOBIN),)
  BINDIR := $(GO_ENV_GOBIN)
else ifneq ($(GO_ENV_GOPATH),)
  BINDIR := $(GO_ENV_GOPATH)/bin
else
  BINDIR := /usr/local/bin
endif

.PHONY: all build clean install test fmt tidy version \
        build-all ensure-clean ensure-release-version tag release help

all: build

help:
	@echo "Usage:"
	@echo "  make build                       Build for current OS/arch"
	@echo "  make install                     Install to $(BINDIR)"
	@echo "  make install PREFIX=/usr/local   Install to /usr/local/bin"
	@echo "  make test                        Run tests with -race"
	@echo "  make build-all                   Cross-compile all platforms"
	@echo "  make version                     Print version info"
	@echo "  make clean                       Remove build artifacts"
	@echo "  make fmt                         Format source"
	@echo "  make tidy                        go mod tidy"
	@echo ""
	@echo "  make tag RELEASE_VERSION=v0.0.1  Create + push annotated tag"
	@echo "  make release RELEASE_VERSION=v0.0.1"
	@echo "               tag + trigger GitHub Actions release workflow"

# ── Build ──────────────────────────────────────────────────────────────────────

build:
	@echo "Building $(APP_NAME) $(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	go build -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(APP_NAME) $(SRC_DIR)
	@echo "→ $(BUILD_DIR)/$(APP_NAME)"
	@$(BUILD_DIR)/$(APP_NAME) --version

install: build
	@echo "Installing to $(DESTDIR)$(BINDIR)..."
	@mkdir -p $(DESTDIR)$(BINDIR)
	install -m 755 $(BUILD_DIR)/$(APP_NAME) $(DESTDIR)$(BINDIR)/$(APP_NAME)
	@echo "✓ installed $(DESTDIR)$(BINDIR)/$(APP_NAME)"

clean:
	rm -rf $(BUILD_DIR)

# ── Cross-compile ──────────────────────────────────────────────────────────────

build-all: clean
	@echo "Cross-compiling $(APP_NAME) $(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux   GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64   $(SRC_DIR)
	GOOS=linux   GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(APP_NAME)-linux-arm64   $(SRC_DIR)
	GOOS=darwin  GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(APP_NAME)-darwin-amd64  $(SRC_DIR)
	GOOS=darwin  GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(APP_NAME)-darwin-arm64  $(SRC_DIR)
	GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(APP_NAME)-windows-amd64.exe $(SRC_DIR)
	GOOS=windows GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(APP_NAME)-windows-arm64.exe $(SRC_DIR)
	@echo ""
	@ls -lh $(BUILD_DIR)/

# ── Quality ────────────────────────────────────────────────────────────────────

test:
	go test -count=1 -race ./...

fmt:
	gofmt -w -s .
	go fmt ./...

tidy:
	go mod tidy

version:
	@echo "Version:  $(VERSION)"
	@echo "Commit:   $(COMMIT)"
	@echo "Date:     $(DATE)"
	@echo "Go:       $(shell go version)"

# ── Release ────────────────────────────────────────────────────────────────────

ensure-clean:
	@git diff --quiet || (echo "error: working tree has uncommitted changes"; exit 1)
	@test -z "$$(git status --porcelain)" || \
	  (echo "error: untracked/staged files present:"; git status --porcelain; exit 1)

ensure-release-version:
	@test -n "$(RELEASE_VERSION)" || \
	  (echo "error: set RELEASE_VERSION — e.g. make release RELEASE_VERSION=v0.0.1"; exit 1)
	@echo "$(RELEASE_VERSION)" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+' || \
	  (echo "error: RELEASE_VERSION must match vMAJOR.MINOR.PATCH (got: $(RELEASE_VERSION))"; exit 1)

# tag: create an annotated tag locally and push it.
# The push triggers .github/workflows/release.yml which builds and publishes.
tag: ensure-clean ensure-release-version
	@if git rev-parse "$(RELEASE_VERSION)" >/dev/null 2>&1; then \
	  echo "error: tag $(RELEASE_VERSION) already exists — bump the version"; \
	  exit 1; \
	fi
	@echo "Tagging $(RELEASE_VERSION) at $$(git rev-parse --short HEAD)..."
	git tag -a $(RELEASE_VERSION) -m "Release $(RELEASE_VERSION)"
	git push $(REMOTE) $(RELEASE_VERSION)
	@echo "✓ tag pushed — GitHub Actions will build and publish the release"

# release = tag (which triggers CI). Nothing else needed locally.
release: tag
