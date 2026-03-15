# Makefile — MCP Suite
# Compile les 3 binaires statiques pour Linux AMD64

BINARY_DIR  := /srv/mcp-suite/bin
BUILD_DIR   := ./build
VERSION     ?= $(shell git describe --tags --always 2>/dev/null || echo "dev")
BUILD_HASH  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS     := -w -s -X main.version=$(VERSION) -X main.buildHash=$(BUILD_HASH)
BUILD_FLAGS := CGO_ENABLED=0 GOOS=linux GOARCH=amd64

.PHONY: all license-server worker master install clean

all: license-server worker master

license-server:
	@echo "→ Compilation license-server..."
	@mkdir -p $(BUILD_DIR)
	$(BUILD_FLAGS) go build \
		-trimpath \
		-ldflags '$(LDFLAGS)' \
		-o $(BUILD_DIR)/license-server \
		./cmd/license-server
	@echo "✓ license-server compilé ($(BUILD_DIR)/license-server)"

worker:
	@echo "→ Compilation worker..."
	$(BUILD_FLAGS) go build \
		-trimpath \
		-ldflags '$(LDFLAGS)' \
		-o $(BUILD_DIR)/worker \
		./cmd/worker
	@echo "✓ worker compilé"

master:
	@echo "→ Compilation master..."
	$(BUILD_FLAGS) go build \
		-trimpath \
		-ldflags '$(LDFLAGS)' \
		-o $(BUILD_DIR)/master \
		./cmd/master
	@echo "✓ master compilé"

# Installe les binaires compilés dans /srv/mcp-suite/bin/
install: all
	@echo "→ Installation dans $(BINARY_DIR)..."
	install -m 755 $(BUILD_DIR)/license-server $(BINARY_DIR)/
	install -m 755 $(BUILD_DIR)/worker $(BINARY_DIR)/
	install -m 755 $(BUILD_DIR)/master $(BINARY_DIR)/
	@echo "✓ Binaires installés"

# Installe les services systemd
systemd:
	cp systemd/*.service /etc/systemd/system/
	systemctl daemon-reload
	@echo "✓ Services systemd installés"

clean:
	rm -rf $(BUILD_DIR)
