# perch-collector (Perch Network Collector) — build targets.
#
# Two flavours of binary:
#
#   make build      → port-based only (no cgo, no libndpi needed)
#   make build-ndpi → port-based + nDPI deep packet inspection (cgo;
#                     requires nDPI >= 5.0: headers + libndpi found via
#                     pkg-config at build time, libndpi at runtime).
#                     Distro packages are still 4.x; scripts/build-ndpi.sh
#                     builds 5.0 into a prefix, then
#                     `make build-ndpi NDPI_PREFIX=<prefix>`.
#
# The runtime config knob `classification_mode` selects which classifier
# is used. A binary built without -tags ndpi cannot honour
# `classification_mode: ndpi`; it will log a warning and fall back to
# port-based on startup.

BIN          ?= perch-collector
IMAGE        ?= perch-collector
PKG          := ./...
GO           ?= go
BUILD_FLAGS  ?= -trimpath
# Version baked into the binary (start-up line, /healthz, the hello): the tag
# at HEAD without its v, else the commit; override with VERSION=.
VERSION      ?= $(or $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//'),dev)
LDFLAGS      ?= -s -w -X main.version=$(VERSION)

# Non-system nDPI install (see scripts/build-ndpi.sh). Points pkg-config
# at it for the cgo build, the test runner's dynamic linker at its lib/,
# and bakes that lib/ into the binary's RUNPATH so it starts without
# LD_LIBRARY_PATH. Leave empty when libndpi >= 5.0 is installed
# system-wide.
NDPI_PREFIX  ?=
ifneq ($(strip $(NDPI_PREFIX)),)
NDPI_ENV     := PKG_CONFIG_PATH=$(NDPI_PREFIX)/lib/pkgconfig$${PKG_CONFIG_PATH:+:$$PKG_CONFIG_PATH} \
                LD_LIBRARY_PATH=$(NDPI_PREFIX)/lib$${LD_LIBRARY_PATH:+:$$LD_LIBRARY_PATH} \
                CGO_LDFLAGS="$${CGO_LDFLAGS:--g -O2} -Wl,-rpath,$(NDPI_PREFIX)/lib"
endif

.PHONY: build build-ndpi test test-ndpi clean check-ndpi-deps docker

build:
	$(GO) build $(BUILD_FLAGS) -ldflags '$(LDFLAGS)' -o $(BIN) .

build-ndpi: check-ndpi-deps
	$(NDPI_ENV) CGO_ENABLED=1 $(GO) build $(BUILD_FLAGS) -tags ndpi -ldflags '$(LDFLAGS)' -o $(BIN) .

test:
	$(GO) test $(PKG)

# Runs the cgo nDPI build path so any header/linker drift in libndpi
# surfaces in CI as a build failure rather than at first start.
test-ndpi: check-ndpi-deps
	$(NDPI_ENV) CGO_ENABLED=1 $(GO) test -tags ndpi $(PKG)

check-ndpi-deps:
	@command -v pkg-config >/dev/null || { echo "pkg-config not installed; apt install pkg-config"; exit 1; }
	@$(NDPI_ENV) pkg-config --exists libndpi || { \
	  echo "libndpi not found via pkg-config; perch-collector requires nDPI >= 5.0."; \
	  echo "Build it into a prefix and point the build at it:"; \
	  echo "  scripts/build-ndpi.sh [prefix]                     # default prefix: \$$HOME/.local/ndpi5"; \
	  echo "  make build-ndpi NDPI_PREFIX=\$$HOME/.local/ndpi5     # likewise make test-ndpi"; \
	  exit 1; }
	@$(NDPI_ENV) pkg-config --atleast-version=5.0 libndpi || { \
	  echo "libndpi $$($(NDPI_ENV) pkg-config --modversion libndpi) found (prefix $$($(NDPI_ENV) pkg-config --variable=prefix libndpi)), but perch-collector requires nDPI >= 5.0."; \
	  echo "Build 5.0 into a prefix and point the build at it:"; \
	  echo "  scripts/build-ndpi.sh [prefix]                     # default prefix: \$$HOME/.local/ndpi5"; \
	  echo "  make build-ndpi NDPI_PREFIX=\$$HOME/.local/ndpi5     # likewise make test-ndpi"; \
	  exit 1; }
	@echo "libndpi $$($(NDPI_ENV) pkg-config --modversion libndpi) detected (prefix $$($(NDPI_ENV) pkg-config --variable=prefix libndpi))"

clean:
	rm -f $(BIN)

# Container image (nDPI build on Debian bookworm). Run it with
# --network host --cap-add NET_RAW --cap-add NET_ADMIN.
docker:
	docker build -t $(IMAGE) .
