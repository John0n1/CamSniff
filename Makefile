SHELL := /bin/bash
ROOT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
MODE ?= nuke
RUN_FLAGS ?=

SH_SOURCES := $(shell find scripts data -type f -name '*.sh' -print) bin/camsniff
ifndef BUILD_SOURCE
ifneq (,$(findstring /mnt/,$(ROOT_DIR)))
BUILD_SOURCE := 0
else
BUILD_SOURCE := 1
endif
endif

DPKG_BUILD_FLAGS := -us -uc
ifeq ($(BUILD_SOURCE),0)
DPKG_BUILD_FLAGS += -b
endif
DPKG_BUILD := dpkg-buildpackage $(DPKG_BUILD_FLAGS)

.PHONY: help build clean run lint dev shellcheck install-deps distclean build-coap

help:
	@echo "Available targets:"
	@echo "  make build        # dpkg-buildpackage -us -uc (adds -b on /mnt; set BUILD_SOURCE=1 for source)"
	@echo "  make clean        # remove build artefacts and temporary state"
	@echo "  make run MODE=war # invoke sudo ./scripts/camsniff.sh --mode war"
	@echo "  make lint         # shellcheck + bash -n across project scripts"
	@echo "  make dev          # lint plus dpkg-buildpackage --dry-run sanity"
	@echo "  make install-deps # bootstrap runtime dependencies via apt/yum/pacman"
	@echo "  make distclean    # clean plus drop virtualenv and build outputs"

build:
	$(DPKG_BUILD)

clean:
	dh_clean
	@if [ -d $(ROOT_DIR)/dev/results ]; then \
		find $(ROOT_DIR)/dev/results -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true; \
	fi
	rm -f $(ROOT_DIR)/*.deb $(ROOT_DIR)/*.buildinfo $(ROOT_DIR)/*.changes $(ROOT_DIR)/*.dsc
	rm -rf $(ROOT_DIR)/debian/camsniff
	rm -rf $(ROOT_DIR)/debian/files
	rm -rf $(ROOT_DIR)/debian/*.debhelper.log
	rm -rf $(ROOT_DIR)/debian/*.substvars
	rm -rf $(ROOT_DIR)/debian/*.debhelper
distclean: clean
	rm -rf $(ROOT_DIR)/venv

run:
	sudo $(ROOT_DIR)/scripts/camsniff.sh --mode $(MODE) $(RUN_FLAGS)

install-deps:
	sudo -E $(ROOT_DIR)/scripts/setup/deps-install.sh

build-coap:
	sudo -E $(ROOT_DIR)/scripts/setup/build-coap.sh

lint: shellcheck
	@echo "Running bash syntax checks"
	@for file in $(SH_SOURCES); do \
		bash -n $$file || exit 1; \
	done

shellcheck:
	@echo "Running shellcheck"
	sudo apt-get install -y shellcheck || true
	@command -v shellcheck >/dev/null 2>&1 || { echo "shellcheck not available"; exit 1; }
	shellcheck -x -P scripts -P data -P . $(SH_SOURCES)

dev: lint
	$(DPKG_BUILD)
