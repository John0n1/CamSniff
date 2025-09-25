# CamSniff Makefile
# High-level developer / packager convenience targets
# Safe defaults: never require root unless target explicitly needs it.

# Variables (override on command line: make run ARGS="-a -t 10.0.0.0/24")
VERSION:=$(shell cat VERSION 2>/dev/null || echo dev)
# Derive upstream version (strip any Debian revision like -1)
UPSTREAM_VERSION:=$(shell echo $(VERSION) | cut -d- -f1)
PYTHON?=python3
PIP?=pip3
VENV_DIR?=src/scripts/.camvenv
REQ_FILE?=requirements.txt
RUN_SCRIPT?=src/camsniff.sh
WEB_SCRIPT?=src/scripts/webui.sh
DEB_BUILD_DIR?=debian
# Allow passing extra args to camsniff
ARGS?=
SHELL:=/bin/bash

# Color helpers
C_GREEN=\033[32m
C_YELLOW=\033[33m
C_RED=\033[31m
C_RESET=\033[0m

.PHONY: help venv deps install-deps lint lint-shell lint-python format format-check self-test doctor run web deb clean distclean version print-% env

help:
	@echo "CamSniff Make Targets"
	@echo "--------------------------------"
	@echo "make help            - This help"
	@echo "make version         - Show current version"
	@echo "make venv            - Create/refresh Python virtualenv (if missing)"
	@echo "make deps            - Install Python deps into venv/system"
	@echo "make install-deps    - Run full system dependency bootstrap (root)"
	@echo "make lint            - Run all linters (shell + python)"
	@echo "make lint-shell      - ShellCheck all bash scripts"
	@echo "make lint-python     - Ruff + Black (check)"
	@echo "make format          - Auto-format Python via Black"
	@echo "make format-check    - Dry-run formatting check"
	@echo "make self-test       - Run JSON self-test diagnostic"
	@echo "make doctor          - Run doctor diagnostics"
	@echo "make run ARGS='...'  - Launch camsniff.sh with optional args"
	@echo "make web             - Launch Web UI (webui.sh)"
	@echo "make deb             - Build Debian package (dpkg-buildpackage)"
	@echo "make clean           - Remove temporary build artifacts"
	@echo "make distclean       - Clean + remove venv & output results"
	@echo "make env             - Print key environment paths"

version:
	@echo "CamSniff version $(VERSION)"

print-%:
	@echo '$*=$($*)'

env:
	@echo "VERSION=$(VERSION)"
	@echo "PYTHON=$(PYTHON)"
	@echo "VENV_DIR=$(VENV_DIR)"
	@echo "REQ_FILE=$(REQ_FILE)"
	@echo "RUN_SCRIPT=$(RUN_SCRIPT)"

# Create virtualenv if not present
venv:
	@if [ ! -d "$(VENV_DIR)" ]; then \
		echo -e "$(C_GREEN)[+] Creating virtualenv $(VENV_DIR)$(C_RESET)"; \
		$(PYTHON) -m venv $(VENV_DIR) || echo -e "$(C_YELLOW)[!] Failed to create venv; will use system python$(C_RESET)"; \
	else \
		echo -e "$(C_GREEN)[+] venv exists$(C_RESET)"; \
	fi

# Install Python requirements
deps: venv
	@if [ -d "$(VENV_DIR)" ] && [ -f "$(VENV_DIR)/bin/activate" ]; then \
		echo -e "$(C_GREEN)[+] Using venv for pip installs$(C_RESET)"; \
		source $(VENV_DIR)/bin/activate; pip install -U pip >/dev/null; \
		if [ -f "$(REQ_FILE)" ]; then pip install -r $(REQ_FILE); else echo "(no requirements.txt)"; fi; \
	else \
		echo -e "$(C_YELLOW)[!] No venv; installing to user site$(C_RESET)"; \
		if [ -f "$(REQ_FILE)" ]; then $(PIP) install --user -r $(REQ_FILE); fi; \
	fi

install-deps:
	@if [ "$$(id -u)" -ne 0 ]; then echo "Requires root (sudo)"; exit 1; fi
	@bash src/scripts/install_deps.sh

# Linting
lint: lint-shell lint-python

lint-shell:
	@command -v shellcheck >/dev/null 2>&1 || { echo "shellcheck not installed"; exit 0; }
	@echo -e "$(C_GREEN)[+] ShellCheck scripts$(C_RESET)"; \
	find src -type f -name '*.sh' -print0 | xargs -0 -r shellcheck -x || true

lint-python:
	@command -v ruff >/dev/null 2>&1 || { echo "ruff not installed (pip install ruff)"; exit 0; }
	@echo -e "$(C_GREEN)[+] Ruff lint$(C_RESET)"; ruff check src || true
	@command -v black >/dev/null 2>&1 || { echo "black not installed (pip install black)"; exit 0; }
	@echo -e "$(C_GREEN)[+] Black check$(C_RESET)"; black --check src || true

format:
	@command -v black >/dev/null 2>&1 || { echo "black not installed"; exit 1; }
	@black src

format-check:
	@command -v black >/dev/null 2>&1 || { echo "black not installed"; exit 1; }
	@black --check src

self-test:
	@bash src/scripts/self_test.sh | jq '.' || bash src/scripts/self_test.sh

doctor:
	@DOCTOR_JSON=1 bash src/scripts/doctor.sh --json || bash src/scripts/doctor.sh || true

run:
	@if [ ! -x "$(RUN_SCRIPT)" ]; then echo "Missing $(RUN_SCRIPT)"; exit 1; fi
	@echo -e "$(C_GREEN)[+] Launching CamSniff$(C_RESET)"; \
	bash $(RUN_SCRIPT) $(ARGS)

web:
	@if [ ! -x "$(WEB_SCRIPT)" ]; then echo "Missing $(WEB_SCRIPT)"; exit 1; fi
	@echo -e "$(C_GREEN)[+] Launching Web UI$(C_RESET)"; \
	bash $(WEB_SCRIPT) $(ARGS)

# Build Debian package (no signing by default)
deb:
	@if [ ! -f debian/control ]; then echo "Missing debian/ metadata"; exit 1; fi
	@echo -e "$(C_GREEN)[+] Building Debian package$(C_RESET)"; \
	format_file=debian/source/format; \
	if [ -f $$format_file ] && grep -q '3.0 (quilt)' $$format_file; then \
	  echo "[i] Source format quilt detected (upstream=$(UPSTREAM_VERSION) full=$(VERSION))"; \
	  echo "[i] Recreating orig tarball camsniff_$(UPSTREAM_VERSION).orig.tar.gz"; \
	  rm -f ../camsniff_$(UPSTREAM_VERSION).orig.tar.* 2>/dev/null || true; \
	  tar -czf ../camsniff_$(UPSTREAM_VERSION).orig.tar.gz --exclude-vcs --transform 's,^,camsniff-$(UPSTREAM_VERSION)/,' .; \
	fi; \
	dpkg-buildpackage -us -uc -rfakeroot || echo -e "$(C_RED)[!] dpkg-buildpackage failed$(C_RESET)"

clean:
	@echo -e "$(C_GREEN)[+] Cleaning build artifacts$(C_RESET)"; \
	rm -f *.build *.changes *.deb *.dsc *.tar.* camcfg.json paused.json || true; \
	rm -rf debian/.debhelper debian/files debian/camsniff/ src/.deps_installed src/.camvenv/ || true

# Distclean removes venv and output results
# (Be careful not to remove user data outside repo)
distclean: clean
	@echo -e "$(C_RED)[!] Removing venv & output directories$(C_RESET)"; \
	rm -rf $(VENV_DIR) src/output/results_* src/output/* || true
	rm camcfg.json paused.json || true	

