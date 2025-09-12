#!/usr/bin/make -f

DESTDIR ?= 
PREFIX ?= /usr
BINDIR = $(PREFIX)/bin
SHAREDIR = $(PREFIX)/share
DOCDIR = $(SHAREDIR)/doc/camsniff
APPSDIR = $(SHAREDIR)/applications
ICONSDIR = $(SHAREDIR)/icons/hicolor/256x256/apps
PIXMAPSDIR = $(SHAREDIR)/pixmaps
MANDIR = $(SHAREDIR)/man/man1
ETCDIR = /etc/camsniff

# Version information
VERSION := 1.0.3

# Source files
ROOT_SCRIPTS := camsniff.sh
CORE_SCRIPTS := core/env_setup.sh core/scan_analyze.sh core/setup.sh core/cleanup.sh core/install_deps.sh core/iot_enumerate.sh
SCRIPTS := $(ROOT_SCRIPTS) $(CORE_SCRIPTS)
SCRIPTS_PY := python_core/ai_analyze.py python_core/cve_quick_search.py
PY_CORE := python_core/cli.py python_core/web_backend.py python_core/__init__.py
TEST_SCRIPTS := tests/test_cve.sh tests/test_package_compliance.sh tests/test_rtsp_paths.sh tests/test_env_setup.sh tests/test_python_core.sh tests/test_rtsp_subst.sh
DOCS := README.md LICENSE
WEB := web/app.py core/webui.sh web/CamSniff.ico
EXTRA := core/doctor.sh requirements.txt

.PHONY: all build install uninstall clean test

all: build

build:
	@echo "Building CamSniff $(VERSION)..."
	# Create wrapper script that calls the main script from share directory
	@echo '#!/bin/bash' > camsniff
	@echo 'exec /usr/share/camsniff/camsniff.sh "$$@"' >> camsniff
	@chmod +x camsniff
	# Create capitalized wrapper for convenience and desktop Exec
	@echo '#!/bin/bash' > CamSniff
	@echo 'exec /usr/share/camsniff/camsniff.sh "$$@"' >> CamSniff
	@chmod +x CamSniff

install: build
	@echo "Installing CamSniff $(VERSION)..."
	# Create directories
	install -d $(DESTDIR)$(BINDIR)
	install -d $(DESTDIR)$(SHAREDIR)/camsniff
	install -d $(DESTDIR)$(SHAREDIR)/camsniff/web
	install -d $(DESTDIR)$(APPSDIR)
	install -d $(DESTDIR)$(ICONSDIR)
	install -d $(DESTDIR)$(PIXMAPSDIR)
	install -d $(DESTDIR)$(DOCDIR)
	install -d $(DESTDIR)$(MANDIR)
	install -d $(DESTDIR)$(ETCDIR)
	install -d $(DESTDIR)/var/lib/camsniff
	install -d $(DESTDIR)/var/log/camsniff
	
	# Install main wrapper script
	install -m 755 camsniff $(DESTDIR)$(BINDIR)/camsniff
	# Also install capitalized convenience executable
	install -m 755 CamSniff $(DESTDIR)$(BINDIR)/CamSniff
	
		# Install all scripts to share directory
		install -m 755 $(SCRIPTS) $(DESTDIR)$(SHAREDIR)/camsniff/
		install -d $(DESTDIR)$(SHAREDIR)/camsniff/scripts
		install -m 644 $(SCRIPTS_PY) $(DESTDIR)$(SHAREDIR)/camsniff/scripts/
		# Install python core package files (for local runs)
		install -d $(DESTDIR)$(SHAREDIR)/camsniff/python_core
		install -m 644 $(PY_CORE) $(DESTDIR)$(SHAREDIR)/camsniff/python_core/
		# Install web files (preserve structure for app.py)
		install -m 755 web/app.py $(DESTDIR)$(SHAREDIR)/camsniff/web/
		install -m 644 web/CamSniff.ico $(DESTDIR)$(SHAREDIR)/camsniff/web/
		install -m 755 core/webui.sh $(DESTDIR)$(SHAREDIR)/camsniff/
		# Install extra helper files
		install -m 755 core/doctor.sh $(DESTDIR)$(SHAREDIR)/camsniff/
		install -m 644 requirements.txt $(DESTDIR)$(SHAREDIR)/camsniff/

	# Desktop entry for launcher
	printf "[Desktop Entry]\n" > $(DESTDIR)$(APPSDIR)/camsniff.desktop
	printf "Type=Application\n" >> $(DESTDIR)$(APPSDIR)/camsniff.desktop
	printf "Name=CamSniff\n" >> $(DESTDIR)$(APPSDIR)/camsniff.desktop
	printf "Comment=Camera Reconnaissance Tool\n" >> $(DESTDIR)$(APPSDIR)/camsniff.desktop
	printf "Exec=CamSniff\n" >> $(DESTDIR)$(APPSDIR)/camsniff.desktop
	printf "Icon=camsniff\n" >> $(DESTDIR)$(APPSDIR)/camsniff.desktop
	printf "Categories=Network;Security;\n" >> $(DESTDIR)$(APPSDIR)/camsniff.desktop
	printf "Keywords=camera;ip;network;security;scanner;rtsp;onvif;\n" >> $(DESTDIR)$(APPSDIR)/camsniff.desktop
	printf "Terminal=true\n" >> $(DESTDIR)$(APPSDIR)/camsniff.desktop

	# Install icon: prefer PNG in hicolor; always install ICO to pixmaps as fallback
	@tmpicons=$$(mktemp -d); \
	if command -v icotool >/dev/null 2>&1; then \
		icotool -x -o "$$tmpicons" web/CamSniff.ico >/dev/null 2>&1 || true; \
		png=$$(ls -1 "$$tmpicons"/*256*.png 2>/dev/null | head -n1 || true); \
		if [ -n "$$png" ]; then \
			install -m 644 "$$png" $(DESTDIR)$(ICONSDIR)/camsniff.png; \
		fi; \
	elif command -v convert >/dev/null 2>&1; then \
		convert web/CamSniff.ico -resize 256x256 "$$tmpicons/camsniff.png" >/dev/null 2>&1 || true; \
		if [ -f "$$tmpicons/camsniff.png" ]; then \
			install -m 644 "$$tmpicons/camsniff.png" $(DESTDIR)$(ICONSDIR)/; \
		fi; \
	fi; \
	install -m 644 web/CamSniff.ico $(DESTDIR)$(PIXMAPSDIR)/camsniff.ico; \
	rm -rf "$$tmpicons" 2>/dev/null || true
	
	# Install documentation
	install -m 644 $(DOCS) $(DESTDIR)$(DOCDIR)/
	
	# Install man page if it exists (and provide CamSniff.1 symlink)
	@if [ -f camsniff.1 ]; then \
		install -m 644 camsniff.1 $(DESTDIR)$(MANDIR)/; \
		ln -sf camsniff.1 $(DESTDIR)$(MANDIR)/CamSniff.1; \
	fi || true
	
	# Create default configuration if it doesn't exist
	@if [ ! -f "$(DESTDIR)$(ETCDIR)/camcfg.json" ]; then \
		echo "Creating default configuration..."; \
		printf '{\n' > "$(DESTDIR)$(ETCDIR)/camcfg.json"; \
		printf '  "sleep_seconds": 45,\n' >> "$(DESTDIR)$(ETCDIR)/camcfg.json"; \
		printf '  "nmap_ports": "1-65535",\n' >> "$(DESTDIR)$(ETCDIR)/camcfg.json"; \
		printf '  "masscan_rate": 20000,\n' >> "$(DESTDIR)$(ETCDIR)/camcfg.json"; \
		printf '  "hydra_rate": 16,\n' >> "$(DESTDIR)$(ETCDIR)/camcfg.json"; \
		printf '  "max_streams": 4,\n' >> "$(DESTDIR)$(ETCDIR)/camcfg.json"; \
		printf '  "cve_github_repo": "https://api.github.com/repos/CVEProject/cvelistV5/contents/cves",\n' >> "$(DESTDIR)$(ETCDIR)/camcfg.json"; \
		printf '  "cve_cache_dir": "/tmp/cve_cache",\n' >> "$(DESTDIR)$(ETCDIR)/camcfg.json"; \
		printf '  "cve_current_year": "2025",\n' >> "$(DESTDIR)$(ETCDIR)/camcfg.json"; \
		printf '  "dynamic_rtsp_url": "https://github.com/John0n1/CamSniff/blob/4d682edf7b4512562d24ccdf863332952637094d/data/rtsp_paths.csv",\n' >> "$(DESTDIR)$(ETCDIR)/camcfg.json"; \
		printf '  "dirb_wordlist": "/usr/share/wordlists/dirb/common.txt",\n' >> "$(DESTDIR)$(ETCDIR)/camcfg.json"; \
		printf '  "password_wordlist": "data/passwords.txt",\n' >> "$(DESTDIR)$(ETCDIR)/camcfg.json"; \
		printf '  "username_wordlist": "data/usernames.txt",\n' >> "$(DESTDIR)$(ETCDIR)/camcfg.json"; \
		printf '  "snmp_communities": ["public", "private", "camera", "admin", "cam", "cisco", "default", "guest", "test"],\n' >> "$(DESTDIR)$(ETCDIR)/camcfg.json"; \
		printf '  "medusa_threads": 8,\n' >> "$(DESTDIR)$(ETCDIR)/camcfg.json"; \
		printf '  "enable_iot_enumeration": true,\n' >> "$(DESTDIR)$(ETCDIR)/camcfg.json"; \
		printf '  "enable_pcap_capture": true,\n' >> "$(DESTDIR)$(ETCDIR)/camcfg.json"; \
		printf '  "enable_wifi_scan": true,\n' >> "$(DESTDIR)$(ETCDIR)/camcfg.json"; \
		printf '  "enable_ble_scan": true,\n' >> "$(DESTDIR)$(ETCDIR)/camcfg.json"; \
		printf '  "enable_zigbee_zwave_scan": true,\n' >> "$(DESTDIR)$(ETCDIR)/camcfg.json"; \
		printf '  "stealth_mode": true,\n' >> "$(DESTDIR)$(ETCDIR)/camcfg.json"; \
		printf '  "enable_nmap_vuln": true\n' >> "$(DESTDIR)$(ETCDIR)/camcfg.json"; \
		printf '}\n' >> "$(DESTDIR)$(ETCDIR)/camcfg.json"; \
		chmod 644 "$(DESTDIR)$(ETCDIR)/camcfg.json"; \
	fi
	
	# Create default config directory
	@echo "System directories created for configuration and logging"

uninstall:
	@echo "Uninstalling CamSniff..."
	rm -f $(DESTDIR)$(BINDIR)/camsniff
	rm -rf $(DESTDIR)$(SHAREDIR)/camsniff
	rm -rf $(DESTDIR)$(DOCDIR)
	rm -f $(DESTDIR)$(MANDIR)/camsniff.1
	# Note: We don't remove /etc/camsniff, /var/lib/camsniff, or /var/log/camsniff 
	# to preserve user configurations and logs

clean:
	@echo "Cleaning build artifacts..."
	rm -f camsniff
	rm -f *.deb
	rm -rf build-deb/
	rm -f .deps_installed
	rm -f camcfg.json

test:
	@echo "Running tests..."
	# Syntax check all shell scripts
	bash -n $(SCRIPTS) $(TEST_SCRIPTS)
	chmod +x $(TEST_SCRIPTS) 2>/dev/null || true
	cd tests && ./test_env_setup.sh
	cd tests && ./test_rtsp_paths.sh
	cd tests && ./test_cve.sh
	cd tests && ./test_python_core.sh
	cd tests && ./test_rtsp_subst.sh
	@echo "All tests passed!"

.PHONY: format lint hooks
format:
	@echo "Formatting shell and python..."
	@command -v shfmt >/dev/null 2>&1 && shfmt -w -i 2 -ci *.sh core/*.sh tests/*.sh || true
	@command -v black >/dev/null 2>&1 && black . || true

lint:
	@echo "Linting shell and python..."
	@command -v shellcheck >/dev/null 2>&1 && shellcheck -x *.sh core/*.sh tests/*.sh || true
	@command -v ruff >/dev/null 2>&1 && ruff check . || true

hooks:
	@echo "Installing pre-commit hooks..."
	@pre-commit install -t pre-commit -t commit-msg || true

.PHONY: core web-backend
core:
	@echo "Running Python core CLI (initdb)..."
	@python3 python_core/cli.py initdb

web-backend:
	@echo "Starting FastAPI backend on :8089..."
	@python3 python_core/web_backend.py

.PHONY: doctor
doctor:
	@chmod +x core/doctor.sh 2>/dev/null || true
	@./core/doctor.sh

# Development targets
dev-install: build
	sudo $(MAKE) install PREFIX=/usr/local

dev-uninstall:
	sudo $(MAKE) uninstall PREFIX=/usr/local

# Package building
deb: clean
	@bash -eu -c 'TMP=$$(mktemp -d /tmp/camsniff-pkg-XXXXXX); \
		rsync -a --delete --exclude ".git" "$(CURDIR)/" "$$TMP/"; \
		cd "$$TMP"; dpkg-buildpackage -us -uc -b; \
		cp -f ../camsniff_* "$(CURDIR)/" || true; echo "Built packages staged back to $(CURDIR)"'

.PHONY: help
help:
	@echo "CamSniff $(VERSION) -  Camera Reconnaissance Tool"
	@echo ""
	@echo "Available targets:"
	@echo "  all         - Build the project (default)"
	@echo "  build       - Build the wrapper script"
	@echo "  install     - Install to system (use DESTDIR for staging)"
	@echo "  uninstall   - Remove from system"
	@echo "  clean       - Clean build artifacts"
	@echo "  test        - Run tests"
	@echo "  deb         - Build Debian package"
	@echo "  dev-install - Install to /usr/local (for development)"
	@echo ""
	@echo "Web UI:"
	@echo "  ./core/webui.sh  - Run lightweight Flask dashboard on :8088"
	@echo "  help        - Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  DESTDIR     - Destination directory for staging (default: empty)"
	@echo "  PREFIX      - Installation prefix (default: /usr)"