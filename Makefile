#!/usr/bin/make -f

DESTDIR ?= 
PREFIX ?= /usr
BINDIR = $(PREFIX)/bin
SHAREDIR = $(PREFIX)/share
DOCDIR = $(SHAREDIR)/doc/camsniff
MANDIR = $(SHAREDIR)/man/man1
ETCDIR = /etc/camsniff

# Version information
VERSION := 1.0.1

# Source files
SCRIPTS := camsniff.sh env_setup.sh scan_analyze.sh setup.sh cleanup.sh install_deps.sh
TEST_SCRIPTS := test_cve.sh test_package_compliance.sh
DOCS := README.md LICENSE

.PHONY: all build install uninstall clean test

all: build

build:
	@echo "Building CamSniff $(VERSION)..."
	# Create wrapper script that calls the main script from share directory
	@echo '#!/bin/bash' > camsniff
	@echo 'exec /usr/share/camsniff/camsniff.sh "$$@"' >> camsniff
	@chmod +x camsniff

install: build
	@echo "Installing CamSniff $(VERSION)..."
	# Create directories
	install -d $(DESTDIR)$(BINDIR)
	install -d $(DESTDIR)$(SHAREDIR)/camsniff
	install -d $(DESTDIR)$(DOCDIR)
	install -d $(DESTDIR)$(MANDIR)
	install -d $(DESTDIR)$(ETCDIR)
	install -d $(DESTDIR)/var/lib/camsniff
	install -d $(DESTDIR)/var/log/camsniff
	
	# Install main wrapper script
	install -m 755 camsniff $(DESTDIR)$(BINDIR)/camsniff
	
	# Install all scripts to share directory
	install -m 755 $(SCRIPTS) $(DESTDIR)$(SHAREDIR)/camsniff/
	
	# Install documentation
	install -m 644 $(DOCS) $(DESTDIR)$(DOCDIR)/
	
	# Install man page if it exists
	test -f camsniff.1 && install -m 644 camsniff.1 $(DESTDIR)$(MANDIR)/ || true
	
	# Create default configuration if it doesn't exist
	@if [ ! -f "$(DESTDIR)$(ETCDIR)/camcfg.json" ]; then \
		echo "Creating default configuration..."; \
		echo '{\
		  "sleep_seconds": 45,\
		  "nmap_ports": "1-65535",\
		  "masscan_rate": 20000,\
		  "hydra_rate": 16,\
		  "max_streams": 4,\
		  "cve_github_repo": "https://api.github.com/repos/CVEProject/cvelistV5/contents/cves",\
		  "cve_cache_dir": "/tmp/cve_cache",\
		  "cve_current_year": "2025",\
		  "dynamic_rtsp_url": "https://github.com/CamioCam/rtsp/blob/master/cameras/paths.csv",\
		  "dirb_wordlist": "/usr/share/wordlists/dirb/common.txt",\
		  "snmp_communities": ["public", "private", "camera", "admin"],\
		  "medusa_threads": 8\
		}' > "$(DESTDIR)$(ETCDIR)/camcfg.json"; \
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
	@echo "All tests passed!"

# Development targets
dev-install: build
	sudo $(MAKE) install PREFIX=/usr/local

dev-uninstall:
	sudo $(MAKE) uninstall PREFIX=/usr/local

# Package building
deb: clean
	dpkg-buildpackage -us -uc -b

.PHONY: help
help:
	@echo "CamSniff $(VERSION) - Enhanced Camera Reconnaissance Tool"
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
	@echo "  help        - Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  DESTDIR     - Destination directory for staging (default: empty)"
	@echo "  PREFIX      - Installation prefix (default: /usr)"