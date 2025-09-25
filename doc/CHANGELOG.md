# Changelog

All notable changes to CamSniff will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.4] - 2025-09-25

### Features
- Centralized version management via `VERSION` file
- Restructured installation layout under `/usr/lib/camsniff/src`
- Added `camsniff-web` desktop launcher and wrapper script
- Introduced `Makefile` with developer convenience targets
- Enhanced `doctor` and `self-test` diagnostics (JSON support in `doctor`)
- Packaging cleanup: minimized hard `Depends`, clarified runtime tool philosophy

## [1.0.3] - 2025-01-08

### Features
- Basic camera reconnaissance and scanning
- RTSP, HTTP, and CoAP protocol support
- Web interface for camera feeds
- Basic credential testing
- CVE checking functionality

### Known Issues
- Limited error handling
- Basic input validation
- Manual dependency management
- Limited brand-specific detection

---

For more information about this release, see the [full documentation](README.md).