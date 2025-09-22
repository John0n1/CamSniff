# Changelog

All notable changes to CamSniff will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.4] - 2025-01-08

###  Enhancements

#### Credential Bypass System
- **NEW**: Authentication bypass techniques for camera discovery
- **NEW**: Brand-specific vulnerability exploitation (Hikvision, Dahua, Axis, Vivotek, Foscam, D-Link, TP-Link, Sony)
- **NEW**: URL encoding bypass attempts for authentication
- **NEW**: Cookie-based session bypass detection
- **NEW**: Common CGI vulnerability exploitation
- **NEW**: Default credential testing with 50+ combinations

#### Camera Detection & Fingerprinting
- **NEW**: Camera detection with brand-specific vulnerability checks
- **NEW**: CVE-specific exploit detection (CVE-2017-7921, CVE-2021-36260, CVE-2018-10658, etc.)
- **NEW**: Generic camera detection for unknown brands
- **NEW**: Camera endpoint discovery (15+ new paths)
- **NEW**: Automatic stream detection and validation

###  Security Improvements

#### Input Validation & Sanitization
- **SECURITY**:  input validation for network addresses
- **SECURITY**: Subnet format validation with range checking
- **SECURITY**: Input sanitization to prevent command injection
- **SECURITY**: Parameter validation across all modules

#### Error Handling
- **SECURITY**: Improved error handling with detailed logging
- **SECURITY**: Secure cleanup of temporary files
- **SECURITY**: Graceful failure handling for missing dependencies
- **SECURITY**: Protected against path traversal attacks

#### Dependency Security
- **SECURITY**: Pinned dependency versions in CI/CD
- **SECURITY**: Automated vulnerability scanning with Trivy
- **SECURITY**: Secret detection with TruffleHog
- **SECURITY**: Python security scanning with Bandit and Safety

### Code Quality & Architecture

#### Python Core Improvements
- **ENHANCED**: Complete rewrite of AI analysis module with proper logging and type hints
- **ENHANCED**: CVE search module with robust error handling and caching
- **ENHANCED**: CLI module with input validation and Async handling
- **ENHANCED**: Type hints added across all Python modules
- **ENHANCED**: Proper logging framework replacing print() statements

#### Shell Script
- **ENHANCED**: error handling with call stack tracking
- **ENHANCED**: logging system with multiple log levels
- **ENHANCED**: Structured JSON logging for machine processing
- **ENHANCED**: Input validation and sanitization functions
- **ENHANCED**: CVE checking with fallback mechanisms

#### Configuration Management
- **ENHANCED**: Robust configuration loading with error recovery
- **ENHANCED**: default configuration values
- **ENHANCED**: Improved wordlist management (usernames and passwords)
- **ENHANCED**: Feature flag system for enabling/disabling capabilities

### Development & Testing

#### CI/CD Pipeline Overhaul
- **NEW**: Multi-stage CI/CD pipeline with security scanning
- **NEW**: Automated code quality checks (ShellCheck, Black, Ruff, MyPy)
- **NEW**: Security vulnerability scanning (Trivy, Bandit, Safety)
- **NEW**: Secret detection and SAST analysis
- **NEW**: Comprehensive test coverage including integration tests
- **NEW**: Build and package validation

#### Testing Infrastructure
- **ENHANCED**: Test suite with better coverage
- **ENHANCED**: Syntax validation for all scripts
- **ENHANCED**: Configuration testing and validation
- **ENHANCED**: Python module testing with dependency checks

#### Documentation
- **ENHANCED**: README updates with detailed usage instructions
- **ENHANCED**: Function documentation with parameter descriptions
- **ENHANCED**: Contributing guidelines for developers
- **ENHANCED**: Security considerations and best practices

### Configuration & Deployment

#### Configuration Options
- **NEW**: Feature flags for fine-grained control
- **NEW**: Logging level configuration (DEBUG, INFO, WARN, ERROR)
- **NEW**: Credential wordlists (50+ usernames, 60+ passwords)
- **NEW**: Brand-specific default credentials
- **NEW**: Configurable timeout and rate limiting

#### Installation & Packaging
- **ENHANCED**: Makefile with targets
- **ENHANCED**: dependency management and validation
- **ENHANCED**: Package structure and file organization
- **ENHANCED**: Proper file permissions and security defaults

### Scanning & Detection

#### Network Scanning Improvements
- **ENHANCED**: RTSP scanning with better error handling
- **ENHANCED**: HTTP scanning with multiple endpoint detection
- **ENHANCED**: SNMP enumeration with community string validation
- **ENHANCED**: CoAP scanning with fuzzing capabilities
- **ENHANCED**: UPnP/SSDP discovery

#### Reporting & Analytics
- **ENHANCED**: Structured JSON reporting for all events
- **ENHANCED**: Camera information tracking
- **ENHANCED**: Device fingerprinting and classification
- **ENHANCED**: Vulnerability assessment reporting
- **ENHANCED**: Timeline-based event tracking

### Bug Fixes

#### Stability Improvements
- **FIXED**: ShellCheck warnings for unused variables
- **FIXED**: Proper variable scoping and export handling
- **FIXED**: Memory leaks in background process management
- **FIXED**: Race conditions in concurrent scanning
- **FIXED**: File descriptor leaks in network operations

#### Compatibility
- **FIXED**: Python 3.10+ compatibility with proper type hints
- **FIXED**: Cross-platform path handling
- **FIXED**: Improved error messages for missing dependencies
- **FIXED**: Better handling of non-interactive environments

### Performance

#### Scanning Optimization
- **OPTIMIZED**: Parallel scanning with configurable concurrency
- **OPTIMIZED**: Efficient credential testing algorithms
- **OPTIMIZED**: Reduced network timeouts for faster scanning
- **OPTIMIZED**: Memory usage optimization for large scans
- **OPTIMIZED**: Background process management

#### Resource Management
- **OPTIMIZED**: Temporary file cleanup and management
- **OPTIMIZED**: Database connection pooling
- **OPTIMIZED**: Logging performance improvements
- **OPTIMIZED**: Cache management for CVE data

### Breaking Changes

- **BREAKING**: Updated minimum Python version to 3.10
- **BREAKING**: Changed log format to structured JSON
- **BREAKING**: Updated configuration file schema
- **BREAKING**: Modified CLI parameter validation

### Migration Guide

For users upgrading from version 1.0.3:

1. **Configuration**: Review and update your `camcfg.json` file with new options
2. **Dependencies**: Ensure Python 3.10+ is installed
3. **Logging**: Update any log parsing scripts for new JSON format
4. **CLI**: Verify command-line arguments due to enhanced validation

### Version Information

- **Release Date**: Sep 22, 2025
- **Compatibility**: Linux (Ubuntu 20.04+, Debian 11+, Kali Linux)
- **Python Version**: 3.10+
- **Dependencies**: See requirements.txt for complete list

---

## [1.0.3] - Previous Release

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