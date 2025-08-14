# CamSniff - Camera Reconnaissance Tool

CamSniff is a bash-based network security reconnaissance tool designed for identifying and analyzing IP cameras and network devices. It consists of 7 shell scripts and follows Debian packaging standards with FHS compliance.

**ALWAYS follow these instructions completely before attempting any other approaches.** Only fallback to additional search and context gathering if the information in these instructions is incomplete or found to be in error.

## Working Effectively

### Bootstrap and Build - EXACT TIMEOUTS
- Bootstrap: `make clean && make build`
  - Takes <1 second total. NEVER CANCEL. Use timeout of 60+ seconds.
  - Creates wrapper script `camsniff` that calls `/usr/share/camsniff/camsniff.sh`
- Test: `make test` 
  - Takes <1 second. NEVER CANCEL. Use timeout of 30+ seconds.
  - Runs syntax check on all 7 shell scripts: camsniff.sh, env_setup.sh, scan_analyze.sh, setup.sh, cleanup.sh, install_deps.sh, test_cve.sh
- Package compliance: `./test_package_compliance.sh`
  - Takes ~0.05 seconds. NEVER CANCEL. Use timeout of 30+ seconds.
  - Tests help functionality, syntax, required files, Debian packaging, FHS compliance

### Installation and Development
- Development install: `sudo make dev-install`
  - Installs to `/usr/local` for testing
  - Creates FHS-compliant directory structure
- System install: `sudo make install`
  - Installs to `/usr` (production)
- Uninstall: `sudo make dev-uninstall` or `sudo make uninstall`
- Clean: `make clean`
  - Removes build artifacts, .deb files, config files

### Running CamSniff
- **CRITICAL**: CamSniff MUST be run with sudo privileges for network scanning and dependency installation
- Help: `./camsniff.sh --help` (works without sudo)
- Interactive mode: `sudo ./camsniff.sh`
- Automation mode: `sudo ./camsniff.sh -a`
- Target specific subnet: `sudo ./camsniff.sh -t 192.168.1.0/24`
- Quiet mode: `sudo ./camsniff.sh -q -y`

### Dependency Management - CRITICAL TIMING
- **AUTOMATIC**: Dependencies are auto-installed on first run via `install_deps.sh`
- **TIMING**: Initial dependency installation takes 10-30 minutes depending on network speed. NEVER CANCEL. Use timeout of 45+ minutes.
- **REQUIREMENTS**: Must run on Debian/Ubuntu-based system with apt-get available
- **PACKAGES**: Core packages auto-installed: fping, masscan, nmap, hydra, ffmpeg, python3-opencv, tcpdump, tshark, arp-scan, gobuster, medusa, onesixtyone, and 15+ others
- **STAMP FILE**: `.deps_installed` file prevents reinstallation on subsequent runs - delete this file to force reinstallation
- **RETRY LOGIC**: Built-in retry mechanism with 5 attempts and 5-second delays for network operations

## Validation - ALWAYS DO THIS

### Build Validation - MANDATORY SEQUENCE
Always validate your changes by running this exact sequence with proper timeouts:
1. `make clean` - Clean build artifacts (<1 second)
2. `make build` - Build wrapper script (<1 second) 
3. `make test` - Syntax check all scripts (<1 second, timeout 30+ seconds)
4. `./test_package_compliance.sh` - Full compliance test (~0.05 seconds, timeout 30+ seconds)
5. `./camsniff.sh --help` - Verify help functionality works

### User Scenario Testing - AFTER CHANGES
**ALWAYS test complete user workflow after making ANY changes:**
1. Run `make clean && make build && make test`
2. Test help: `./camsniff.sh --help` 
3. Verify all 7 scripts have executable permissions: `ls -la *.sh`
4. Test syntax individually: `bash -n camsniff.sh` (repeat for other scripts)
5. **LIMITATION**: Cannot test full scanning functionality without sudo and network cameras

### Critical Limitations - CANNOT FULLY VALIDATE
- **NETWORK SCANNING**: Actual camera discovery requires root and network with IP cameras
- **DEPENDENCY INSTALLATION**: Full installation requires sudo and takes 10-30 minutes (timeout 45+ minutes)
- **STREAM ANALYSIS**: Camera stream analysis requires active RTSP/HTTP camera feeds  
- **CVE CHECKING**: Vulnerability analysis requires network access to GitHub CVE databases
- **BRUTE FORCING**: Password testing requires target cameras with authentication

## Repository Structure

### Key Scripts (by lines of code)
- `scan_analyze.sh` - 748 lines - Core scanning and analysis functionality
- `install_deps.sh` - 201 lines - Dependency installation with retry logic
- `camsniff.sh` - 190 lines - Main entry point with CLI argument parsing
- `env_setup.sh` - 139 lines - Environment configuration
- `test_package_compliance.sh` - 97 lines - Integration test suite
- `setup.sh` - 32 lines - Basic setup functions
- `cleanup.sh` - 20 lines - Cleanup utilities
- `test_cve.sh` - 25 lines - CVE testing functionality

### Build Files
- `Makefile` - Build system with targets: build, test, install, clean, deb, help
- `debian/` - Debian packaging files (control, rules, changelog, copyright)
- `camsniff.1` - Man page
- `PACKAGING.md` - Package development documentation

### Configuration
- `camcfg.json` - Generated runtime configuration (excluded from git)
- RTSP paths fetched from: `https://raw.githubusercontent.com/John0n1/CamSniff/main/data/rtsp_paths.csv`

## Common Tasks - EXACT COMMANDS

### Makefile Targets - VALIDATED COMMANDS
```bash
make help       # Show available targets (<1 second)
make clean      # Clean build artifacts (<1 second)  
make build      # Build wrapper script (<1 second)
make test       # Run syntax checks on all 7 scripts (<1 second, timeout 30+ seconds)
make install    # Install to system (requires sudo)
make deb        # Build Debian package (requires Debian/Ubuntu)
```

### Command Line Usage - VERIFIED EXAMPLES
```bash
# Show help (works without sudo)
./camsniff.sh --help

# Basic interactive scanning (REQUIRES sudo, 10-30 min first run for deps)
sudo ./camsniff.sh

# Automated scanning with specific target (REQUIRES sudo)
sudo ./camsniff.sh -a -t 192.168.1.0/24

# Quiet mode with yes to all prompts (REQUIRES sudo)
sudo ./camsniff.sh -y -q

# All available options
sudo ./camsniff.sh -a -t 10.0.0.0/24 -y -q
```

### Development Workflow - TESTED SEQUENCE
```bash
# Complete development cycle
make clean && make build && make test && ./test_package_compliance.sh

# Check individual script syntax
bash -n camsniff.sh
bash -n scan_analyze.sh

# Verify all scripts executable  
chmod +x *.sh && ls -la *.sh

# Test help without running full application
./camsniff.sh --help
```

### File Structure After Installation
```
/usr/bin/camsniff                    # Main executable wrapper
/usr/share/camsniff/*.sh             # All 7 shell scripts
/usr/share/doc/camsniff/             # Documentation
/usr/share/man/man1/camsniff.1       # Man page
/etc/camsniff/                       # Configuration directory
/var/lib/camsniff/                   # State files
/var/log/camsniff/                   # Log files
```

## Development Guidelines

### Making Changes
- **SYNTAX**: Always run `make test` after script changes
- **COMPATIBILITY**: Maintain Debian/Ubuntu compatibility
- **PERMISSIONS**: Preserve executable bits on .sh files: `chmod +x *.sh`
- **FHS COMPLIANCE**: Follow Filesystem Hierarchy Standard for any new files

### Testing Changes
1. Clean build: `make clean && make build`
2. Syntax test: `make test`
3. Compliance test: `./test_package_compliance.sh`
4. Help functionality: `./camsniff.sh --help`
5. Manual testing requires sudo and appropriate network environment

### Security Considerations
- Tool requires root privileges for network scanning
- Auto-installs many system packages via apt-get
- Performs active network reconnaissance
- Handles network credentials and camera streams
- Optional fuzzing tools only installed in development mode

## Troubleshooting - VERIFIED SOLUTIONS

### Common Issues - EXACT FIXES
- **"Must be run as root"**: Use `sudo ./camsniff.sh` for all scanning operations
- **Missing dependencies**: Run `sudo ./camsniff.sh` to auto-install (takes 10-30 minutes, timeout 45+ minutes)
- **Permission denied on scripts**: Run `chmod +x *.sh` to make all scripts executable
- **Network issues during setup**: Requires stable internet for dependency installation and CVE data fetching
- **Build fails**: Run `make clean` then `make build` to reset build state

### Build Issues - TESTED SOLUTIONS  
- **Syntax errors**: Run `bash -n <scriptname.sh>` to check individual scripts
- **Missing core files error**: Verify all 7 core .sh scripts present: `ls -la camsniff.sh env_setup.sh scan_analyze.sh setup.sh cleanup.sh install_deps.sh test_cve.sh`
- **Makefile errors**: Run `make help` to verify Makefile is working
- **Debian package build**: Use `make deb` only on Debian/Ubuntu systems with debhelper installed

### Performance Issues - TIMING EXPECTATIONS
- **Build seems slow**: Normal build takes <1 second - if longer, check disk space
- **Test seems hung**: Normal test takes <1 second - if longer than 30 seconds, restart
- **Dependency install hung**: Normal install takes 10-30 minutes - NEVER CANCEL before 45 minutes
- **First run slow**: First `sudo ./camsniff.sh` run takes 10-30 minutes for dependency installation

### What You Cannot Test Without Root Access
These features require sudo privileges and cannot be validated in restricted environments:
- Network scanning operations (nmap, masscan, fping require raw sockets)
- Camera stream analysis (ffmpeg, rtsp connections require network access)
- Dependency installation (apt-get requires root privileges)
- System directory creation (/var/lib, /var/log, /etc access)
- Network interface manipulation for reconnaissance