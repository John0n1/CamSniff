# CamSniff Package Development

This document provides information for developers and package maintainers.

## Building from Source

### Prerequisites
- Debian/Ubuntu-based system
- debhelper (>= 10)
- Standard build tools

### Build Commands

```bash
# Clean previous builds
make clean

# Run tests
make test

# Build package
make build

# Install locally for testing
sudo make install

# Create Debian package
dpkg-buildpackage -us -uc -b
```

## Package Structure

CamSniff follows the Filesystem Hierarchy Standard (FHS):

- `/usr/bin/camsniff` - Main executable
- `/usr/share/camsniff/` - Program files
- `/usr/share/doc/camsniff/` - Documentation
- `/usr/share/man/man1/camsniff.1` - Manual page
- `/etc/camsniff/` - Configuration directory
- `/var/lib/camsniff/` - State files
- `/var/log/camsniff/` - Log files

## Testing Package Compliance

Run the compliance test suite:

```bash
./test_package_compliance.sh
```

This validates:
- Script syntax
- Help functionality
- Required files presence
- Debian packaging structure
- FHS compliance
- Installation process

## Security Considerations

- Optional fuzzing tools are only installed in development mode
- No hardcoded credentials or API keys
- No unauthorized network connections
- Graceful degradation when optional tools are unavailable
- Proper permission handling for system directories

## Kali Linux Package Submission

This package is designed to meet Kali Linux package submission requirements:

- ✅ Open Source License (MIT)
- ✅ Security-focused tool
- ✅ Clean build process
- ✅ FHS compliance
- ✅ Debian packaging standards
- ✅ Minimal dependencies
- ✅ No privilege escalation issues
- ✅ Comprehensive documentation

For submission to Kali Linux packages repository, follow the [official contribution guide](https://www.kali.org/docs/community/submitting-packages/).