# Contributing to CamSniff

Thank you for your interest in contributing to CamSniff! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Building and Testing](#building-and-testing)
- [Code Standards](#code-standards)
- [Pull Request Process](#pull-request-process)
- [Issue Guidelines](#issue-guidelines)
- [Good First Issues](#good-first-issues)

## Getting Started

### Prerequisites

Before contributing, ensure you have the following installed:

- **Operating System**: Linux (Ubuntu/Debian recommended)
- **Bash**: Version 4.0 or later
- **Python**: Version 3.6 or later
- **Git**: For version control
- **sudo access**: Required for dependency installation

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:

```bash
git clone https://github.com/your-username/CamSniff.git
cd CamSniff
```

3. Add the upstream repository:

```bash
git remote add upstream https://github.com/John0n1/CamSniff.git
```

## Development Environment

### Installation

1. **Install dependencies** (requires sudo for first run):

```bash
sudo ./camsniff.sh --help  # This triggers dependency installation
```

2. **Install development tools**:

```bash
# Install linting and formatting tools
sudo apt-get install shellcheck shfmt
pip install black ruff pre-commit

# Install pre-commit hooks
make hooks
```

3. **Verify installation**:

```bash
make doctor  # Run diagnostic check
```

### Project Structure

```
CamSniff/
├── camsniff.sh           # Main entry point
├── core/                 # Core shell scripts
│   ├── env_setup.sh     # Environment configuration
│   ├── scan_analyze.sh  # Scanning and analysis
│   ├── setup.sh         # Initial setup
│   ├── cleanup.sh       # Cleanup utilities
│   ├── install_deps.sh  # Dependency management
│   └── iot_enumerate.sh # IoT device enumeration
├── python_core/         # Python modules
├── tests/               # Test suite
├── data/                # Data files (wordlists, CVE data)
├── web/                 # Web interface
└── .github/workflows/   # CI/CD configuration
```

## Building and Testing

### Building

```bash
# Build the project
make build

# Install locally for testing
make dev-install
```

### Running Tests

```bash
# Run all tests
make test

# Run specific test
cd tests && ./test_env_setup.sh

# Test syntax only
bash -n camsniff.sh core/*.sh tests/*.sh
```

### Linting and Formatting

```bash
# Run linting
make lint

# Auto-format code
make format

# Check with pre-commit hooks
pre-commit run --all-files
```

## Code Standards

### Shell Script Standards

All shell scripts must follow these standards:

1. **Use strict error handling**:
```bash
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
```

2. **Quote variables**:
```bash
# Good
echo "$variable"
command "$arg1" "$arg2"

# Bad
echo $variable
command $arg1 $arg2
```

3. **Use local variables in functions**:
```bash
function example() {
  local var="value"
  local file_path
  file_path="$(dirname "$1")"
}
```

4. **Separate declaration and assignment**:
```bash
# Good
local result
result="$(command_that_might_fail)"

# Avoid
local result="$(command_that_might_fail)"
```

5. **Use shellcheck directives when needed**:
```bash
# shellcheck disable=SC2034
VARIABLE_USED_IN_SOURCED_FILE="value"
```

### Python Standards

- Follow PEP 8 style guidelines
- Use type hints where appropriate
- Use Black for formatting
- Use Ruff for linting

### Testing Standards

- All new functionality must include tests
- Tests should be placed in the `tests/` directory
- Test files should be named `test_*.sh`
- Tests must pass on clean Ubuntu/Debian systems

## Pull Request Process

### Before Submitting

1. **Create a branch**:
```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-number
```

2. **Make your changes** following the code standards

3. **Test your changes**:
```bash
make test
make lint
```

4. **Commit your changes**:
```bash
git add .
git commit -m "Clear description of your changes"
```

### Submitting the Pull Request

1. **Push to your fork**:
```bash
git push origin your-branch-name
```

2. **Create a Pull Request** on GitHub with:
   - Clear title describing the change
   - Detailed description of what was changed and why
   - Reference to any related issues (e.g., "Fixes #123")
   - Screenshots for UI changes (if applicable)

3. **Ensure CI passes** - All automated checks must pass

### Code Review Process

- Maintainers will review your PR
- Address any requested changes
- Once approved, your PR will be merged

## Issue Guidelines

### Reporting Bugs

When reporting bugs, please include:

- **Environment**: OS version, shell version, Python version
- **Steps to reproduce**: Clear step-by-step instructions
- **Expected behavior**: What should have happened
- **Actual behavior**: What actually happened
- **Logs**: Relevant log output from `output/*/logs/`
- **Configuration**: Your `camcfg.json` (remove sensitive info)

### Suggesting Features

For feature requests:

- **Use case**: Describe the problem you're trying to solve
- **Proposed solution**: Your suggested approach
- **Alternatives**: Other solutions you've considered
- **Additional context**: Any other relevant information

## Good First Issues

Looking for a way to contribute? Check out issues labeled with:

- `good first issue` - Suitable for newcomers
- `help wanted` - Community contributions welcome
- `documentation` - Improve docs and examples
- `bug` - Fix existing issues
- `enhancement` - Add new features

### Easy Contribution Ideas

1. **Documentation improvements**:
   - Fix typos or unclear instructions
   - Add examples to existing documentation
   - Improve code comments

2. **Testing enhancements**:
   - Add test cases for edge cases
   - Improve test coverage
   - Add integration tests

3. **Code quality**:
   - Fix shellcheck warnings
   - Improve error messages
   - Add input validation

4. **Feature additions**:
   - Add support for new camera protocols
   - Improve output formatting
   - Add new scanning techniques

### Development Tips

- **Start small**: Begin with documentation or small bug fixes
- **Ask questions**: Use GitHub Discussions or issues for help
- **Follow patterns**: Look at existing code for style examples
- **Test thoroughly**: Ensure your changes work on clean systems
- **Be patient**: Code review may take time, especially for larger changes

## Community

- **GitHub Discussions**: Ask questions and share ideas
- **Issues**: Report bugs and request features
- **Pull Requests**: Contribute code improvements

## Getting Help

If you need help:

1. Check existing documentation and issues
2. Search GitHub Discussions
3. Create a new issue with the `question` label
4. Join the community discussions

---

**Thank you for contributing to CamSniff!** 

Your contributions help make network security testing more accessible and effective for everyone.