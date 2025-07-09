#!/usr/bin/env bash
# Integration test for CamSniff package compliance
set -euo pipefail

echo "=== CamSniff Package Compliance Test ==="

# Test 1: Help functionality
echo "Testing help functionality..."
if ./camsniff.sh --help >/dev/null 2>&1; then
    echo "✓ Help functionality works"
else
    echo "✗ Help functionality failed"
    exit 1
fi

# Test 2: Syntax check all scripts
echo "Testing script syntax..."
if bash -n *.sh; then
    echo "✓ All scripts have valid syntax"
else
    echo "✗ Script syntax errors found"
    exit 1
fi

# Test 3: Check for required files
echo "Testing required files..."
for file in LICENSE README.md Makefile camsniff.1; do
    if [[ -f "$file" ]]; then
        echo "✓ $file exists"
    else
        echo "✗ $file missing"
        exit 1
    fi
done

# Test 4: Check Debian packaging files
echo "Testing Debian packaging files..."
for file in debian/control debian/rules debian/changelog debian/copyright; do
    if [[ -f "$file" ]]; then
        echo "✓ $file exists"
    else
        echo "✗ $file missing"
        exit 1
    fi
done

# Test 5: Test Makefile targets
echo "Testing Makefile targets..."
if make help >/dev/null 2>&1; then
    echo "✓ Makefile help target works"
else
    echo "✗ Makefile help target failed"
    exit 1
fi

if make test >/dev/null 2>&1; then
    echo "✓ Makefile test target works"
else
    echo "✗ Makefile test target failed"
    exit 1
fi

# Test 6: Test installation structure
echo "Testing installation structure..."
TMPDIR=$(mktemp -d)
if make install DESTDIR="$TMPDIR" >/dev/null 2>&1; then
    echo "✓ Installation works"
    
    # Check FHS compliance
    for dir in usr/bin usr/share/camsniff usr/share/doc/camsniff usr/share/man/man1 etc/camsniff var/lib/camsniff var/log/camsniff; do
        if [[ -d "$TMPDIR/$dir" ]]; then
            echo "✓ FHS directory $dir created"
        else
            echo "✗ FHS directory $dir missing"
            rm -rf "$TMPDIR"
            exit 1
        fi
    done
    
    # Check main executable
    if [[ -f "$TMPDIR/usr/bin/camsniff" ]]; then
        echo "✓ Main executable installed"
    else
        echo "✗ Main executable not found"
        rm -rf "$TMPDIR"
        exit 1
    fi
    
    rm -rf "$TMPDIR"
else
    echo "✗ Installation failed"
    rm -rf "$TMPDIR"
    exit 1
fi

echo ""
echo "=== All Tests Passed! ==="
echo "CamSniff is ready for Kali Linux package submission"