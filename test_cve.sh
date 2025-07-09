#!/usr/bin/env bash

# Test script for the new CVE functionality
cd "$(dirname "$0")"

echo "Testing CVE GitHub integration..."

# Source the required scripts
source env_setup.sh
source scan_analyze.sh

echo "Testing CVE search for 'hikvision'..."
cve_check "hikvision"

echo ""
echo "Testing CVE search for 'dahua'..."
cve_check "dahua"

echo ""
echo "Testing CVE quick search for 'axis'..."
cve_quick_search "axis"

echo ""
echo "CVE cache directory contents:"
ls -la "$CVE_CACHE_DIR" 2>/dev/null || echo "Cache directory not found"
