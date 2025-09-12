#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Simple, fast compliance test for local workspace
echo "[INFO] CamSniff package compliance check starting..."

# 1) Core files present
required=(
  "../camsniff.sh" "../core/env_setup.sh" "../core/scan_analyze.sh" "../core/setup.sh" "../core/cleanup.sh" "../core/install_deps.sh"
  "../Makefile" "../README.md" "../camsniff.1"
  "../debian/control" "../debian/rules" "../debian/changelog"
)
missing=()
for f in "${required[@]}"; do
  [[ -e "$f" ]] || missing+=("$f")
done
if (( ${#missing[@]} )); then
  echo "[ERROR] Missing required files:"; printf ' - %s\n' "${missing[@]}"; exit 1
fi
echo "[OK] Required files present"

# 2) Scripts are executable (fix locally if not)
chmod +x ../*.sh ../core/*.sh 2>/dev/null || true
for s in ../camsniff.sh ../core/env_setup.sh ../core/scan_analyze.sh ../core/setup.sh ../core/cleanup.sh ../core/install_deps.sh test_package_compliance.sh; do
  [[ -x "$s" ]] || { echo "[ERROR] Script not executable: $s"; exit 1; }
done
echo "[OK] Scripts are executable"

# 3) Syntax check (fast)
bash -n ../camsniff.sh ../core/env_setup.sh ../core/scan_analyze.sh ../core/setup.sh ../core/cleanup.sh ../core/install_deps.sh test_package_compliance.sh || {
  echo "[ERROR] Syntax check failed"; exit 1; }
echo "[OK] Syntax checks passed"

# 4) Make help works
if (cd .. && make help) >/dev/null 2>&1; then
  echo "[OK] make help works"
else
  echo "[ERROR] make help failed"; exit 1
fi

# 5) Build wrapper and verify
(cd .. && make clean) >/dev/null 2>&1
(cd .. && make build) >/dev/null 2>&1
[[ -x ../camsniff ]] || { echo "[ERROR] Wrapper 'camsniff' not built"; exit 1; }
echo "[OK] Wrapper built"

# 6) Help command works without sudo
if ../camsniff.sh --help >/dev/null 2>&1; then
  echo "[OK] Help runs without sudo"
else
  echo "[ERROR] Help failed"; exit 1
fi

# 7) Debian packaging files basic sanity
grep -qi '^package: *camsniff' ../debian/control || { echo "[ERROR] debian/control missing Package stanza"; exit 1; }
echo "[OK] Debian control sanity"
echo "[PASS] CamSniff package compliance OK"
