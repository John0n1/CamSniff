import re
import sys
import os
import json
import time
import subprocess
from datetime import datetime
from pathlib import Path

def _find_cve_dir() -> Path:
    # Prefer env override if exported from shell
    env_dir = os.environ.get('CVE_CACHE_DIR')
    if env_dir:
        p = Path(env_dir)
        if p.is_dir():
            return p
    root = Path(__file__).resolve().parents[1]
    return root / 'data' / 'cves'


def _read_title_from_file(path: Path) -> tuple[str, str]:
    try:
        with path.open('r', encoding='utf-8', errors='ignore') as f:
            cve = json.load(f)
        containers = (cve or {}).get('containers', {})
        cna = containers.get('cna', {})
        title = cna.get('title') or ''
        return (path.stem, title)
    except Exception:
        return (path.stem, '')


def _search_with_cli(term: str, base: Path, limit: int = 5) -> list[Path]:
    # Try ripgrep first
    cmds = []
    if shutil.which('rg'):
        cmds.append(['rg', '-l', '-i', '-m', str(limit), term, str(base)])
    # Fallback to grep
    if shutil.which('grep'):
        cmds.append(['grep', '-ril', '-m', str(limit), term, str(base)])
    for cmd in cmds:
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=1.5)
            files = [Path(p) for p in out.decode('utf-8', errors='ignore').splitlines() if p]
            if files:
                return files[:limit]
        except Exception:
            continue
    return []


def _bounded_recent_scan(term: str, base: Path, limit: int = 5, seconds: float = 1.5) -> list[Path]:
    # Only scan recent years to keep it fast
    now = datetime.utcnow().year
    years = [str(y) for y in range(now, max(now - 5, 1999), -1)]
    start = time.monotonic()
    results: list[Path] = []
    for y in years:
        ydir = base / y
        if not ydir.is_dir():
            continue
        for p in ydir.rglob('CVE-*.json'):
            try:
                if time.monotonic() - start > seconds:
                    return results
                # Quick filename check first
                if term in p.stem.lower():
                    results.append(p)
                else:
                    # Peek content quickly without full JSON load
                    with p.open('r', encoding='utf-8', errors='ignore') as f:
                        head = f.read(4096).lower()
                        if term in head:
                            results.append(p)
                if len(results) >= limit:
                    return results
            except Exception:
                continue
    return results


def main():
    if len(sys.argv) < 2:
        return 0
    search_term = sys.argv[1].lower()
    clean_term = re.sub(r'[^\w\s-]', '', search_term).strip()
    if not clean_term:
        return 0
    try:
        base = _find_cve_dir()
        if not base.is_dir():
            return 0

        # Strategy: fast CLI search → bounded recent scan → minimal fallback
        paths: list[Path] = []
        try:
            import shutil  # lazily import to avoid overhead when not needed
        except Exception:
            shutil = None  # type: ignore

        if 'shutil' in globals() and globals()['shutil']:
            paths = _search_with_cli(clean_term, base)
        if not paths:
            paths = _bounded_recent_scan(clean_term, base)
        if not paths:
            # Last resort: check just a handful of files under base to avoid long walks
            count = 0
            for p in base.glob('**/CVE-*.json'):
                paths.append(p)
                count += 1
                if count >= 20:
                    break

        hits = []
        for p in paths[:5]:
            cve_id, title = _read_title_from_file(p)
            text = f"{cve_id} {title}".lower()
            if clean_term in text:
                hits.append((cve_id, title))
            if len(hits) >= 5:
                break
        for cve_id, title in hits[:5]:
            print(f"[CVE] {cve_id}: {title or 'No title available'}")
    except Exception as e:
        print(f"[DEBUG] Quick CVE search failed: {e}", file=sys.stderr)
    return 0

if __name__ == '__main__':
    sys.exit(main())
