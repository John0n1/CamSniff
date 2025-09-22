import re
import sys
import os
import json
import time
import subprocess
import shutil
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Optional

# Configure logging
logging.basicConfig(
    level=logging.WARNING,  # Only show warnings/errors by default
    format='[%(levelname)s %(asctime)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

def _find_cve_dir() -> Path:
    """Find CVE directory, preferring environment variable."""
    # Prefer env override if exported from shell
    env_dir = os.environ.get('CVE_CACHE_DIR')
    if env_dir:
        p = Path(env_dir)
        if p.is_dir():
            return p
    root = Path(__file__).resolve().parents[1]
    return root / 'data' / 'cves'

def _read_title_from_file(path: Path) -> Tuple[str, str]:
    """
    Read CVE ID and title from JSON file.
    
    Returns:
        Tuple of (CVE ID, title)
    """
    try:
        with path.open('r', encoding='utf-8', errors='ignore') as f:
            cve = json.load(f)
        containers = (cve or {}).get('containers', {})
        cna = containers.get('cna', {})
        title = cna.get('title') or ''
        return (path.stem, title)
    except Exception as e:
        logger.debug("Failed to read CVE file %s: %s", path, e)
        return (path.stem, '')

def _search_with_cli(term: str, base: Path, limit: int = 5) -> List[Path]:
    """Use command-line tools for fast text search."""
    cmds = []
    if shutil.which('rg'):
        cmds.append(['rg', '-l', '-i', '-m', str(limit), term, str(base)])
    # Fallback to grep
    if shutil.which('grep'):
        cmds.append(['grep', '-ril', '-m', str(limit), term, str(base)])
    
    for cmd in cmds:
        try:
            out = subprocess.check_output(
                cmd, 
                stderr=subprocess.DEVNULL, 
                timeout=1.5,
                text=True
            )
            files = [Path(p) for p in out.splitlines() if p and Path(p).exists()]
            if files:
                return files[:limit]
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError) as e:
            logger.debug("CLI search failed with %s: %s", cmd[0], e)
            continue
    return []

def _bounded_recent_scan(term: str, base: Path, limit: int = 5, seconds: float = 1.5) -> List[Path]:
    """Scan recent years only to keep search fast."""
    # Only scan recent years to keep it fast
    now = datetime.utcnow().year
    years = [str(y) for y in range(now, max(now - 5, 1999), -1)]
    start = time.monotonic()
    results: List[Path] = []
    
    for y in years:
        ydir = base / y
        if not ydir.is_dir():
            continue
            
        try:
            for p in ydir.rglob('CVE-*.json'):
                if time.monotonic() - start > seconds:
                    return results
                    
                try:
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
                except Exception as e:
                    logger.debug("Error processing file %s: %s", p, e)
                    continue
        except Exception as e:
            logger.debug("Error scanning year directory %s: %s", ydir, e)
            continue
            
    return results

def search_cves(search_term: str, limit: int = 5) -> List[Tuple[str, str]]:
    """
    Search for CVEs matching the term.
    
    Args:
        search_term: Term to search for
        limit: Maximum number of results
        
    Returns:
        List of (CVE ID, title) tuples
    """
    clean_term = re.sub(r'[^\w\s-]', '', search_term.lower()).strip()
    if not clean_term:
        return []
        
    try:
        base = _find_cve_dir()
        if not base.is_dir():
            logger.warning("CVE directory not found: %s", base)
            return []

        # Strategy: fast CLI search → bounded recent scan → minimal fallback
        paths: List[Path] = []

        # Try CLI tools first
        paths = _search_with_cli(clean_term, base, limit)
        
        # Fallback to bounded recent scan
        if not paths:
            paths = _bounded_recent_scan(clean_term, base, limit)
            
        # Last resort: check just a handful of files
        if not paths:
            count = 0
            for p in base.glob('**/CVE-*.json'):
                paths.append(p)
                count += 1
                if count >= 20:
                    break

        hits = []
        for p in paths[:limit]:
            cve_id, title = _read_title_from_file(p)
            text = f"{cve_id} {title}".lower()
            if clean_term in text:
                hits.append((cve_id, title))
            if len(hits) >= limit:
                break
                
        return hits[:limit]
        
    except Exception as e:
        logger.error("CVE search failed: %s", e)
        return []


def main() -> int:
    """Main entry point for CVE search."""
    if len(sys.argv) < 2:
        return 0
        
    search_term = sys.argv[1]
    results = search_cves(search_term)
    
    for cve_id, title in results:
        print(f"[CVE] {cve_id}: {title or 'No title available'}")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
