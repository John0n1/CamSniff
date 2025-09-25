import asyncio
import json
import sqlite3
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List
import typer
from datetime import datetime, timezone

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s %(asctime)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

app = typer.Typer(help="CamSniff Python core CLI")

import os

OUTPUT_BASE = Path(os.environ.get("CAMSNIFF_OUTPUT", "output"))
DB_PATH = Path(os.environ.get("CAMSNIFF_DB", OUTPUT_BASE / "results.sqlite"))
LOGS_DIR = OUTPUT_BASE / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

@dataclass
class Host:
    """Host data structure."""
    ip: str

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS hosts(
  ip TEXT PRIMARY KEY,
  first_seen TEXT,
  last_seen TEXT
);
CREATE TABLE IF NOT EXISTS services(
  ip TEXT,
  port INTEGER,
  proto TEXT,
  banner TEXT,
  PRIMARY KEY(ip, port, proto)
);
CREATE TABLE IF NOT EXISTS streams(
  url TEXT PRIMARY KEY,
  ip TEXT,
  kind TEXT,
  first_seen TEXT,
  last_seen TEXT
);
"""

def get_timestamp() -> str:
    """Get current ISO timestamp."""
    return datetime.now(timezone.utc).isoformat()

def db() -> sqlite3.Connection:
    """Get database connection with proper configuration."""
    try:
        con = sqlite3.connect(DB_PATH)
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("PRAGMA journal_mode=WAL")
        return con
    except sqlite3.Error as e:
        logger.error("Database connection failed: %s", e)
        raise

@app.command()
def initdb():
    """Initialize the database with required schema."""
    try:
        with db() as con:
            con.executescript(SCHEMA)
        typer.echo(f"Initialized DB at {DB_PATH}")
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error("Failed to initialize database: %s", e)
        raise typer.Exit(1)

def validate_ip(ip_addr: str) -> bool:
    """Basic IP address validation."""
    import re
    pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return bool(re.match(pattern, ip_addr))


@app.command()
def probe_http(
    ip: Optional[str] = typer.Option(None, "--ip", "-i", help="Target IP address"),
    ip_arg: Optional[str] = typer.Argument(None, help="Target IP address (positional)"),
    port: int = typer.Option(80, "--port", "-p", help="Target port"),
    timeout: float = typer.Option(2.5, "--timeout", "-t", help="Request timeout seconds"),
):
    """Async HTTP HEAD/GET probe to find MJPEG/HLS endpoints (single host)."""
    target_ip = ip or ip_arg
    if not target_ip:
        raise typer.BadParameter("IP address is required (use --ip or positional)")
    
    if not validate_ip(target_ip):
        raise typer.BadParameter(f"Invalid IP address: {target_ip}")
    
    if not 1 <= port <= 65535:
        raise typer.BadParameter(f"Invalid port: {port}")
    
    if timeout <= 0:
        raise typer.BadParameter(f"Timeout must be positive: {timeout}")

    async def run():
        """Main async probe function."""
        try:
            import aiohttp
        except ImportError:
            logger.error("aiohttp not available - install with: pip install aiohttp")
            raise typer.Exit(1)
            
        found: List[str] = []
        paths = [
            "/video", "/cam", "/stream", "/live", "/mjpeg", "/cgi-bin/mjpeg",
            "/axis-cgi/mjpg/video.cgi", "/cgi-bin/camera", "/video.cgi", 
            "/snapshot.cgi", "/image.cgi", "/videostream.cgi",
            "/onvif/device_service", "/streaming/channels/1/httppreview",
            "/index.m3u8", "/live.m3u8", "/playlist.m3u8"
        ]
        
        base = f"http://{target_ip}:{port}"
        logger.info("Probing %s with %d paths", base, len(paths))
        
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=10)
            timeout_obj = aiohttp.ClientTimeout(total=timeout)
            
            async with aiohttp.ClientSession(
                connector=connector, 
                timeout=timeout_obj
            ) as session:
                sem = asyncio.Semaphore(10)

                async def check(path: str) -> None:
                    """Check individual path for camera streams."""
                    url = base + path
                    async with sem:
                        # Try HEAD first (faster)
                        try:
                            async with session.head(url) as r:
                                ct = r.headers.get("Content-Type", "")
                                if any(x in ct for x in [
                                    "multipart/x-mixed-replace", "image/jpeg", 
                                    "video/", "application/vnd.apple.mpegurl"
                                ]):
                                    found.append(url)
                                    logger.info("Found stream: %s (Content-Type: %s)", url, ct)
                                    return
                        except Exception as e:
                            logger.debug("HEAD failed for %s: %s", url, e)
                        
                        # Fallback to GET
                        try:
                            async with session.get(url) as r:
                                ct = r.headers.get("Content-Type", "")
                                if any(x in ct for x in [
                                    "multipart/x-mixed-replace", "image/jpeg", 
                                    "video/", "application/vnd.apple.mpegurl"
                                ]):
                                    found.append(url)
                                    logger.info("Found stream: %s (Content-Type: %s)", url, ct)
                        except Exception as e:
                            logger.debug("GET failed for %s: %s", url, e)

                await asyncio.gather(*(check(p) for p in paths), return_exceptions=True)

        except Exception as e:
            logger.error("Probe failed: %s", e)
            raise typer.Exit(1)

        # Log findings
        if found:
            log_file = LOGS_DIR / "scan.jsonl"
            try:
                with log_file.open("a", encoding="utf-8") as fh:
                    for url in found:
                        fh.write(json.dumps({
                            "ts": get_timestamp(),
                            "level": "event",
                            "event": "http_stream_found",
                            "url": url,
                            "ip": target_ip,
                            "port": port
                        }) + "\n")
                logger.info("Found %d streams, logged to %s", len(found), log_file)
            except Exception as e:
                logger.error("Failed to write log: %s", e)
            
            typer.echo("\n".join(found))
        else:
            logger.info("No streams found on %s:%d", target_ip, port)

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        logger.info("Probe interrupted by user")
        raise typer.Exit(130)
    except Exception as e:
        logger.error("Probe failed: %s", e)
        raise typer.Exit(1)

def main() -> None:
    """Main entry point."""
    app()

if __name__ == "__main__":
    main()
