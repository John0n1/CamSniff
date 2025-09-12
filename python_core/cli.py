import asyncio
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import typer

app = typer.Typer(help="CamSniff Python core CLI")

DB_PATH = Path("output/results.sqlite")
LOGS_DIR = Path("output/logs")
LOGS_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

@dataclass
class Host:
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


def db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.execute("PRAGMA foreign_keys=ON")
    return con


@app.command()
def initdb():
    with db() as con:
        con.executescript(SCHEMA)
    typer.echo(f"Initialized DB at {DB_PATH}")


@app.command()
def probe_http(
    ip: Optional[str] = typer.Option(None, "--ip", "-i", help="Target IP address"),
    ip_arg: Optional[str] = typer.Argument(None, help="Target IP address (positional)"),
    port: int = typer.Option(80, "--port", "-p", help="Target port"),
    timeout: float = typer.Option(2.5, "--timeout", "-t", help="Request timeout seconds"),
):
    """Async HTTP HEAD/GET probe to find MJPEG/HLS endpoints (single host)."""
    import aiohttp

    target_ip = ip or ip_arg
    if not target_ip:
        raise typer.BadParameter("IP address is required (use --ip or positional)")

    async def run():
        found = []
        paths = [
            "/video",
            "/cam",
            "/stream",
            "/live",
            "/mjpeg",
            "/cgi-bin/mjpeg",
            "/axis-cgi/mjpg/video.cgi",
            "/cgi-bin/camera",
            "/video.cgi",
            "/snapshot.cgi",
            "/image.cgi",
            "/videostream.cgi",
            "/onvif/device_service",
            "/streaming/channels/1/httppreview",
            "/index.m3u8",
            "/live.m3u8",
        ]
        base = f"http://{target_ip}:{port}"
        conn = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=conn) as session:
            sem = asyncio.Semaphore(10)

            async def check(path: str):
                url = base + path
                async with sem:
                    try:
                        async with session.head(url, timeout=timeout) as r:
                            ct = r.headers.get("Content-Type", "")
                            if "multipart/x-mixed-replace" in ct or "image/jpeg" in ct or "video/" in ct or "application/vnd.apple.mpegurl" in ct:
                                found.append(url)
                                return
                    except Exception:
                        pass
                    try:
                        async with session.get(url, timeout=timeout) as r:
                            ct = r.headers.get("Content-Type", "")
                            if "multipart/x-mixed-replace" in ct or "image/jpeg" in ct or "video/" in ct or "application/vnd.apple.mpegurl" in ct:
                                found.append(url)
                    except Exception:
                        pass

            await asyncio.gather(*(check(p) for p in paths))

        if found:
            log_file = LOGS_DIR.joinpath("scan.jsonl")
            with log_file.open("a", encoding="utf-8") as fh:
                for u in found:
                    fh.write(json.dumps({
                        "ts": "",  # backend can fill or use client time
                        "level": "event",
                        "event": "http_stream_found",
                        "url": u,
                    }) + "\n")
            typer.echo("\n".join(found))

    asyncio.run(run())


if __name__ == "__main__":
    app()

def main():
    app()
