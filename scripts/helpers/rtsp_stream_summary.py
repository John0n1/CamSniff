#!/usr/bin/env python3
#
# https://github.com/John0n1/CamSniff
#
# Copyright (c) 2025 John Hauger Mitander
# License: MIT License https://opensource.org/license/MIT

"""Summarise ffprobe output for CamSniff."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Summarise ffprobe JSON output"
    )
    parser.add_argument(
        "--input", required=True, help="Path to ffprobe JSON output"
    )
    parser.add_argument(
        "--url", required=True, help="RTSP URL that was probed"
    )
    return parser.parse_args()


def load_probe(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        return {}


def build_summary(data: dict, url: str) -> dict:
    streams = data.get("streams") or []
    codec = ""
    width = None
    height = None
    fps = ""

    for stream in streams:
        codec = stream.get("codec_name") or codec
        width = stream.get("width") or width
        height = stream.get("height") or height
        fps = stream.get("avg_frame_rate") or fps
        if codec and width and height:
            break

    resolution = None
    if width and height:
        resolution = f"{width}x{height}"

    return {
        "url": url,
        "codec": codec or "",
        "resolution": resolution,
        "frame_rate": fps or "",
    }


def main() -> int:
    args = parse_args()
    payload = build_summary(load_probe(Path(args.input)), args.url)
    print(json.dumps(payload))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
