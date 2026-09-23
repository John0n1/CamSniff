#!/usr/bin/env python3
"""Fetch bounded upstream camera intelligence into an inactive, reviewable catalogue.

Nothing in the generated catalogue is executed or added to live probe dictionaries.
"""

import argparse
import base64
import hashlib
import json
import re
import urllib.request
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "data" / "upstream" / "candidates.json"
SOURCES = (
    ("cameradar", "Ullaakut/cameradar", "internal/dict/assets/routes", "MIT"),
    ("nuclei-dahua-panel", "projectdiscovery/nuclei-templates", "http/exposed-panels/dahua-web-panel.yaml", "MIT"),
)
MAX_BYTES = 65536
MAX_ROUTES = 512
ROUTE = re.compile(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]{0,159}\Z")
SECRET = re.compile(r"pass(?:word|wd)?|pwd|user(?:name)?|token|secret|auth|pin|\{\{|\}\}|\?{3,}", re.I)


def github_json(url, token=""):
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "CamSniff-intel-sync/1", **({"Authorization": "Bearer " + token} if token else {})},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        if response.status != 200:
            raise ValueError("unexpected GitHub status")
        payload = response.read(MAX_BYTES * 3 + 1)
    if len(payload) > MAX_BYTES * 3:
        raise ValueError("GitHub response too large")
    return json.loads(payload)


def fetch_source(repo, path, token=""):
    # Repositories and paths are compile-time allowlisted; redirect URLs are never
    # taken from the response. Ref is resolved once and then pinned for this run.
    base = "https://api.github.com/repos/" + repo
    revision = github_json(base + "/commits/" + ("master" if repo.endswith("cameradar") else "main"), token)["sha"]
    if not re.fullmatch(r"[a-f0-9]{40}", revision):
        raise ValueError("invalid commit SHA")
    data = github_json(base + "/contents/" + path + "?ref=" + revision, token)
    if data.get("encoding") != "base64" or data.get("type") != "file":
        raise ValueError("unexpected GitHub content type")
    content = base64.b64decode(data["content"], validate=False)
    if len(content) > MAX_BYTES:
        raise ValueError("source file too large")
    blob = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
    if data.get("sha") != blob:
        raise ValueError("Git blob hash mismatch")
    return revision, content.decode("utf-8")


def provenance(name, repo, path, revision, license_name):
    if not re.fullmatch(r"[a-f0-9]{40}", revision):
        raise ValueError("invalid pinned revision")
    return {"source": name, "repository": repo, "path": path, "commit": revision,
            "license": license_name, "url": f"https://github.com/{repo}/blob/{revision}/{path}"}


def routes_from_text(content, source):
    lines = content.splitlines()
    if len(lines) > MAX_ROUTES:
        raise ValueError("route source exceeds review budget")
    records, rejected = [], 0
    for line in lines:
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        value = "/" + value.lstrip("/")
        if not ROUTE.fullmatch(value) or SECRET.search(value) or "@" in value or "%" in value:
            rejected += 1
            continue
        records.append({"kind": "rtsp_route", "value": value, "source": source})
    return records, rejected


def nuclei_metadata(content, source):
    # Parse data only; never retain or execute template requests, matchers,
    # payloads, variables, or code. Explicitly restrict to a detection template.
    doc = yaml.safe_load(content)
    if not isinstance(doc, dict) or not isinstance(doc.get("info"), dict):
        raise ValueError("invalid Nuclei template")
    info = doc["info"]
    if info.get("severity") != "info" or "detect" not in str(info.get("tags", "")).split(","):
        raise ValueError("template is not an informational detection")
    identifier = doc.get("id")
    if not isinstance(identifier, str) or not re.fullmatch(r"[a-z0-9-]{1,80}", identifier):
        raise ValueError("invalid template id")
    return {"kind": "detection_reference", "id": identifier, "name": str(info.get("name", ""))[:120],
            "vendor": str(info.get("metadata", {}).get("vendor", ""))[:80], "source": source}


def build(inputs):
    entries, rejected, sources = [], 0, {}
    for name, repo, path, license_name in SOURCES:
        revision, content = inputs[name]
        if len(content.encode()) > MAX_BYTES:
            raise ValueError("source file too large")
        sources[name] = provenance(name, repo, path, revision, license_name)
        if name == "cameradar":
            routes, discarded = routes_from_text(content, name)
            entries.extend(routes)
            rejected += discarded
        else:
            entries.append(nuclei_metadata(content, name))
    unique = {json.dumps(record, sort_keys=True): record for record in entries}
    return {"schema_version": 1, "status": "review_required", "active": False,
            "sources": sources, "rejected_unsafe_routes": rejected,
            "records": sorted(unique.values(), key=lambda item: (item["kind"], item.get("value", item.get("id", ""))))}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-dir", type=Path, help="offline fixture directory (each source has .txt and .sha files)")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--check", action="store_true", help="verify output matches source inputs")
    args = parser.parse_args(argv)
    if args.fixture_dir:
        inputs = {name: ((args.fixture_dir / (name + ".sha")).read_text().strip(),
                         (args.fixture_dir / (name + ".txt")).read_text()) for name, *_ in SOURCES}
    else:
        import os
        inputs = {name: fetch_source(repo, path, os.environ.get("GH_TOKEN", "")) for name, repo, path, _ in SOURCES}
    output = json.dumps(build(inputs), indent=2, ensure_ascii=False) + "\n"
    if args.check:
        if not args.output.is_file() or args.output.read_text() != output:
            parser.error("catalogue differs from normalized sources")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output)
    print(f"Upstream catalogue: {len(json.loads(output)['records'])} review-only records")


if __name__ == "__main__":
    main()
