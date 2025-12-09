## Orientation
- CamSniff is a Bash-driven reconnaissance pipeline for IP cameras; the orchestrator lives in `scripts/camsniff.sh` and must run as root because it invokes packet captures and low-level scans.
- Startup calls `scripts/setup/deps-install.sh` with a spinner to ensure Nmap/Masscan/TShark/ffmpeg, builds libcoap if missing, and resolves per-mode knobs from `scripts/core/mode-config.sh`.
- Modes in `scripts/core/mode-config.sh` feed port profiles (`scripts/core/port-profiles.sh`), RTSP threads, credential caps, curl/ffmpeg timeouts, and optional NSE extras; adjust both files together to keep UI labels accurate.

## Workflow
- Use `sudo scripts/camsniff.sh --mode medium --yes` for an end-to-end scan; the script derives the target CIDR from the default route and stages artifacts under `dev/results/<UTC>/`.
- Pre-flight tooling with `sudo scripts/setup/deps-install.sh` or `sudo make install-deps`; follow with `make lint` (shellcheck + bash -n) and `make dev` for a dpkg dry run when iterating.
- The Makefile’s `make run MODE=war RUN_FLAGS='--extra ivre'` wraps the launcher; IVRE sync only stays enabled if MongoDB and the Python `ivre` package are available.
- After scans, inspect `dev/results/<stamp>/discovery.json` and `credentials.json` with `scripts/tools/analyze.sh`; logs live in `dev/results/<stamp>/logs/`, thumbnails under `thumbnails/`.

## Data & Extension Points
- Vendor fingerprints, default credentials, CVEs, and HTTP/RTSP templates live in `data/catalog/paths.csv`; edits immediately change enrichment and credential probing.
- `scripts/core/port-profiles.sh` maps logical profiles to Nmap/Masscan specs and RTSP thread hints—update labels if you add or rename a profile so banners stay truthful.
- Credential attempts pull from `data/dictionaries/usernames.txt`, `data/dictionaries/passwords.txt`, and fallback HTTP routes in `data/dictionaries/http-paths.txt`; keep comment lines starting with `hash` so the parsers skip them.
- Protocol heuristics (`detect_onvif`, `detect_hls`, `detect_webrtc`, `detect_srt_from_ports`) live in `scripts/camsniff.sh`; use `record_protocol_hit` and `track_port` helpers to keep discovery JSON consistent.

## Results Contract
- `discovery.json` stores a `hosts[]` array with `sources`, `ports`, `observed_paths`, `rtsp_bruteforce`, and `additional_protocols`; preserve these keys if you extend the schema because `scripts/ivre-sync.py` consumes them.
- `credentials.json` is a flat list written by `scripts/credential-probe.sh`; each item records `ip`, `username`, `password`, `success`, `method`, and optional media artifacts used by thumbnail generation.
- IVRE integration calls `scripts/ivre-sync.py` after discovery when `--extra ivre` is set; it expects the virtualenv at `venv/` and logs to `dev/results/<stamp>/logs/ivre-sync.log`.
- GeoIP databases under `share/geoip/` seed IVRE lookups; keep the `.version` sidecar files in sync when updating datasets.

## Conventions
- Bash code consistently uses `set -euo pipefail`, associative arrays, and helper functions close to their call sites; prefer pure functions and guard external commands with `command -v` checks.
- UI rendering comes from `scripts/ui/banner.sh`; keep additions terminal-safe (tput-aware) because the launcher clears the screen around prompts and progress output.
- Avoid touching unrelated `dev/results/` artifacts in code changes; they are user-generated outputs and should be ignored by automation.
