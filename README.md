# CamSniff 2.1.0

CamSniff is an automated reconnaissance toolkit for IP cameras. It performs coordinated discovery across TCP/UDP ports, mDNS/Avahi announcements, live traffic captures, credential probing, and RTSP enumeration to surface insecure or misconfigured devices on a local network.

> ⚠️ **Use responsibly.** Only scan networks and devices you are explicitly authorised to assess.

## Key capabilities

- Multi-stage discovery pipeline (Nmap, Masscan, Avahi/mDNS, and TShark traffic captures)
- Mode-aware tuning (`--mode stealth` … `--mode unphantmoable`) with aggressive defaults when no flags are provided
- Tight integration with the bundled `rtsp-url-brute.nse` to brute-force common RTSP media paths as part of the Nmap stage
- Secondary heuristics for ONVIF, RTMP, HLS, WebRTC, and SRT across TCP/UDP surfaces, persisted as `additional_protocols` in results
- Automatic credential probing (HTTP snapshots + RTSP stills) using curated username/password dictionaries
- Rich device profiling powered by `data/paths.csv`, including vendor fingerprints, default credentials, and CVE references
- Comprehensive run artifacts under `dev/results/<timestamp>/` for repeatable analysis
- Matrix “digital rain” welcome animation with centered ASCII art status panels for a polished UX
- Fallback HTTP snapshot dictionary and expanded credential lists to maximise capture success

## Prerequisites

- Linux host with `bash`, `curl`, `jq`, `python3`, and the following tools available:
	- `nmap` (required)
	- `masscan` (optional; enabled automatically in aggressive modes)
	- `avahi-browse` (from `avahi-utils`)
	- `tshark` (Wireshark CLI)
	- `ffmpeg`
	- `iproute2` (for `ip` routing helpers)
	- `chafa` (optional, for ASCII thumbnails)
- Root privileges when executing the main scanner.

## Quick start

```bash
sudo camsniff
sudo camsniff.sh --mode war
sudo camsniff --mode stealth --yes
```

![CamSniff run](docs/screenshots/run1.png)

CLI flags:

- `--mode/-m <name>` — `stealth`, `ultra stealth`, `medium`, `aggressive`, `war`, or `unphantmoable` (default).
- `--yes/-y` — auto-confirm the interactive banner prompt.
- `--version/-v` and `--help/-h` — metadata and usage information.

## What happens during a run

1. Dependencies are validated (with optional installation via `deps-install.sh`).
2. Nmap scans the selected port profile, automatically loading `data/rtsp-url-brute.nse` and tuning RTSP brute threads according to the active mode.
3. Masscan runs when the mode allows it, broadening coverage with configurable packet rates.
4. Avahi/mDNS discovery and TShark captures surface service broadcasts and live RTSP/HTTP traffic.
5. Results are merged with the vendor knowledge base (`data/paths.csv`), protocol heuristics are recorded under `additional_protocols`, and everything is written to `dev/results/<timestamp>/discovery.json`.
6. `scripts/credential-probe.sh` replays the discovery data to attempt HTTP snapshots and RTSP frame grabs, saving artifacts plus ASCII previews.

## Outputs & artifacts

Every run generates a timestamped directory under `dev/results/` containing:

- `discovery.json` — consolidated scan results, vendor matches, and protocol hits (`additional_protocols`) alongside RTSP brute-force findings.
- `credentials.json` — successes and failures from the credential probe.
- `logs/`
	- `nmap-output.txt` & `nmap-command.log`
	- `masscan-output.json` & `masscan-command.log` (when enabled)
	- `avahi-services.txt`
	- `tshark-traffic.csv`
- `thumbnails/`
	- Captured JPEGs (HTTP snapshots / RTSP frames)
	- Optional ASCII previews (`*.txt`) rendered via `chafa`

Use `scripts/analyze.sh` after a run to print host counts, protocol coverage, and credential statistics for the most recent `dev/results/` directory.

## Debian packaging

CamSniff ships with a refreshed `debian/` directory that targets Debian 13 (trixie), Kali, and Ubuntu contrib repositories. Build artifacts with:

```bash
dpkg-buildpackage -us -uc
```

The packaging metadata installs scripts under `/usr/lib/camsniff/`, registers icons in the hicolor theme, and publishes a desktop entry without elevated wrappers. Prior to building, ensure any root-owned leftovers from previous runs (for example `debian/.debhelper/`, `debian/camsniff/`, or `scripts/venv/`) are removed with elevated privileges if necessary.

## Data dictionaries

CamSniff ships with a set of editable data files under `data/` to keep common fingerprints and credential heuristics in one place:

- `paths.csv` — vendor catalogue powering profile matches, default credential suggestions, CVE references, and RTSP/HTTP templates.
- `usernames.txt` / `passwords.txt` — extended dictionaries used by the credential probe (comments and blank lines are ignored).
- `http-paths.txt` — fallback HTTP snapshot endpoints used when a vendor profile does not specify its own capture URL.
- `rtsp-url-brute.nse` — Nmap NSE script dictionary invoked during the discovery stage.
- `port-profiles.sh` — shared port profile definitions consumed by the main orchestrator.