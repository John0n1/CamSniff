# Scanning Configuration Reference

This document describes CamSniff's scanning engine in detail — Nmap and Masscan
flag choices, port profiles, UDP discovery, and tuning knobs.

---

## Overview

CamSniff uses a layered scanning strategy driven by the selected `--mode`:

1. **Nmap TCP scan** — primary host and port discovery with optional NSE scripts.
2. **Masscan TCP scan** — high-rate parallel sweep to merge additional open ports
   (medium mode and above).
3. **UDP micro-scan** — targeted Nmap UDP probe for ONVIF WS-Discovery, STUN/TURN,
   and SRT indicator ports.
4. **Avahi/mDNS** — passive service discovery filtered for camera keywords.
5. **SSDP** — active UPnP/SSDP broadcast sweep for camera announcements.
6. **TShark** — short traffic capture to observe live RTSP and HTTP streams.

Results from all layers are merged into a unified host record in `discovery.json`.

---

## Nmap Configuration

### Base flags (all modes)

```
nmap -Pn -n [timing] [extras] --max-retries N [--min-rate N] [-O --osscan-guess --fuzzy] [-sV --version-intensity N] -p <ports> --open <targets>
```

| Flag | Purpose |
|------|---------|
| `-Pn` | Skip host discovery (ping). Cameras often block ICMP; this ensures they are scanned regardless. |
| `-n`  | Disable DNS resolution. Faster scans, no noise from reverse-lookup failures. |
| `--max-retries N` | Limit probe retries per port. Reduces scan time and network noise for unresponsive ports. |
| `--min-rate N` | Enforce a minimum packet rate (war/nuke only) to maintain throughput with heavy scripts. |
| `-O --osscan-guess --fuzzy` | Enable OS detection with aggressive guessing. Controlled by `NMAP_OSSCAN_ENABLE`. |
| `-sV --version-intensity N` | Service/version detection at a calibrated intensity level per mode (see table below). |
| `--open` | Only report open ports, suppressing closed/filtered noise. |

### Per-mode Nmap settings

| Mode       | Timing | Max Retries | Min Rate | Version Intensity | Extra Scripts              |
|------------|--------|-------------|----------|-------------------|----------------------------|
| `stealth+` | -T1    | 1           | –        | 1 (minimal)       | `--scan-delay 200ms`       |
| `stealth`  | -T2    | 1           | –        | 2 (light)         | –                          |
| `medium`   | -T4    | 2           | –        | 5 (standard)      | `--script=banner,http-title` |
| `aggressive` | -T4  | 3           | –        | 7 (intense)       | `--script default`         |
| `war`      | -T5    | 3           | 100 pps  | 8 (high)          | `--script default`         |
| `nuke`     | -T5    | 4           | 200 pps  | 9 (all probes)    | `--script vuln,default`    |

### NSE scripts by mode

| Mode       | Scripts used |
|------------|-------------|
| `stealth+` | RTSP URL brute (custom NSE, if present) |
| `stealth`  | RTSP URL brute |
| `medium`   | RTSP URL brute + `banner`, `http-title` |
| `aggressive` | RTSP URL brute + `default` script set |
| `war`      | RTSP URL brute + `default` script set |
| `nuke`     | RTSP URL brute + `vuln` + `default` script sets |

The custom RTSP brute script lives at `data/protocols/rtsp-url-brute.nse` and uses
the URL dictionary from `data/dictionaries/rtsp-urls.txt`. Concurrency is tuned
per mode via `CAM_RTSP_THREAD_PROFILE` in `scripts/core/port-profiles.sh`.

---

## Masscan Configuration

Masscan performs a fast TCP SYN sweep in parallel with or immediately after Nmap.
It is disabled for stealth modes.

```
masscan -p <ports> --rate <pps> --wait <seconds> <targets> -oJ <output>
```

| Parameter | Purpose |
|-----------|---------|
| `--rate`  | Packets per second. Scales with mode intensity. |
| `--wait`  | Seconds to wait after transmission before closing. Ensures all late SYN-ACKs are captured. |
| `-oJ`     | JSON output for structured port/IP ingestion. |

### Per-mode Masscan settings

| Mode       | Enabled | Rate (pps) | Wait (s) |
|------------|---------|------------|----------|
| `stealth+` | no      | –          | –        |
| `stealth`  | no      | –          | –        |
| `medium`   | yes     | 1,000      | 3        |
| `aggressive` | yes   | 5,000      | 5        |
| `war`      | yes     | 12,000     | 7        |
| `nuke`     | yes     | 20,000     | 10       |

---

## Port Profiles

Port profiles are defined in `scripts/core/port-profiles.sh` and map a logical
profile name to concrete Nmap and Masscan port specifications.

| Profile    | Key ports included |
|------------|--------------------|
| `minimal`  | 80, 554 |
| `core`     | 80, 443, 554 |
| `standard` | HTTP (80/81/88/443), RTSP (554/8554), SDK (8000/8080/8081), **Hikvision SDK (8899)**, **Dahua (34567)**, 37777 |
| `extended` | Standard + RTMP (1935), ONVIF alt (2000/2020), streaming (5000/5001/5540), media (7070/7447), **NVR (9527)**, etc. |
| `war`      | Extended + Axis (4520), Reolink (8787), WS-Discovery (3702), broad 8000–8200/9000–9400 sweeps |
| `total`    | 1–65535 |
| `fallback` | 80, 443, 554, 8000–8100, 9000–9100, 37777 |

### Notable camera-vendor ports

| Port  | Vendor / Protocol | Notes |
|-------|-------------------|-------|
| 554   | RTSP (standard)   | All vendors |
| 8554  | RTSP (alternate)  | Common on embedded cameras |
| 8000  | Hikvision iVMS    | SDK / iVMS-4200 |
| 8080  | Generic HTTP alt  | Web UI on many cameras |
| 8899  | Hikvision SDK     | Alternative SDK port |
| 34567 | Dahua / XMeye     | DVR/NVR control port |
| 37777 | Dahua primary     | Main Dahua TCP control |
| 9527  | NVR brands        | Generic NVR web/control |
| 2000  | Axis VAPIX alt    | Some Axis configurations |
| 2020  | ONVIF alt         | Some ONVIF device implementations |
| 1935  | RTMP              | Streaming protocol |
| 9710  | SRT               | Secure Reliable Transport |
| 3702  | WS-Discovery (UDP)| ONVIF device discovery |
| 3478  | STUN/WebRTC (UDP) | ICE/STUN candidates |

---

## UDP Discovery

A targeted UDP scan runs after TCP discovery to identify protocol indicators.

```
nmap -sU -Pn -n -T4 --max-retries 2 --host-timeout 30s -p 3702,3478,5349,9710,9999 <hosts>
```

| Port | Protocol | Signal |
|------|----------|--------|
| 3702 | WS-Discovery | ONVIF device announces presence here |
| 3478 | STUN     | WebRTC/ICE negotiation; camera streams via WebRTC |
| 5349 | TURN/TLS | Encrypted TURN relay for WebRTC |
| 9710 | SRT      | SRT media transport |
| 9999 | SRT alt  | Additional SRT indicator |

---

## Advanced Tuning

The following environment variables override mode defaults:

| Variable | Default | Description |
|----------|---------|-------------|
| `CAM_MODE_NMAP_SPEED` | (mode-driven) | Nmap timing template e.g. `-T4` |
| `CAM_MODE_NMAP_EXTRA` | (mode-driven) | Extra Nmap flags/scripts |
| `CAM_MODE_NMAP_OSSCAN_ENABLE` | `true` | Enable OS detection |
| `CAM_MODE_NMAP_VERSION_ENABLE` | `true` | Enable service version detection |
| `CAM_MODE_NMAP_VERSION_INTENSITY` | (mode-driven) | Version probe intensity 1–9 |
| `CAM_MODE_NMAP_MAX_RETRIES` | (mode-driven) | Max per-port probe retries |
| `CAM_MODE_NMAP_MIN_RATE` | (mode-driven) | Minimum packet rate (0 = unlimited) |
| `CAM_MODE_MASSCAN_ENABLE` | (mode-driven) | Enable/disable Masscan |
| `CAM_MODE_MASSCAN_RATE` | (mode-driven) | Masscan packets per second |
| `CAM_MODE_MASSCAN_WAIT` | (mode-driven) | Masscan end-of-scan wait seconds |
| `CAM_MODE_PORT_PROFILE` | (mode-driven) | Port profile key |
| `NMAP_RTSP_THREADS` | (mode-driven) | RTSP brute NSE thread count |

These are normally set by `scripts/core/mode-config.sh` and exported for
`scripts/camsniff.sh`. Override them in your environment before invoking the
script for one-off adjustments without editing configuration files.

---

## Performance Tips

- **Local LAN scans**: The default `-T4` medium mode balances speed and reliability
  well. Prefer `-T4` over `-T5` unless the LAN segment is known-stable.
- **High-density subnets** (e.g. /16 or larger): Enable war or nuke mode with
  Masscan's high rate to cover the address space quickly, then rely on Nmap to
  enrich discovered hosts.
- **Stealth scans**: `-T1` with `--scan-delay 200ms` and no Masscan minimises
  packets-per-second. Pair with `--skip-credentials` to avoid any banner pulls.
- **Flaky cameras**: Increase `--max-retries` via `CAM_MODE_NMAP_MAX_RETRIES` if
  cameras intermittently refuse connections before responding.
- **Version detection overhead**: Lower `CAM_MODE_NMAP_VERSION_INTENSITY` (e.g. to
  3) when scanning large subnets and you only need port-level discovery.
