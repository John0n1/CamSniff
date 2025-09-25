# CamSniff - IP Camera Reconnaissance Tool

''*You think you're alone, but what if someone’s eyes are fixed on you right now?*''

[![Latest Release](https://img.shields.io/github/v/release/John0n1/CamSniff?style=flat-square&logo=github&color=brightgreen&label=Latest%20Release)](https://github.com/John0n1/CamSniff/releases/latest)
[![License](https://img.shields.io/github/license/John0n1/CamSniff?style=flat-square&logo=opensourceinitiative&color=blue)](LICENSE)
[![Issues](https://img.shields.io/github/issues/John0n1/CamSniff?style=flat-square&logo=github&color=yellow)](https://github.com/John0n1/CamSniff/issues)

<img width="128" height="128" alt="CamSniff" src="https://github.com/user-attachments/assets/99c120d5-6bda-44c0-99f6-36e169810a23" />

- **[Introduction](#introduction)**
- **[Features](#features)**
- **[Dependencies](#dependencies)**
- **[Installation](#installation)**
- **[Usage](#usage)**
- **[Output and Reporting](#output-and-reporting)**
- **[Configuration](#configuration)**
- **[Troubleshooting](#troubleshooting)**
- **[Contributing](#contributing)**
- **[Acknowledgments](#acknowledgments)**
- **[License](#license)**

[![Stars](https://img.shields.io/github/stars/John0n1/CamSniff?style=for-the-badge)](https://github.com/John0n1/CamSniff/stargazers)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://www.buymeacoffee.com/John0n1)



## Introduction
**CamSniff is a powerful reconnaissance tool for discovering, analyzing and displaying IP cameras and IoT devices.**

- **It performs device fingerprinting, service enumeration, endpoint detection, snapshot capture for AI analysis, and vulnerability scanning.**

- **The built-in web interface provides real-time visualizations, including camera feeds, network maps, geographic locations, and alerts.**

<p align="center">
  <img src="https://github.com/user-attachments/assets/1ec79521-c935-4e29-bb54-b3316d978787" alt="CamSniff Screenshot" style="border: 2px solid #333; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.3); max-width: 80%;">
</p>

**Primarily built for Debian-based Linux distributions, CamSniff auto-installs dependencies on first run with admin privileges.**

- **It uses local datasets for RTSP paths (`data/rtsp_paths.csv`) and CVEs (`data/cves`) by default, avoiding network downloads. Radio-based features (Wi-Fi, BLE, Zigbee, Z-Wave) may not work on WSL due to hardware limitations.**

**Disclaimer:** This tool is for educational and research purposes only. Use responsibly and with explicit permission. The authors are not liable for any misuse.


## Features

- **Device Fingerprinting:** Supports major brands like Hikvision, D-Link, TP-Link, Samsung, Panasonic, Dahua, Axis, Vivotek, and Foscam.
- **Network Scanning:** Uses `fping`, `arp-scan`, `masscan`, `nmap`, and `onesixtyone` for host discovery and port scanning.
- **Protocol Handling:** RTSP, HTTP (MJPEG/HLS), CoAP, RTMP, and MQTT.
- **IoT Enumeration:** UPnP/SSDP, mDNS, BLE, Zigbee/Z-Wave, Wi-Fi OUI lookup, and network topology mapping.
- **Web Interface:** Flask-based dashboard for camera feeds, topology diagrams, maps, alerts, live screenshots, and timelines.
- **Reporting:** Text/JSON summaries, alert logs, and optional Nmap vulnerability scans.
- **Credential Brute-Forcing:** Hydra and Medusa with custom wordlists; Gobuster for directory brute-forcing.
- **AI Analysis:** OpenCV for detecting infrared, motion, and brightness in snapshots.
- **Multi-View Support:** Mosaic layouts with overlays for multiple cameras.
- **Automation:** Auto/quiet modes, subnet targeting, stealth delays, and plugin extensibility.

## Dependencies

CamSniff depends on various open-source tools and libraries, auto-installed on first run with `sudo`. Review their licenses individually.

### Core Utilities 🛠
- [Bash](https://www.gnu.org/software/bash/) - Scripting shell
- [curl](https://curl.se/) - Data transfer
- [jq](https://jqlang.github.io/jq/) - JSON processing
- [netcat](https://nc110.sourceforge.io/) - Network utility
- [FFmpeg](https://ffmpeg.org/) - Multimedia handling
- [FFplay](https://ffmpeg.org/ffplay.html) - Media playback

### Network Scanning 🔍
- [fping](https://fping.org/) - ICMP ping
- [masscan](https://github.com/robertdavidgraham/masscan) - Fast port scanner
- [Nmap](https://nmap.org/) - Network mapping
- [Hydra](https://github.com/vanhauser-thc/thc-hydra) - Brute-force login
- [tcpdump](https://www.tcpdump.org/) - Packet capture
- [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) - Protocol analysis
- [arp-scan](https://github.com/royhills/arp-scan) - ARP scanning

### Python Components 🐍
- [Python 3](https://www.python.org/) - Core language
- [venv](https://docs.python.org/3/library/venv.html) - Virtual environments
- [pip](https://pip.pypa.io/) - Package manager
- [OpenCV](https://github.com/opencv/opencv-python) - Computer vision
- [Flask](https://flask.palletsprojects.com/) - Web framework

### Additional Tools 🧰
- [Gobuster](https://github.com/OJ/gobuster) - Directory enumeration
- [Medusa](https://github.com/jmk-foofus/medusa) - Brute-force
- [onesixtyone](https://github.com/trailofbits/onesixtyone) - SNMP scanner
- [libcoap](https://libcoap.net/) - CoAP client
- [rtmpdump](https://rtmpdump.mplayerhq.hu/) - RTMP streaming

### IoT Discovery 📡
- [Avahi](https://www.avahi.org/) - mDNS/DNS-SD
- [BlueZ](https://www.bluez.org/) - Bluetooth/BLE
- [NetworkManager](https://networkmanager.dev/) - Wi-Fi tools (`iw`, `nmcli`)

Recommended: `avahi-utils`, `bluez`, `bluez-tools`, `wireless-tools`, `iw`, `network-manager`.

## Installation

### Recommended: DEB Package
Download from [releases](https://github.com/John0n1/CamSniff/releases/latest):

```bash
sudo apt install ./camsniff*.deb
```

Or:

```bash
sudo gdebi ./camsniff*.deb
```

Installs `/usr/bin/camsniff` and `/etc/camsniff/camcfg.json`.

### From Source
1. Clone:

   ```bash
   git clone https://github.com/John0n1/CamSniff.git
   cd CamSniff
   ```

2. Make executable:

   ```bash
   chmod +x *.sh
   ```

### Python-Only (via pip)
For CLI probes and web backend:

```bash
pip install camsniff
```

Provides `camsniff-cli` and `camsniff-web`. Does not include full Bash orchestrator or system tools.

## Usage

Run with `sudo` for full functionality:

```bash
sudo ./camsniff.sh
```

Or if installed:

```bash
sudo camsniff
```

Options:
- `-y, --yes`: Skip prompts
- `-q, --quiet`: Less verbose
- `-a, --auto`: Fully automated
- `-t, --target <subnet>`: e.g., `192.168.1.0/24`
- `-h, --help`: Show help

Wireless features require compatible hardware; disable in config if unsupported.

## Project Structure
```
├── camsniff.sh          # Main entry point script
├── src/scripts                # Core functionality scripts
│   ├── env_setup.sh     # Environment configuration
│   ├── scan_analyze.sh  # Scanning and analysis logic
│   ├── setup.sh         # Initial setup functions
│   ├── cleanup.sh       # Cleanup operations
│   ├── install_deps.sh  # Dependency installation
│   ├── iot_enumerate.sh # IoT device enumeration
│   ├── webui.sh         # Web interface launcher
│   └── doctor.sh        # System diagnostics
├── src/python_core/         # Python modules and scripts
│   ├── __init__.py      # Package initialization
│   ├── cli.py           # Command-line interface
│   ├── web_backend.py   # FastAPI backend
│   ├── ai_analyze.py    # AI analysis functions
│   └── cve_quick_search.py # CVE search functionality
├── data/                # Data files (CVEs)
└── debian/              # Debian packaging files
```

## Output and Reporting

Results saved in `output/results_YYYYMMDD_HHMMSS/`:

- `logs/`: Scan logs
- `screenshots/`: Annotated snapshots
- `reports/`:
  - `summary_YYYYMMDD_HHMMSS.txt/json`: Overviews
  - `cameras.json`: Device details (IPs, protocols, etc.)
  - `alerts.log`: Events
  - `analysis_IP.json`: AI results per device
  - `mdns_services.txt`, `ssdp_devices.txt`, `ble_scan.txt`: IoT data
  - `topology.json`: Network map
  - `logs/nmap_vuln_*.txt`: Vulnerability scans (if enabled)

**Web Interface:** Start with `./core/webui.sh` or `camsniff-web`. Access at `http://localhost:8088` (configurable via `CAMSNIFF_WEB_PORT`).

## Configuration

Edit `camcfg.json` (defaults: `/etc/camsniff/camcfg.json`):

```json
{
  "sleep_seconds": 45,
  "nmap_ports": "1-65535",
  "masscan_rate": 20000,
  "hydra_rate": 16,
  "max_streams": 4,
  "cve_github_repo": "",
  "cve_cache_dir": "data/cves",
  "cve_current_year": "2025",
  "dynamic_rtsp_url": "",
  "dirb_wordlist": "/usr/share/wordlists/dirb/common.txt",
  "password_wordlist": "data/passwords.txt",
  "username_wordlist": "data/usernames.txt",
  "snmp_communities": ["public", "private", "camera", "admin", "cam", "cisco", "default", "guest", "test"],
  "medusa_threads": 8,
  "enable_iot_enumeration": true,
  "enable_pcap_capture": true,
  "enable_wifi_scan": true,
  "enable_ble_scan": true,
  "enable_zigbee_zwave_scan": true,
  "stealth_mode": true,
  "enable_nmap_vuln": true
}
```

- `stealth_mode`: Adds delays for stealth.
- `enable_nmap_vuln`: Enables detailed vuln scans (slower).
- Offline-first: Uses local files for RTSP/CVEs.

## Troubleshooting

- **Dependencies:** Use `sudo` for auto-install.
- **RTSP Errors:** Verify `dynamic_rtsp_url` or use fallback.
- **Permissions:** `sudo` required for scans.
- **Animations:** Set `NO_ANIM=1` for non-interactive.
- **IoT Scans:** Disable unsupported features in config.
- **Logs:** Check `output/*/logs/` and `alerts.log`.

## Contributing

1. Fork and clone:

   ```bash
   git clone https://github.com/your-username/CamSniff.git
   cd CamSniff
   ```

2. Branch:

   ```bash
   git checkout -b feature-branch
   ```

3. Commit and push:

   ```bash
   git commit -m "Description"
   git push origin feature-branch
   ```

4. Open a PR with details.

Try to follow simimar coding patterns.

## Acknowledgments

Gratitude to open-source tool developers powering CamSniff.

## License

MIT License. See [LICENSE](LICENSE).
