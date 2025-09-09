# CamSniff - IP Camera Reconnaissance

[![Last commit](https://img.shields.io/github/last-commit/John0n1/CamSniff?style=flat-square&logo=github&color=red)](https://github.com/John0n1/CamSniff/commits/main)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/John0n1/CamSniff?style=flat-square&logo=github&color=neon&label=Latest%20Release)](https://github.com/John0n1/CamSniff/releases/latest) 
[![License](https://img.shields.io/github/license/John0n1/CamSniff?style=flat-square&logo=github&color=blue)](https://github.com/John0n1/CamSniff/blob/main/LICENSE)

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

[![stars](https://img.shields.io/github/stars/John0n1/CamSniff?style=social)](https://github.com/John0n1/CamSniff/stargazers)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-black?style=social&logo=buy-me-a-coffee&logoColor=yellow)](https://www.buymeacoffee.com/John0n1)

---

## Introduction

CamSniff is an advanced tool for reconnaissance and analysis of IP cameras and related IoT devices. It identifies devices, enumerates services, detects common camera endpoints, captures snapshots for AI-assisted analysis, and identifies potential vulnerabilities. The integrated web interface enables real-time visualization of results, including camera feeds, network topology, geographic mapping, and alerts.

<p align="center">
   <img src="https://github.com/user-attachments/assets/1ec79521-c935-4e29-bb54-b3316d978787" alt="CamSniff Screenshot" style="border: 2px solid #333; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.3); max-width: 80%;">
</p>

CamSniff is designed for Linux environments, with primary testing on Debian-based distributions such as Kali Linux, Debian, and Ubuntu. It automatically installs required dependencies on the initial run when executed with administrative privileges.

---

## Features

- **Device Identification**: Fingerprinting with support for major brands, including Hikvision, Dahua, Axis, Vivotek, and Foscam.
- **Network Scanning**: Integrates utilities like `fping`, `arp-scan`, `masscan`, `nmap`, and `onesixtyone` for comprehensive host and port discovery.
- **Protocol Support**: Handles RTSP, HTTP (MJPEG/HLS), CoAP, RTMP, and MQTT.
- **IoT Enumeration**: Includes UPnP/SSDP, mDNS, BLE scanning, Zigbee/Z-Wave detection, Wi-Fi OUI analysis, and network topology mapping.
- **Web Interface**: Flask-based dashboard for viewing camera feeds, topology diagrams, maps, and alerts, with live screenshots and timelines.
- **Reporting**: Produces text and JSON summaries, alert logs, and optional Nmap vulnerability scan results.
- **Credential Testing**: Uses Hydra and Medusa with predefined username/password lists; includes Gobuster for directory enumeration.
- **AI Analysis**: Applies OpenCV-based heuristics for infrared detection, motion, and brightness on captured frames.
- **Multi-Camera Views**: Supports mosaic layouts with overlays.
- **Automation**: Offers auto and quiet modes, subnet targeting, and extensible plugin support.

---

## Dependencies

CamSniff relies on a set of open-source tools and libraries. These are automatically installed during the first run (with administrative privileges), but users should review their individual licenses and terms.

**Core Utilities:**
- [![bash](https://img.shields.io/badge/bash-4EAA25?style=flat-square&logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/) - GNU Bourne Again SHell
- [![curl](https://img.shields.io/badge/curl-073551?style=flat-square&logo=curl&logoColor=white)](https://curl.se/) - Data transfer tool
- [![jq](https://img.shields.io/badge/jq-5890FF?style=flat-square&logo=jq&logoColor=white)](https://jqlang.github.io/jq/) - JSON processor
- [![netcat](https://img.shields.io/badge/netcat-FF6B35?style=flat-square&logo=terminal&logoColor=white)](https://nc110.sourceforge.io/) - Network utility
- [![FFmpeg](https://img.shields.io/badge/FFmpeg-007808?style=flat-square&logo=ffmpeg&logoColor=white)](https://ffmpeg.org/) - Multimedia framework
- [![FFplay](https://img.shields.io/badge/FFplay-007808?style=flat-square&logo=ffmpeg&logoColor=white)](https://ffmpeg.org/ffplay.html) - Media player

**Network Scanning Tools:**
- [![fping](https://img.shields.io/badge/fping-4A90E2?style=flat-square&logo=ping&logoColor=white)](https://fping.org/) - Ping utility
- [![masscan](https://img.shields.io/badge/masscan-FF4B4B?style=flat-square&logo=github&logoColor=white)](https://github.com/robertdavidgraham/masscan) - TCP port scanner
- [![Nmap](https://img.shields.io/badge/Nmap-4682B4?style=flat-square&logo=nmap&logoColor=white)](https://nmap.org/) - Network mapper
- [![Hydra](https://img.shields.io/badge/THC--Hydra-8B0000?style=flat-square&logo=github&logoColor=white)](https://github.com/vanhauser-thc/thc-hydra) - Login cracker
- [![tcpdump](https://img.shields.io/badge/tcpdump-1E90FF?style=flat-square&logo=wireshark&logoColor=white)](https://www.tcpdump.org/) - Packet analyzer
- [![tshark](https://img.shields.io/badge/tshark-1679A7?style=flat-square&logo=wireshark&logoColor=white)](https://www.wireshark.org/docs/man-pages/tshark.html) - Protocol analyzer
- [![arp-scan](https://img.shields.io/badge/arp--scan-32CD32?style=flat-square&logo=github&logoColor=white)](https://github.com/royhills/arp-scan) - ARP scanner

**Python Environment:**
- [![Python 3](https://img.shields.io/badge/Python%203-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/) - Programming language
- [![venv](https://img.shields.io/badge/python--venv-3776AB?style=flat-square&logo=python&logoColor=white)](https://docs.python.org/3/library/venv.html) - Virtual environments
- [![pip](https://img.shields.io/badge/pip-3776AB?style=flat-square&logo=pypi&logoColor=white)](https://pip.pypa.io/) - Package installer
- [![OpenCV](https://img.shields.io/badge/OpenCV-5C3EE8?style=flat-square&logo=opencv&logoColor=white)](https://github.com/opencv/opencv-python) - Computer vision library
- [![Flask](https://img.shields.io/badge/Flask-000000?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com/) - Web framework (for UI)

**Additional Tools:**
- [![Gobuster](https://img.shields.io/badge/Gobuster-00ADD8?style=flat-square&logo=go&logoColor=white)](https://github.com/OJ/gobuster) - Directory and DNS enumeration
- [![Medusa](https://img.shields.io/badge/Medusa-8B008B?style=flat-square&logo=github&logoColor=white)](https://github.com/jmk-foofus/medusa) - Brute-force tool
- [![onesixtyone](https://img.shields.io/badge/onesixtyone-FF8C00?style=flat-square&logo=github&logoColor=white)](https://github.com/trailofbits/onesixtyone) - SNMP scanner
- [![libcoap](https://img.shields.io/badge/coap--client-6B46C1?style=flat-square&logo=internet&logoColor=white)](https://libcoap.net/) - CoAP client
- [![rtmpdump](https://img.shields.io/badge/rtmpdump-FF69B4?style=flat-square&logo=adobe&logoColor=white)](https://rtmpdump.mplayerhq.hu/) - RTMP dumper

**IoT Discovery Tools:**
- [![Avahi](https://img.shields.io/badge/avahi--browse-E95420?style=flat-square&logo=ubuntu&logoColor=white)](https://www.avahi.org/) - mDNS/DNS-SD discovery
- [![Bluetooth](https://img.shields.io/badge/bluetoothctl-0082FC?style=flat-square&logo=bluetooth&logoColor=white)](https://www.bluez.org/) - BLE scanning
- [![NetworkManager](https://img.shields.io/badge/iw%2Fnmcli-FCC624?style=flat-square&logo=wifi&logoColor=black)](https://networkmanager.dev/) - Wi-Fi scanning

Recommended packages: `avahi-utils`, `bluez`, `bluez-tools`, `wireless-tools`, `iw`, and `network-manager`.

---

## Installation

### DEB Package (Recommended)

Download the latest DEB package from the [releases page](https://github.com/John0n1/CamSniff/releases/latest) and install it:

```bash
sudo apt install ./camsniff*.deb
```

Alternatively:

```bash
sudo gdebi ./camsniff*.deb
```

This installs the executable at `/usr/bin/camsniff` and the default configuration at `/etc/camsniff/camcfg.json`.

### From Source

1. Clone the repository:

   ```bash
   git clone https://github.com/John0n1/CamSniff.git
   cd CamSniff
   ```

2. Set executable permissions:

   ```bash
   chmod +x *.sh
   ```

---

## Usage

Run the tool with administrative privileges for interactive mode:

```bash
sudo ./camsniff.sh
```

If installed via DEB:

```bash
sudo camsniff
```

**Command-Line Options:**

```
sudo ./camsniff.sh [OPTIONS]

Options:
  -y, --yes     Skip confirmation prompts
  -q, --quiet   Reduce output verbosity
  -a, --auto    Enable full automation (no prompts)
  -t, --target  Specify target subnet (e.g., 192.168.1.0/24)
  -h, --help    Display this help message
```

---

## Output and Reporting

CamSniff generates structured outputs in a timestamped directory:

```bash
output/results_YYYYMMDD_HHMMSS/
```

**Directory Structure:**

```
├── logs/           # Scan logs and debug data
├── screenshots/    # Camera snapshots with AI annotations
└── reports/        # Summaries and data files
  ├── summary_YYYYMMDD_HHMMSS.txt    # Text summary
  ├── summary_YYYYMMDD_HHMMSS.json   # JSON summary
  ├── cameras.json                   # Camera details (e.g., stream URLs)
  ├── alerts.log                     # Event logs (e.g., discoveries, notices)
  ├── analysis_IP.json               # Per-device AI results
  ├── mdns_services.txt              # mDNS results (if enabled)
  ├── ssdp_devices.txt               # UPnP/SSDP results (if enabled)
  ├── ble_scan.txt                   # BLE results (if enabled)
  ├── topology.json                  # Network topology data
  └── logs/nmap_vuln_*.txt           # Nmap vulnerability scans (if enabled)
```

**Camera Details:** Each entry includes IP/port, protocol, manufacturer, credentials (if tested), and AI analysis (e.g., IR, motion, brightness).

**Web Interface:** Launch with:

```bash
./webui.sh
```

Access at `http://localhost:5000` for interactive views.

---

## Configuration

Configuration is loaded from `camcfg.json` (defaults to `/etc/camsniff/camcfg.json` if installed via DEB). All settings have defaults but can be customized.

**Example Configuration:**

```json
{
  "sleep_seconds": 45,
  "nmap_ports": "1-65535",
  "masscan_rate": 20000,
  "hydra_rate": 16,
  "max_streams": 4,
  "cve_github_repo": "https://github.com/CVEProject/cvelistV5/tree/0c81b12af2cabcadb83f312d4d81dc99008235c9/cves/",
  "cve_cache_dir": "/tmp/cve_cache",
  "cve_current_year": "2025",
  "dynamic_rtsp_url": "https://github.com/John0n1/CamSniff/blob/4d682edf7b4512562d24ccdf863332952637094d/data/rtsp_paths.csv",
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

**Key Notes:**
- `stealth_mode`: Adds random delays to scans for reduced predictability.
- `enable_nmap_vuln`: Runs Nmap vulnerability scripts (increases scan time but enhances insights).
- Wireless features (Wi-Fi, BLE, Zigbee/Z-Wave) require compatible hardware; disable if not supported.

---

## Troubleshooting

- **Dependency Issues:** Run with `sudo` for automatic installation.
- **RTSP Path Errors:** Ensure `dynamic_rtsp_url` points to a valid file; a fallback list is available.
- **Permissions:** Administrative privileges are required for scanning and captures.
- **Non-Interactive Environments:** Set `NO_ANIM=1` to disable animations.
- **IoT Features:** Disable unsupported hardware scans in configuration.
- **Diagnostics:** Review `output/*/logs/` and `alerts.log` for details.

---

## Contributing

Contributions are welcome. Please follow these steps:

1. Fork the repository.
2. Clone your fork:

   ```bash
   git clone https://github.com/John0n1/CamSniff.git
   cd CamSniff
   ```

3. Create a branch:

   ```bash
   git checkout -b feature-branch
   ```

4. Make and commit changes:

   ```bash
   git commit -m "Description of changes"
   ```

5. Push to your fork:

   ```bash
   git push origin feature-branch
   ```

6. Open a pull request with a detailed description.

Adhere to the project's coding standards.

---

## Acknowledgments

Thanks to the developers of the open-source tools and libraries that enable CamSniff.

---

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.

**Disclaimer:** This tool is for educational and research purposes only. Use it responsibly and with permission. The authors assume no liability for misuse.
