# CamSniff - Camera Reconnaissance

[![Last commit](https://img.shields.io/github/last-commit/John0n1/CamSniff?style=flat-square&logo=github&color=red)](https://github.com/John0n1/CamSniff/commits/main)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/John0n1/CamSniff?style=flat-square&logo=github&color=neon&label=Latest%20Release)](https://github.com/John0n1/CamSniff/releases/latest) 
[![License](https://img.shields.io/github/license/John0n1/CamSniff?style=flat-square&logo=github&color=blue)](https://github.com/John0n1/CamSniff/blob/main/LICENSE)

---

- **[Requirements](#requirements)**
- **[Installation](#installation)**
- **[Usage](#usage)**
- **[Configuration](#configuration)**

[![stars](https://img.shields.io/github/stars/John0n1/CamSniff?style=social)](https://github.com/John0n1/CamSniff/stargazers)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-black?style=social&logo=buy-me-a-coffee&logoColor=yellow)](https://www.buymeacoffee.com/John0n1)
---

## Introduction

**CamSniff** is a sophisticated reconnaissance and analysis tool designed for IP cameras and associated IoT devices. It efficiently discovers devices, enumerates services, identifies common camera endpoints, captures snapshots for lightweight AI-driven analysis, and highlights potential vulnerabilities. The integrated Web UI provides real-time visualization of results, including camera feeds, network topology, maps, and alerts.

---

## Features

- **Camera Identification**: Advanced fingerprinting with brand-specific hints (e.g., Hikvision, Dahua, Axis, Vivotek, Foscam, and more).
- **Network Scanning**: Utilizes tools such as `fping`, `arp-scan`, `masscan`, `nmap`, `onesixtyone`, and others for  scanning.
- **Protocols**: Supports RTSP, HTTP/MJPEG/HLS, CoAP, RTMP, and MQTT protocols.
- **IoT Enumeration**: Includes UPnP/SSDP, mDNS, BLE scanning, Zigbee/Z-Wave adapter detection, WiFi OUI hints, and topology snapshots.
- **Web Dashboard**: A lightweight Flask-based UI for viewing cameras, topology, maps, and alerts, complete with live screenshots and timelines.
- **Reporting**: Generates text and JSON summaries, alerts logs, and optional Nmap vulnerability scan outputs.
- **Credentials & Brute Force**: Employs Hydra/Medusa combinations with curated username/password lists; includes Gobuster for directory scanning.
- **AI Snapshot Analysis**: Applies IR spot detection, motion, and brightness heuristics using OpenCV on captured frames.
- **Mosaic View**: Supports multi-camera layouts with basic overlays.
- **Automation**: Features auto/quiet modes, target subnet selection, and plugin hooks for streamlined operations.

---

## Requirements

CamSniff is optimized for Linux environments, with testing focused on Debian-based distributions such as Kali, Parrot, and Ubuntu. The script automatically installs required tools during the initial run when executed with root privileges.

**⚠️📜 Please note that some of the following tools and libraries come with their own licenses and terms of use. Be sure to review and comply with these licenses when using CamSniff. CamSniff itself only automates the use of these tools and does not modify them.**

The following tools and libraries form the core functionality of CamSniff. We extend our gratitude to the developers of these projects.

**Core Tools:**
- [![bash](https://img.shields.io/badge/bash-4EAA25?style=flat-square&logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/) - GNU Bourne Again SHell
- [![curl](https://img.shields.io/badge/curl-073551?style=flat-square&logo=curl&logoColor=white)](https://curl.se/) - Command line tool for transferring data
- [![jq](https://img.shields.io/badge/jq-5890FF?style=flat-square&logo=jq&logoColor=white)](https://jqlang.github.io/jq/) - Lightweight JSON processor
- [![netcat](https://img.shields.io/badge/netcat-FF6B35?style=flat-square&logo=terminal&logoColor=white)](https://nc110.sourceforge.io/) - Network utility for reading/writing network connections
- [![FFmpeg](https://img.shields.io/badge/FFmpeg-007808?style=flat-square&logo=ffmpeg&logoColor=white)](https://ffmpeg.org/) - Complete multimedia framework
- [![FFplay](https://img.shields.io/badge/FFplay-007808?style=flat-square&logo=ffmpeg&logoColor=white)](https://ffmpeg.org/ffplay.html) - Simple media player

**Network Tools:**
- [![fping](https://img.shields.io/badge/fping-4A90E2?style=flat-square&logo=ping&logoColor=white)](https://fping.org/) - Fast ping utility
- [![masscan](https://img.shields.io/badge/masscan-FF4B4B?style=flat-square&logo=github&logoColor=white)](https://github.com/robertdavidgraham/masscan) - Fast TCP port scanner
- [![Nmap](https://img.shields.io/badge/Nmap-4682B4?style=flat-square&logo=nmap&logoColor=white)](https://nmap.org/) - Network discovery and security auditing
- [![Hydra](https://img.shields.io/badge/THC--Hydra-8B0000?style=flat-square&logo=github&logoColor=white)](https://github.com/vanhauser-thc/thc-hydra) - Network logon cracker
- [![tcpdump](https://img.shields.io/badge/tcpdump-1E90FF?style=flat-square&logo=wireshark&logoColor=white)](https://www.tcpdump.org/) - Packet analyzer
- [![tshark](https://img.shields.io/badge/tshark-1679A7?style=flat-square&logo=wireshark&logoColor=white)](https://www.wireshark.org/docs/man-pages/tshark.html) - Network protocol analyzer
- [![arp-scan](https://img.shields.io/badge/arp--scan-32CD32?style=flat-square&logo=github&logoColor=white)](https://github.com/royhills/arp-scan) - ARP scanning tool

**Python Environment:**
- [![Python 3](https://img.shields.io/badge/Python%203-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/) - Programming language
- [![venv](https://img.shields.io/badge/python--venv-3776AB?style=flat-square&logo=python&logoColor=white)](https://docs.python.org/3/library/venv.html) - Virtual environment support
- [![pip](https://img.shields.io/badge/pip-3776AB?style=flat-square&logo=pypi&logoColor=white)](https://pip.pypa.io/) - Package installer for Python
- [![OpenCV](https://img.shields.io/badge/OpenCV-5C3EE8?style=flat-square&logo=opencv&logoColor=white)](https://github.com/opencv/opencv-python) - Computer vision library

**Additional Tools:**
- [![Gobuster](https://img.shields.io/badge/Gobuster-00ADD8?style=flat-square&logo=go&logoColor=white)](https://github.com/OJ/gobuster) - Directory/file & DNS busting tool
- [![Medusa](https://img.shields.io/badge/Medusa-8B008B?style=flat-square&logo=github&logoColor=white)](https://github.com/jmk-foofus/medusa) - Speedy, parallel login brute-forcer
- [![onesixtyone](https://img.shields.io/badge/onesixtyone-FF8C00?style=flat-square&logo=github&logoColor=white)](https://github.com/trailofbits/onesixtyone) - SNMP scanner
- [![libcoap](https://img.shields.io/badge/coap--client-6B46C1?style=flat-square&logo=internet&logoColor=white)](https://libcoap.net/) - CoAP protocol client
- [![rtmpdump](https://img.shields.io/badge/rtmpdump-FF69B4?style=flat-square&logo=adobe&logoColor=white)](https://rtmpdump.mplayerhq.hu/) - RTMP streaming media dumper

**IoT Discovery Tools:**
- [![Avahi](https://img.shields.io/badge/avahi--browse-E95420?style=flat-square&logo=ubuntu&logoColor=white)](https://www.avahi.org/) - mDNS/DNS-SD service discovery
- [![Bluetooth](https://img.shields.io/badge/bluetoothctl-0082FC?style=flat-square&logo=bluetooth&logoColor=white)](https://www.bluez.org/) - Bluetooth Low Energy scanning
- [![NetworkManager](https://img.shields.io/badge/iw%2Fnmcli-FCC624?style=flat-square&logo=wifi&logoColor=black)](https://networkmanager.dev/) - WiFi network scanning
- [![tcpdump](https://img.shields.io/badge/tcpdump-1E90FF?style=flat-square&logo=wireshark&logoColor=white)](https://www.tcpdump.org/) - Packet capture for analysis

- Also recommended: `avahi-utils`, `bluez`, `bluez-tools`, `wireless-tools`, `iw`, `network-manager`, and `python3-flask` for the Web UI.
---

## Installation

### Recommended (DEB Package)

Download and install the latest DEB package from the [releases page](https://github.com/John0n1/CamSniff/releases/latest):

```bash
sudo apt install -y ./camsniff*.deb 
```
or

```bash
gdebi ./camsniff_1.0.2_all.deb
```
This installation places the launcher at `/usr/bin/camsniff` and the default configuration at `/etc/camsniff/camcfg.json`.

### Manual (From Source)

1. Clone the repository:
   ```bash
   git clone https://github.com/John0n1/CamSniff.git
   cd CamSniff
   ```

2. Make the scripts executable:
   ```bash
   chmod +x *.sh
   ```

3. Run the launcher:
   ```bash
   sudo ./camsniff.sh
   ```

---

## Usage

Launch the main script `camsniff.sh` with root privileges to enter interactive mode:

```bash
sudo ./camsniff.sh
```

If installed via the DEB package, use the following command:

```bash
sudo camsniff
```

### Optional Web Dashboard

Initiate the lightweight dashboard during or after scans to visualize cameras, maps, and alerts:

```bash
./webui.sh
```

This launches a Flask server accessible at `http://localhost:8088` (customizable via `CAMSNIFF_WEB_PORT`). It automatically loads the latest output folder from `./output/`.

## Output and Reporting

CamSniff 1.0.2 now delivers a improved, , structured outputs and reports:

```bash
./webui.sh
```

This launches a Flask server accessible at `http://localhost:8088` (customizable via `CAMSNIFF_WEB_PORT`). It automatically loads the latest output folder from `./output/`.

## Output and Reporting

CamSniff 1.0.2 now delivers a improved, , structured outputs and reports:

### Output Directory Structure
```
./output/results_YYYYMMDD_HHMMSS/
├── logs/           # Scan logs and debug information
├── screenshots/    # Camera snapshots with AI analysis
└── reports/        # Summary reports and structured data
  ├── summary_YYYYMMDD_HHMMSS.txt    # Human-readable summary
  ├── summary_YYYYMMDD_HHMMSS.json   # Machine-readable summary
  ├── cameras.json                    # Detailed camera discoveries (stream URLs)
  ├── alerts.log                      # Events (camera_found, ai_notice, ...)
  ├── analysis_IP.json               # Per-camera AI analysis
  ├── mdns_services.txt              # mDNS enumeration results (if enabled)
  ├── ssdp_devices.txt               # UPnP/SSDP devices (if enabled)
  ├── ble_scan.txt                   # BLE device scan (if enabled)
  ├── topology.json                  # Simple network graph snapshot
  └── logs/nmap_vuln_*.txt           # Optional nmap vuln outputs
```

**Key Features:**
- **Real-time CVE data**: Fetches the latest vulnerability information from [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5)
- **Smart caching**: Results are cached locally for 24 hours to improve performance
- **Device-specific searches**: Automatically searches for CVEs related to detected camera brands (Hikvision, Dahua, Axis, etc.)
- **Structured CVE data**: Parses official CVE JSON format for accurate vulnerability information

### Camera Information
Each discovered camera is logged with:
- IP address and port
- Protocol type (RTSP, HTTP, etc.)
- Device manufacturer (when detectable)
- Credentials used (if any)
- AI analysis results (IR detection, motion areas, brightness)

### Command Line Options
```bash
sudo ./camsniff.sh [OPTIONS]

Options:
  -y, --yes     Skip confirmation prompts
  -q, --quiet   Reduce output verbosity
  -a, --auto    Full automation mode (skip all prompts)
  -t, --target  Specify target subnet (e.g., 192.168.1.0/24)
  -h, --help    Show this help message
```

---

## Configuration

CamSniff loads its configuration from `camcfg.json` (prioritizing `/etc/camsniff/camcfg.json` if installed). Below is an example with default settings (all features enabled in version 1.0.2):

**Everything has a default value but can be customized:**

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
  "snmp_communities": ["public", "private", "camera", "admin", "cam", "cisco", "default", "guest", "test"], //
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

**Notes:**
- `stealth_mode`: Introduces jitter to sleep intervals for a less predictable scanning pattern.
- `enable_nmap_vuln`: Executes `nmap --script vuln` on discovered hosts (may increase scan duration but provides deeper insights).
- Wireless/BLE/Zigbee features require compatible hardware and permissions; disable them if not applicable.

---

## Troubleshooting

- **Missing Dependencies:** The tool auto-installs dependencies on first run; ensure execution with `sudo`.
- **RTSP Paths Not Found:** Verify that `dynamic_rtsp_url` references a valid CSV/TSV; a built-in minimal list serves as a fallback.
- **Permission Issues:** Root privileges are required for scanning, dependency installation, and packet capture (pcap).
- **Non-TTY Output/CI:** Use `NO_ANIM=1` to disable animations in non-interactive environments.
- **IoT Enumeration:** BLE and Zigbee/Z-Wave require hardware/driver support; disable relevant flags if unavailable.
- **Error Messages:** Inspect `output/*/logs/` and `alerts.log` for detailed diagnostics and context.

---

## Contributing

We welcome contributions to enhance CamSniff. Please submit issues or pull requests to collaborate.

### Guidelines for New Contributors

1. **Fork the Repository**  
   Start by forking the CamSniff repository to your GitHub account.

2. **Clone the Repository**  
   Clone the forked repository to your local machine:

   ```bash
   git clone https://github.com/John0n1/CamSniff.git
   cd CamSniff
   ```

3. **Create a New Branch**  
   Create a new branch for your feature or bug fix:

   ```bash
   git checkout -b camsniff-feature
   ```

4. **Make Changes**  
   Make your changes to the codebase. Ensure that your code follows the project's coding style and conventions.

5. **Commit Changes**  
   Commit your changes with a descriptive commit message:

   ```bash
   git commit -m "Add camsniff-feature"
   ```

6. **Push Changes**  
   Push your changes to your forked repository:

   ```bash
   git push origin feature-name
   ```

7. **Create a Pull Request**  
   Open a pull request from your forked repository to the main CamSniff repository. Provide a detailed description of your changes and any relevant information.

---

## Acknowledgments

We extend our thanks to the open-source projects that underpin CamSniff's capabilities.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

This tool is intended for educational and research purposes only. Use it responsibly and ensure you have permission to scan and analyze any network or device. The authors are not responsible for any misuse. ⚠️

---