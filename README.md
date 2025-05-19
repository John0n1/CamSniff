# CamSniff - Camera Reconnaissance 📡

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/John0n1/CamSniff?style=flat-square&logo=github&label=Latest%20Release)](https://github.com/John0n1/CamSniff/releases/latest)
[![License](https://img.shields.io/github/license/John0n1/CamSniff?style=flat-square&logo=github)](https://github.com/John0n1/CamSniff/blob/main/LICENSE)

---

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Acknowledgments](#acknowledgments)
- [License](#license)
- [Contact](#contact)
- [Disclaimer](#disclaimer)

---

## Introduction

**CamSniff** is a powerful reconnaissance tool designed for security professionals and researchers. It specializes in identifying and analyzing IP cameras and other network devices, providing deep insights into their configuration and vulnerabilities.

---

## Features

- **Network Scanning**  
  Identify active devices using tools like `fping`, `arp-scan`, `masscan`, `nmap`, `onesixtyone`, and more.

- **Protocol Support**  
  Scan and analyze RTSP, HTTP, CoAP, RTMP, and HLS protocols.

- **Brute-Forcing**  
  - Credentials brute-forcing with `hydra` and `medusa`.
  - Directory brute-forcing with `gobuster`.

- **Vulnerability Analysis**  
  Automated checks for known CVEs based on device information.

- **AI-Based Insights**  
  Detect IR spots and other patterns in camera streams using OpenCV.

- **Stream Management**  
  Display camera streams in a mosaic view using `ffmpeg` and `ffplay`.

- **Plugin Support**  
  Extend functionality with custom Bash or Python scripts in the `plugins` directory.

---

## Requirements

CamSniff is designed for Linux systems, especially Debian-based distributions (e.g., Ubuntu). All dependencies are installed automatically when you run the script.

**Core Tools:**  
`bash`, `curl`, `jq`, `nc`, `ffmpeg`, `ffplay`

**Network Tools:**  
`fping`, `masscan`, `nmap`, `hydra`, `tcpdump`, `tshark`, `arp-scan`

**Python:**  
`python3`, `python3-venv`, `python3-pip`, `opencv-python`

**Other Tools:**  
`gobuster`, `medusa`, `onesixtyone`, `coap-client`, `rtmpdump`

---

## Installation

### Recommended (DEB Package)

Download and install the latest DEB package from the [releases page](https://github.com/John0n1/CamSniff/releases/latest) for easy installation and updates.

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

1. **Launch the Tool**  
   Run `camsniff.sh` to start. An introduction will appear and you’ll be prompted to begin scanning.

2. **Scanning**  
   - Scan your network for devices and identify cameras.
   - Analyze and display camera streams in a mosaic view.

3. **Plugins**  
   - Extend functionality by adding `.sh` or `.py` scripts to the `plugins` directory.

4. **Logs**  
   - All logs are stored in `.log` files for debugging and analysis.

---

## Configuration

CamSniff uses the `camcfg.json` file for scanning parameters. Example:

```json
{
  "sleep_seconds": 45,
  "nmap_ports": "1-65535",
  "masscan_rate": 20000,
  "hydra_rate": 16,
  "max_streams": 4,
  "cve_db": "/usr/share/cve/cve-2025.json",
  "dynamic_rtsp_url": "https://github.com/CamioCam/rtsp/blob/master/cameras/paths.csv",
  "dirb_wordlist": "/usr/share/wordlists/dirb/common.txt",
  "snmp_communities": ["public", "private", "camera", "admin"],
  "medusa_threads": 8
}
```

---

## Troubleshooting

- **Missing Dependencies:**  
  The tool will try to auto-install missing dependencies. Run as root (`sudo`) to allow installations.

- **RTSP Paths Not Found:**  
  Ensure `dynamic_rtsp_url` in `camcfg.json` points to a valid RTSP paths CSV.

- **Permission Issues:**  
  Always run as root to ensure necessary permissions for network scanning and dependency installation.

---

## Contributing

Contributions are welcome! Please submit issues or pull requests to help improve CamSniff.

---

## Acknowledgments

- Thanks to [CamioCam](https://github.com/CamioCam) for RTSP paths and CVE database.
- [OpenCV](https://opencv.org/) for computer vision.
- [FFmpeg](https://ffmpeg.org/) for multimedia processing.
- [Hydra](https://github.com/vanhauser-thc/hydra), [Gobuster](https://github.com/OJ/gobuster), [Masscan](https://github.com/robertdavidgraham/masscan), [Nmap](https://nmap.org/), [tcpdump](https://www.tcpdump.org/), [TShark](https://www.wireshark.org/), [Arp-scan](https://nmap.org/arp-scan/), [CoAP](https://coap.technology/), [RTMPDump](https://rtmpdump.mplayerhq.hu/), and all other open-source projects that make CamSniff possible.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Contact

For questions, suggestions, or issues, contact the author at john@on1.no

---

## Disclaimer

This tool is intended for educational and research purposes only. Use it responsibly and ensure you have permission to scan and analyze any network or device. The authors are not responsible for any misuse. ⚠️
