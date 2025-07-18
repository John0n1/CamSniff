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

- **Enhanced Camera Identification**  
  Advanced fingerprinting of IP cameras with brand detection (Hikvision, Dahua, Axis, etc.)

- **Network Scanning**  
  Identify active devices using tools like `fping`, `arp-scan`, `masscan`, `nmap`, `onesixtyone`, and more.

- **Protocol Support**  
  Scan and analyze RTSP, HTTP, CoAP, RTMP, and HLS protocols with enhanced detection methods.

- **Structured Output & Reporting**  
  - JSON and text-based summary reports
  - Organized output directories with logs, screenshots, and analysis
  - Real-time camera discovery tracking

- **Brute-Forcing**  
  - Credentials brute-forcing with `hydra` and `medusa`.
  - Directory brute-forcing with `gobuster`.

- **Vulnerability Analysis**  
  Automated checks for known CVEs based on device information.

- **Enhanced AI-Based Insights**  
  - Detect IR spots and motion areas in camera streams using OpenCV
  - Brightness analysis for night vision detection
  - Comprehensive image analysis with structured output

- **Advanced Stream Management**  
  - Enhanced mosaic view with camera information overlay
  - Optimal grid layouts for multiple cameras
  - Real-time camera feed management

- **Automation & Command Line Options**  
  - Full automation mode for unattended scanning
  - Custom target subnet specification
  - Quiet mode and skip prompts options

- **Plugin Support**  
  Extend functionality with custom Bash or Python scripts in the `plugins` directory.

---

## Requirements

CamSniff is designed for Linux systems, especially Debian-based distributions (e.g., Kali Linux). All dependencies are installed automatically when you run the script.

The following tools and libaries make up the core functionality of CamSniff. A big thanks to the developers of these tools for their contributions to the open-source community.

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

Simply run the main script "`camsniff.sh`" with root privileges to start the interactive mode:

```bash
sudo ./camsniff.sh
```
If you install the DEB package, you can use the command:

```bash
sudo camsniff
```

## Enhanced Output and Reporting

CamSniff 1.0.1 now provides comprehensive structured output and reporting:

### Output Directory Structure
```
/tmp/camsniff_results_YYYYMMDD_HHMMSS/
├── logs/           # Scan logs and debug information
├── screenshots/    # Camera snapshots with AI analysis
└── reports/        # Summary reports and structured data
    ├── summary_YYYYMMDD_HHMMSS.txt    # Human-readable summary
    ├── summary_YYYYMMDD_HHMMSS.json   # Machine-readable summary
    ├── cameras.json                    # Detailed camera information
    └── analysis_IP.json               # Per-camera AI analysis
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

CamSniff uses `camcfg.json` for scanning parameters. Example:

```json
{
  "sleep_seconds": 45,
  "nmap_ports": "1-65535",
  "masscan_rate": 20000,
  "hydra_rate": 16,
  "max_streams": 4,
  "cve_github_repo": "https://api.github.com/repos/CVEProject/cvelistV5/contents/cves",
  "cve_cache_dir": "/tmp/cve_cache",
  "cve_current_year": "2025",
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

- **Network Issues:**  
  If you encounter network-related issues, ensure that your network connection is stable. You can also try restarting your network interface or router.

- **Error Messages:**  
  If you receive error messages during the scanning process, check the logs for detailed information. The logs are stored in `.log` files in the current directory.

---

## Contributing

Contributions are welcome! Please submit issues or pull requests to help improve CamSniff.

### Guidelines for New Contributors

1. **Fork the Repository**  
   Start by forking the CamSniff repository to your GitHub account.

2. **Clone the Repository**  
   Clone the forked repository to your local machine:

   ```bash
   git clone https://github.com/John0m1/CamSniff.git
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

Thanks to the other open-source projects that make CamSniff possible.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

This tool is intended for educational and research purposes only. Use it responsibly and ensure you have permission to scan and analyze any network or device. The authors are not responsible for any misuse. ⚠️

---

