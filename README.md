# CamSniff 4.10

CamSniff is a powerful, all-in-one network camera reconnaissance tool designed for security professionals and enthusiasts. It combines advanced scanning, fingerprinting, and AI-assisted analysis to identify and interact with network cameras and IoT devices.

## Features

- **Dependency Management**: Automatically installs required system dependencies and sets up a Python virtual environment.
- **Dynamic Scanning**:
  - Passive taps (ARP, mDNS/WS-Discovery).
  - Ultra-fast host/port discovery using `fping`, `masscan`, and `nmap`.
  - Dynamic RTSP path discovery.
- **Protocol Support**:
  - RTSP, HTTP, HTTPS, ONVIF, SSDP (UPnP), SNMP, CoAP, RTMP, HLS, MQTT.
- **Brute Force**: Hydra-based credential brute-forcing for RTSP and HTTP.
- **CVE Lookup**: Local database for vulnerability checks.
- **AI-Assisted Analysis**: Detects IR spots and performs frame analysis.
- **Interactive TUI**: Stream selection using `fzf`.
- **Mosaic Viewer**: Console-based video mosaic with `ffmpeg`.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/John0n1/CamSniff.git
   cd CamSniff
   ```

2. Run the script with `sudo`:
   ```bash
   sudo ./camsniff.sh
   ```

3. Follow the prompts to start scanning.

## Configuration

The script uses a `camcfg.json` file for configuration. If the file does not exist, it will be created with default values:

```json
{
  "sleep_seconds": 45,
  "nmap_ports": "1-65535",
  "masscan_rate": 20000,
  "hydra_rate": 16,
  "max_streams": 4,
  "cve_db": "/usr/share/cve/cve-2025.json",
  "dynamic_rtsp_url": "https://raw.githubusercontent.com/maaaaz/michelle/master/rtsp.txt"
}
```


## Usage

1. Start the script:
   ```bash
   sudo ./camsniff.sh
   ```

2. Follow the interactive prompts to begin scanning.

3. The script will:
   - Discover hosts and open ports.
   - Identify cameras and IoT devices.
   - Perform vulnerability checks and AI-assisted analysis.
   - Display streams in a mosaic or allow selection via TUI.

## Requirements

- **Operating System**: Linux (Debian-based distributions recommended).
- **Dependencies**: Automatically installed by the script (e.g., `fping`, `masscan`, `nmap`, `hydra`, `ffmpeg`, `python3`, etc.).

## Disclaimer

This tool is intended for educational and ethical purposes only. Unauthorized use on networks or devices without permission is illegal and unethical. Use responsibly.

## License

[MIT License](https://opensource.org/licenses/MIT)

## Author

Developed by [John0n1](https://github.com/John0n1).