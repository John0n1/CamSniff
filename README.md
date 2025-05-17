# CamSniff Camera Reconnaissance

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/John0n1/CamSniff?style=flat-square&logo=github&label=Latest%20Release)](https://github.com/John0n1/CamSniff/releases/latest)
[![License](https://img.shields.io/github/license/John0n1/CamSniff?style=flat-square&logo=github)](https://github.com/John0n1/CamSniff/blob/main/LICENSE)


CamSniff is a powerful reconnaissance tool designed for security professionals and researchers. It focuses on identifying and analyzing IP cameras and other network devices, providing insights into their configurations, vulnerabilities, and potential security risks. It combines network scanning, protocol analysis, and brute-forcing techniques to gather information about devices on a network aswell as displaying their streams in a mosaic view. The tool is designed to be user-friendly and extensible, allowing users to add custom scripts and plugins for additional functionality.

## Features

- **Network Scanning**: Identifies active devices using `fping`, `arp-scan`, `masscan`, `nmap`, `onesixtyone` and more.
- **Protocol Support**:
  - RTSP, HTTP, CoAP, RTMP, and HLS.
- **Brute-Forcing**:
  - Credentials brute-forcing using `hydra` and `medusa`.
  - Directory brute-forcing using `gobuster`.
- **Vulnerability Analysis**:
  - Checks for known CVEs based on device information.
- **AI-Based Insights**:
  - Detects IR spots and other patterns in camera streams using OpenCV.
- **Stream Management**:
  - Displays camera streams in a mosaic view using `ffmpeg` and `ffplay`.
- **Plugin Support**:
  - Extend functionality with custom scripts in the `plugins` directory.

## Requirements

CamSniff is designed for Linux systems and will automatically install the required dependencies listed below. It is recommended to run the tool on a Debian-based distribution (e.g., Ubuntu) for optimal compatibility.

- **Core Tools**: `bash`, `curl`, `jq`, `nc`, `ffmpeg`, `ffplay`
- **Network Tools**: `fping`, `masscan`, `nmap`, `hydra`, `tcpdump`, `tshark`, `arp-scan`
- **Python**: `python3`, `python3-venv`, `python3-pip`, `opencv-python`
- **Other Tools**: `gobuster`, `medusa`, `onesixtyone`, `coap-client`, `rtmpdump`

All dependencies are automatically installed when running the script.

## Installation

### RECOMMENDED: Install the DEB package from the releases page for easy installation and updates.

Alternatively, you can install CamSniff from the source code. Follow these steps to set up the tool on your system:

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
   ./launch.sh
   ```

## Usage

1. **Launch the Tool**:
   Run `launch.sh` to start the tool. It will display an introduction and prompt you to begin scanning.

2. **Scanning**:
   - The tool will scan your network for active devices and identify cameras.
   - It will analyze camera streams and display them in a mosaic view.

3. **Plugins**:
   - Add custom scripts to the `plugins` directory to extend functionality.
   - Supported formats: `.sh` (Bash) and `.py` (Python).

4. **Logs**:
   - Logs are stored in `.log` files for debugging and analysis.

## Configuration

The tool uses a configuration file `camcfg.json` to define scanning parameters. Below is an example configuration:
Thanks to [CamioCam]( https://github.com/CamioCam) for sharing the RTSP paths and CVE database. ⭐
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

## Troubleshooting

- **Missing Dependencies**:
  If any dependencies are missing, the tool will attempt to install them automatically. Ensure you run the script as root (`sudo`).

- **RTSP Paths Not Found**:
  Ensure the `dynamic_rtsp_url` in `camcfg.json` points to a valid CSV file containing RTSP paths.

- **Permission Issues**:
  Run the tool as root to ensure it has the necessary permissions for network scanning and dependency installation.

## Contributing

Contributions are welcome! Feel free to submit issues or pull requests to improve the tool.

## Acknowledgments
Thanks to [CamioCam]( https://github.com/CamioCam) for sharing the RTSP paths and CVE database. ⭐
Thanks to [OpenCV](https://opencv.org/) for providing the computer vision library used for analyzing camera streams. ⭐
Thanks to [FFmpeg](https://ffmpeg.org/) for providing the multimedia framework used for handling video streams. ⭐
Thanks to [Hydra]( https://github.com/vanhauser-thc/hydra) for providing the password cracking tool. ⭐ 
Thanks to [Gobuster]( https://github.com/OJ/gobuster) for providing the directory brute-forcing tool. ⭐
Thanks to [Masscan]( https://github.com/robertdavidgraham/masscan) for providing the fast network scanner. ⭐
Thanks to [Nmap]( https://nmap.org/) for providing the network exploration tool. ⭐
Thanks to [tcpdump](https://www.tcpdump.org/) for providing the packet analyzer. ⭐
Thanks to [TShark](https://www.wireshark.org/) for providing the network protocol analyzer. ⭐
Thanks to [Arp-scan]( https://nmap.org/arp-scan/) for providing the network scanner. ⭐
Thanks to [CoAP](https://coap.technology/) for providing the Constrained Application Protocol. ⭐
Thanks to [RTMPDump](https://rtmpdump.mplayerhq.hu/) for providing the RTMP streaming tool. ⭐

And all the other open-source projects that have contributed to the development of this tool. ⭐

## Disclaimer 
This tool is intended for educational and research purposes only. Use it responsibly and ensure you have permission to scan and analyze any network or device. The authors are not responsible for any misuse or illegal activities conducted with this tool. Always follow ethical guidelines and legal regulations when using security tools. ⚠️ 

## Contact
For any questions, suggestions, or issues, please contact the author at john@on1.no

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
