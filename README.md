# CamSniff
A stealthy local network **IP camera & IoT device detection** and **monitoring** tool for Linux.  
Designed for Debian 12 or similar systems with the [PEP 668 “externally-managed environment”](https://peps.python.org/pep-0668/) restrictions in mind — **no** system-wide pip installations required.

`camsniff.sh` combines **passive** sniffing (ARP, DHCP, SSDP/mDNS, DNS) with **selective active** scans (ARP-scan, Nmap, RTSP path checks, ONVIF WS-Discovery) to quietly find IP cameras, NVR/DVR boxes, and doorbell cams on your local LAN. It also gathers banners, checks for suspicious DNS queries (phone-home cloud domains), and logs everything for later review.

![camsniff_logo](https://github.com/user-attachments/assets/7de852a5-cb14-478d-91d5-2d6f604eedcd)

# Features

- **Passive Sniffing**  
  - Captures ARP & DHCP traffic, revealing new devices as soon as they connect.  
  - Sniffs SSDP/mDNS/ONVIF multicast for cameras that announce themselves.  
  - Monitors DNS queries to detect cameras phoning home.  

- **Active Recon**  
  - **ARP Sweep** (via `arp-scan`) to find live hosts (cannot be blocked by normal firewalls).  
  - **Stealthy Nmap** scanning common camera ports: 80, 443, 554, 8080, 8554, 8000, 37777, 5000, etc.  
  - **RTSP Path Brute Force** using `ffprobe` to discover video streams or confirm correct stream paths.  
  - **ONVIF WS-Discovery** to identify ONVIF-compatible cameras (via Python venv).  

- **Fingerprinting & Logging**  
  - HTTP banner grabbing & screenshots (with `curl` and `cutycapt`).  
  - MAC vendor lookups (via `arp-scan`).  
  - Suspicious DNS domain detection (optional).  
  - Neatly logs all findings and saves `.pcap` captures for later analysis.  

- **PEP 668–Friendly**  
  - Automatically sets up a local **Python virtual environment** (`./camsniff_venv`) for required Python packages (`wsdiscovery`, `scapy`, `onvif-zeep`) so it **does not** conflict with system Python packages on Debian 12 or similar.  

# Quick Start

1. **Clone or Download** this repo:
   ```bash
   git clone https://github.com/John0n1/CamSniff.git
   cd CamSniff
   ```

2. **Make the script executable**:
   ```bash
   chmod +x camsniff.sh
   ```

3. **Run as root** (required for sniffing, ARP scanning, etc.):
   ```bash
   sudo ./camsniff.sh
   ```
   - If needed, your system will prompt for the root password or `sudo` password.

4. **Watch it go**:
   - The script will create a local folder **`watchtower_venv/`** and install Python dependencies there.  
   - It will create or use subfolders `logs/`, `captures/`, `screenshots/`.  
   - Then it continuously loops, capturing passive data and performing spaced-out active scans.  

# Dependencies & Environment

- **Debian/Ubuntu** or similar apt-based system recommended.  
- The script installs these packages if missing (no pip system-wide installs):  
  - `tcpdump`, `tshark`, `nmap`, `arp-scan`, `avahi-utils`, `ffmpeg`, `curl`, `jq`, `cutycapt`, `python3`, `python3-venv`  
- A local Python virtual environment (`watchtower_venv`) is created to install:
  - `wsdiscovery`  
  - `scapy`  
  - `onvif-zeep`

# Files & Output

- **`logs/`**:  
  - `camsniff.log`: general script log  
  - `arp_scan.log`: results of `arp-scan`  
  - `live_hosts.txt`: list of currently alive IP addresses  
  - `nmap_scan.xml`: Nmap scan results in XML format  
  - `found_streams.log`: discovered RTSP streams  
  - `http_banners.log`: HTTP banner and title info  
  - `onvif_devices.log`: results of ONVIF WS-Discovery  
  - `mac_vendors.log`: appended MAC vendor info from `arp-scan`  
  - `dns_suspicious.log`: if a suspicious domain is detected in DNS queries  

- **`captures/`**:  
  - `arp_dhcp.pcap`: raw ARP/DHCP traffic  
  - `multicast.pcap`: SSDP, mDNS, ONVIF discovery traffic  
  - `dns_queries.pcap`: DNS query captures  

- **`screenshots/`**:  
  - Contains PNG screenshots of camera web interfaces (taken with `cutycapt`).  

# Customizing

- **`config.json`**: Customize settings like `SLEEP_SECONDS`, `COMMON_RTSP_PATHS`, `suspicious` domains, and `ports` for Nmap scans.
- **`SLEEP_SECONDS`** in the script controls how frequently the active scanning loop runs (default: 300s = 5 minutes).  
- **Additional RTSP Paths**: see `COMMON_RTSP_PATHS` if your camera uses special stream URLs.  
- **Suspicious DNS Patterns**: customize in `parse_dns_queries()` for your own phone-home domain checks.  
- **Ports**: to scan more or fewer ports, edit the Nmap command (`-p80,443,554,8080,8554,8000,37777,5000`).  
- **Stealth vs. Speed**: reduce or increase frequency of scans, or adjust Nmap timing from `-T2` to `-T1` or `-T4` as you prefer.  

# Known Issues

- **Older IP Cameras**: Certain cheap or ancient camera firmware can crash if scanned too aggressively. If you suspect this, consider slowing scans (`-T1`) or using smaller intervals.  
- **Multinetwork/VLAN**: If you have multiple interfaces or VLANs, you may need to run separate instances of CamSniff with `INTERFACE` set manually.  
- **Large Subnets**: For /16 or bigger networks, scanning every device can take time. Adjust intervals or break up the network by sub-ranges.  

### Disclaimer

This script is provided for **legitimate security auditing and network monitoring** on **your own** networks or those you have explicit permission to test. **Unauthorized scanning** of networks or devices may be illegal in your jurisdiction. Use responsibly.

### License

[MIT License](./LICENSE)

**Happy stealthy camera hunting!**  
Feel free to open [issues](https://github.com/John0n1/CamSniff/issues) or contribute PRs for new features or bugfixes.
