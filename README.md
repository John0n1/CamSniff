# CamSniff v5.5.2

CamSniff is a powerful, all-in-one network camera reconnaissance tool for security pros and enthusiasts. It combines advanced host/port discovery, protocol support, credential brute-forcing, CVE lookup, AI-assisted frame analysis, and interactive/mosaic video display.

---

## 📁 Repository Structure

```

CamSniff/
├── LICENSE
├── .gitignore
├── README.md            ← (this file)
├── Linux/               ← Linux (Bash) edition
│   ├── camsniff.sh
│   ├── setup.sh
│   ├── install\_deps.sh
│   ├── env\_setup.sh
│   ├── scan\_analyze.sh
│   ├── cleanup.sh
│   └── camcfg.json
└── Windows/             ← Windows (PowerShell) edition
├── camsniff.ps1
├── setup.ps1
├── install\_deps.ps1
├── env\_setup.ps1
├── scan\_analyze.ps1
├── cleanup.ps1
└── config.json

````

---

## 🚀 Features

- **Cross-Platform**  
  - **Linux**: Modular Bash scripts  
  - **Windows**: Pure PowerShell modules  
- **Auto Dependency Management**  
  - Linux: `apt` + Python venv  
  - Windows: Chocolatey + Python venv  
- **Dynamic Scanning**: Passive taps, `fping`, `masscan`, `nmap`  
- **Protocols**: RTSP, HTTP/S, ONVIF, SSDP, SNMP, CoAP, RTMP, HLS, MQTT  
- **Brute-Force**: Hydra-based for RTSP & HTTP  
- **Vuln Lookup**: Local CVE JSON database  
- **AI Analysis**: IR-spot & frame analysis via OpenCV  
- **Interactive TUI**: `fzf` selection  
- **Mosaic Viewer**: `ffmpeg` + `ffplay`  

---

## ⚙️ Configuration

- **Linux**: `Linux/camcfg.json`  
- **Windows**: `Windows/config.json`

If missing, a default config is created on first run.

```json
{
  "sleep_seconds": 45,
  "nmap_ports": "1-65535",
  "masscan_rate": 20000,
  "hydra_rate": 16,
  "max_streams": 4,
  "cve_db": "/path/to/cve-2025.json",      // Linux: /usr/share/cve/...  Windows: C:\cve\...
  "dynamic_rtsp_url": "https://raw.githubusercontent.com/maaaaz/michelle/master/rtsp.txt"
}
````

Adjust values and re-run; changes apply on next sweep.

---

## 💻 Installation & Usage

### Linux (Debian-based)

```bash
git clone https://github.com/John0n1/CamSniff.git
cd CamSniff/Linux
chmod +x setup.sh install_deps.sh env_setup.sh scan_analyze.sh cleanup.sh camsniff.sh
sudo ./camsniff.sh
```

* Follow the Y/N prompt to start.
* **Ctrl+C** to stop (auto-cleanup runs).

### Windows (PowerShell)

1. **Clone & navigate**

   ```powershell
   git clone https://github.com/John0n1/CamSniff.git
   cd CamSniff\Windows
   ```
2. **Unblock & run (Admin)**

   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   Unblock-File *.ps1
   .\camsniff.ps1
   ```

   * First run auto-installs: Chocolatey, nmap, masscan, ffmpeg, Python venv, etc.
   * Press **Y** to begin scanning.
   * **Ctrl+C** to exit (auto-cleanup kills child processes).


---

## ⚠️ Disclaimer

For educational and ethical use only. Unauthorized scanning or exploitation without permission is illegal. Use responsibly.

---

## 📄 License

This project is released under the [MIT License](https://opensource.org/licenses/MIT).

---

## 👤 Author

Developed by [John0n1](https://github.com/John0n1).
