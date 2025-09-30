## Customisation hints

- Extend `data/paths.csv` with new vendor fingerprints, CVE IDs, default credentials, and snapshot/stream templates.
- Update `data/usernames.txt` and `data/passwords.txt` to broaden credential probing.
- Swap in an alternate RTSP dictionary by editing `data/rtsp-url-brute.nse` or passing `rtsp-url-brute.urlfile=<path>` through the Nmap script arguments (see comments in the script).
- Modes, timeouts, and credential limits are centralised in `scripts/mode-config.sh`.
- Protocol heuristics for ONVIF/RTMP/HLS/WebRTC/SRT are implemented in `scripts/camsniff.sh` under `probe_additional_protocols`; adjust or extend them there.