## Customisation hints

- Extend `data/catalog/paths.csv` with new vendor fingerprints, CVE IDs, default credentials, and snapshot/stream templates.
- Update `data/dictionaries/usernames.txt` and `data/dictionaries/passwords.txt` to broaden credential probing.
- Swap in an alternate RTSP dictionary by editing `data/protocols/rtsp-url-brute.nse` or passing `rtsp-url-brute.urlfile=<path>` through the Nmap script arguments (see comments in the script).
- Modes, timeouts, and credential limits are centralised in `scripts/core/mode-config.sh`.
- Protocol heuristics for ONVIF/RTMP/HLS/WebRTC/SRT are implemented in `scripts/camsniff.sh` under `probe_additional_protocols`; adjust or extend them there.

## IVRE Integration

CamSniff includes full integration with [IVRE](https://ivre.rocks), an open-source network reconnaissance framework that stores scan results in MongoDB for advanced querying, analysis, and visualization.

### Features

The IVRE integration provides:

- **Fully automatic setup**: MongoDB and IVRE are installed and configured automatically when using `--extra ivre`
- **Automated schema mapping**: Discovery data is automatically converted to IVRE's Nmap-compatible format
- **Vendor enrichment**: MAC address-based vendor identification from `data/catalog/paths.csv`
- **Credential tracking**: Successful authentication attempts are tagged and searchable
- **Thumbnail references**: Links to captured camera snapshots are stored in host metadata
- **CVE tracking**: Known vulnerabilities are associated with discovered cameras
- **Protocol categorization**: Cameras are tagged by supported protocols (RTSP, ONVIF, CoAP, WebRTC, SRT)

### Automatic Usage

Simply add `--extra ivre` to any CamSniff scan:

```bash
sudo scripts/camsniff.sh --mode medium --extra ivre --yes
```

CamSniff will automatically:
1. Check if IVRE is installed
2. Install MongoDB if needed
3. Create Python virtual environment
4. Install IVRE Python packages
5. Initialize IVRE databases
6. Sync discovery results after the scan

No additional configuration is required!

### Manual Operations

The unified IVRE manager handles all operations:

```bash
# Check IVRE status
scripts/integrations/ivre-manager.sh check

# Manual setup (if needed)
sudo scripts/integrations/ivre-manager.sh setup

# Ingest specific run
scripts/integrations/ivre-manager.sh ingest dev/results/20251010T215139Z/discovery.json

# Bulk ingest all historical runs
scripts/integrations/ivre-manager.sh bulk-ingest

# Show summary statistics
scripts/integrations/ivre-manager.sh summary

# Export results
scripts/integrations/ivre-manager.sh export json > cameras.json
scripts/integrations/ivre-manager.sh export csv > cameras.csv
```

### Querying IVRE Data

Use the query helper for common analysis:

```bash
# Use the original query script for detailed analysis
scripts/ivre-query.sh summary
scripts/ivre-query.sh vendors
scripts/ivre-query.sh credentials
scripts/ivre-query.sh dashboard
```

Or access IVRE directly:

```bash
source venv/bin/activate

# Show all CamSniff discoveries
ivre scancli --category camsniff

# Filter by vendor
ivre scancli --category vendor:hikvision

# Show cameras with credentials
ivre scancli --category credentials-found

# Export to JSON
ivre scancli --category camsniff --json > all_cameras.json
```

### IVRE Web Interface

Launch the web interface for interactive exploration:

```bash
scripts/ivre-query.sh web
# Or directly:
source venv/bin/activate
ivre httpd
```

Access at `http://localhost:8080` to view interactive maps, statistics, and detailed host information.

### Schema Details

CamSniff maps discovery data into IVRE with these fields:

**Host-level scripts:**
- `camsniff-summary`: Mode, network, sources, vendor, credentials, protocols
- `camsniff-vendor`: Company, model, CVEs, credentials (if found)
- `camsniff-protocols`: List of detected protocols (ONVIF, CoAP, etc.)
- `camsniff-rtsp-responses`: RTSP probe results

**Categories (tags):**
- `camsniff`: All CamSniff hosts
- `camsniff-mode:<name>`: Hosts discovered in specific mode
- `vendor:<company>`: Hosts from specific vendor
- `credentials-found`: Hosts with successful authentication

**Credential structure:**
```json
{
  "username": "admin",
  "password": "12345",
  "method": "rtsp",
  "rtsp_url": "rtsp://...",
  "http_url": "http://...",
  "thumbnail": "/path/to/snapshot.jpg"
}
```

### Troubleshooting

**Check IVRE status:**
```bash
scripts/integrations/ivre-manager.sh check
```

**Re-setup IVRE:**
```bash
sudo scripts/integrations/ivre-manager.sh setup
```

**View sync logs:**
```bash
tail -f dev/results/*/logs/ivre-sync.log
```

**Clear all CamSniff data:**
```bash
source venv/bin/activate
ivre scancli --category camsniff --delete
```
