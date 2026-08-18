# Customization and IVRE

CamSniff keeps scanner behavior in code and device knowledge in data files.
Prefer data changes when adding a vendor or endpoint; change probe logic only
when the evidence model itself needs to change.

## Vendor catalogue

`data/catalog/paths.csv` is the cross-vendor catalogue used for profile
matching. Rows may include company/model labels, OUI expressions, service
ports, default credentials, RTSP/HTTP templates, ONVIF paths, and CVE IDs.

A port is supporting evidence only. Vendor identity must come from stronger
signals such as OUI, banner content, or an observed vendor-specific path. Keep
CVE associations model-specific and verifiable.

After editing the catalogue, validate enrichment with:

```bash
python3 scripts/helpers/profile_resolver.py catalog \
  --paths data/catalog/paths.csv \
  --output /tmp/camsniff-catalog.json
make test
```

## Endpoint dictionaries

Generic dictionaries live in `data/dictionaries/`:

- `rtsp-urls.txt` — relative RTSP paths used by the NSE probe.
- `http-paths.txt` — fallback HTTP snapshot templates.
- `usernames.txt` and `passwords.txt` — bounded credential candidates.

Vendor-specific endpoint templates live under `data/vendors/<vendor>/`.

```text
# HTTP
template|port|channel|stream|label

# RTSP
template|port|channel|stream|transport|label
```

Templates support `{{ip_address}}`, `{{username}}`, `{{password}}`, `{{port}}`,
`{{channel}}`, and `{{stream}}`. Credential values inserted into RTSP userinfo
are URL-encoded before use. Keep dictionaries conservative: every additional
path or credential expands traffic and runtime.

## Modes and port profiles

- `scripts/core/mode-config.sh` owns rates, retries, timeouts, and feature flags.
- `scripts/core/port-profiles.sh` owns named TCP/Masscan port sets.

Mode variables form an internal interface and may replace values inherited from
the environment. Make changes in the resolver, then run `make test` and an
isolated loopback smoke run.

## IVRE integration

Enable IVRE for a scan with:

```bash
sudo camsniff --mode medium --extra ivre
```

This invokes `scripts/integrations/ivre-manager.sh`, which manages the Python
environment, MongoDB readiness, and ingestion. IVRE setup changes local system
state and should be reviewed before use.

Supported manager commands:

```bash
# Readiness check
scripts/integrations/ivre-manager.sh check

# Explicit setup
sudo scripts/integrations/ivre-manager.sh setup

# Ingest one discovery dataset
scripts/integrations/ivre-manager.sh ingest /path/to/discovery.json

# Ingest source-tree history
scripts/integrations/ivre-manager.sh bulk-ingest

# Query/export CamSniff records
scripts/integrations/ivre-manager.sh summary
scripts/integrations/ivre-manager.sh export json > cameras.json
scripts/integrations/ivre-manager.sh export csv > cameras.csv
```

Discovery schema version 2 service entries retain their TCP/UDP transport and
state when mapped into IVRE. Successful credentials are read from the nested
`credentials` and `artifact` structures used by `credentials.json`.

IVRE records can contain credential material. Restrict MongoDB access and treat
exports with the same care as the original run directory.

## Troubleshooting IVRE

```bash
scripts/integrations/ivre-manager.sh check
tail -f dev/results/*/logs/ivre-sync.log
```

Packaged installations store ordinary scan output under
`/var/lib/camsniff/results/`; pass an explicit discovery path to `ingest` when
working outside a source checkout.
