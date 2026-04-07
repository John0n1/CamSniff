# Mode Reference

CamSniff ships with six scanning modes that tune every aspect of the scan from
timing and port breadth to credential attempt limits and passive probe toggles.
Select a mode with `--mode <name>`.

---

## Quick reference

| Mode         | Masscan | Nmap timing | Creds cap | TShark (s) | ONVIF/SSDP | Best for |
|--------------|---------|-------------|-----------|------------|------------|----------|
| `stealth+`   | no      | -T1         | 16        | 15         | off        | Maximum stealth, minimal footprint |
| `stealth`    | no      | -T2         | 32        | 20         | off        | Quiet scans with low detection risk |
| `medium`     | yes     | -T4         | 64        | 35         | on         | Default — balanced speed and coverage |
| `aggressive` | yes     | -T4         | 96        | 45         | on         | Richer banner/script output |
| `war`        | yes     | -T5         | 128       | 55         | on         | Broad vendor sweep across large networks |
| `nuke`       | yes     | -T5         | 256       | 75         | on         | Full port range, vuln scripts, deepest scan |

All modes add `-Pn -n` to Nmap (skip ping + skip DNS resolution) to ensure
firewalled cameras are still scanned and lookups don't slow down discovery.

---

## stealth+

**Alias**: `stealth-plus`

The slowest and least detectable mode. Adds a 200 ms scan delay between probes
and limits credential attempts to 16. Intended for high-security environments
where any anomalous traffic is a concern.

```
--mode stealth+
```

| Setting | Value |
|---------|-------|
| Masscan | disabled |
| Nmap timing | -T1 |
| Nmap extra | `--scan-delay 200ms` |
| Nmap max-retries | 1 |
| Version intensity | 1 |
| Port profile | `minimal` (80, 554) |
| Max credentials | 16 |
| TShark duration | 15 s |
| ONVIF probe | off |
| SSDP sweep | off |
| HTTP metadata | off |
| Follow-up service scan | off |

---

## stealth

Quiet but functional. Scans the core camera port set (HTTP + RTSP + HTTPS) at
Nmap T2 timing without Masscan acceleration. Suitable for production network
segments where noise must be kept low.

```
--mode stealth
```

| Setting | Value |
|---------|-------|
| Masscan | disabled |
| Nmap timing | -T2 |
| Nmap extra | – |
| Nmap max-retries | 1 |
| Version intensity | 2 |
| Port profile | `core` (80, 443, 554) |
| Max credentials | 32 |
| TShark duration | 20 s |
| ONVIF probe | off |
| SSDP sweep | off |
| HTTP metadata | off |
| Follow-up service scan | off |

---

## medium *(default)*

The recommended starting point. Combines Nmap T4 with Masscan at 1,000 pps,
adds lightweight NSE scripts (`banner`, `http-title`) for device fingerprinting,
and enables ONVIF, SSDP, HTTP metadata, and follow-up UDP scans.

```
--mode medium    # or omit --mode entirely
```

| Setting | Value |
|---------|-------|
| Masscan | enabled, 1,000 pps, wait 3 s |
| Nmap timing | -T4 |
| Nmap extra | `--script banner,http-title` |
| Nmap max-retries | 2 |
| Version intensity | 5 |
| Port profile | `standard` |
| Max credentials | 64 |
| TShark duration | 35 s |
| ONVIF probe | on |
| SSDP sweep | on |
| HTTP metadata | on |
| Follow-up service scan | on |

---

## aggressive

Increases version detection intensity and enables the full Nmap default script
set for richer banner, auth, and service fingerprinting. Masscan runs at 5,000
pps. Well-suited for scheduled audits of known camera segments.

```
--mode aggressive
```

| Setting | Value |
|---------|-------|
| Masscan | enabled, 5,000 pps, wait 5 s |
| Nmap timing | -T4 |
| Nmap extra | `--script default` |
| Nmap max-retries | 3 |
| Version intensity | 7 |
| Port profile | `extended` |
| Max credentials | 96 |
| TShark duration | 45 s |
| ONVIF probe | on |
| SSDP sweep | on |
| HTTP metadata | on |
| Follow-up service scan | on |

---

## war

Maximum speed without a full port sweep. Masscan runs at 12,000 pps with a 7 s
wait to catch late responders. Nmap enforces a 100 pps minimum rate alongside
T5 timing. The port profile covers all major vendor-specific ports including
Hikvision (8899), Dahua (34567), Axis (4520), and Reolink (8787).

```
--mode war
```

| Setting | Value |
|---------|-------|
| Masscan | enabled, 12,000 pps, wait 7 s |
| Nmap timing | -T5 |
| Nmap extra | `--script default` |
| Nmap max-retries | 3 |
| Nmap min-rate | 100 pps |
| Version intensity | 8 |
| Port profile | `war` |
| Max credentials | 128 |
| TShark duration | 55 s |
| ONVIF probe | on |
| SSDP sweep | on |
| HTTP metadata | on |
| Follow-up service scan | on |

---

## nuke

**Aliases**: `full`, `total`

Full spectrum scan: ports 1–65535, Masscan at 20,000 pps, Nmap vulnerability
scripts, version intensity 9 (all probes), and 256 credential attempts per host.
Use only on networks you are explicitly authorised to test.

```
--mode nuke
```

| Setting | Value |
|---------|-------|
| Masscan | enabled, 20,000 pps, wait 10 s |
| Nmap timing | -T5 |
| Nmap extra | `--script vuln,default` |
| Nmap max-retries | 4 |
| Nmap min-rate | 200 pps |
| Version intensity | 9 |
| Port profile | `total` (1–65535) |
| Max credentials | 256 |
| TShark duration | 75 s |
| ONVIF probe | on |
| SSDP sweep | on |
| HTTP metadata | on |
| Follow-up service scan | on |

---

## Choosing a mode

```
Low noise / high stealth ───────────────────────────────────► High coverage
stealth+   stealth   medium (default)   aggressive   war   nuke
```

- Start with **medium** on an unknown network.
- Use **stealth/stealth+** when scanning monitored production environments.
- Use **aggressive** for a scheduled audit where speed matters more than silence.
- Use **war** for large /16+ address spaces or dense camera deployments.
- Use **nuke** only in lab or fully authorised red-team contexts — it is loud,
  fast, and exhaustive.

---

## Overriding mode settings

Any mode variable can be overridden by exporting it before launching CamSniff:

```bash
# Use medium mode but increase Masscan rate
export CAM_MODE_MASSCAN_RATE=8000
sudo camsniff --mode medium

# Reduce credential attempts in war mode
export CAM_MODE_MAX_CREDENTIALS=32
sudo camsniff --mode war

# Disable OS detection for faster scanning
export CAM_MODE_NMAP_OSSCAN_ENABLE=false
sudo camsniff --mode aggressive
```

See [scanning.md](scanning.md) for a full list of tunable variables.
