# Changelog

This file summarizes user-visible releases. Debian-specific release history is
retained in `debian/changelog`.

## 2.3.0 — 2026-09-22

CamSniff 2.3.0 changes the scanner from a collection of independent heuristics
into an evidence-driven network-video identification engine. Discovery,
target selection, protocol verification, vendor resolution, and reporting now
share structured evidence instead of maintaining competing scoring models.

### Evidence and adaptive targeting

- Add inspectable positive and negative evidence to every confidence result.
- Use one canonical confidence engine for both smart targeting and final output.
- Plan HTTP, ONVIF, and streaming follow-ups per host from available evidence.
- Suppress common port-collision false positives with conservative application
  fingerprints while allowing verified camera evidence to outweigh them.

### Protocol intelligence

- Add bounded native RTSP `OPTIONS` and `DESCRIBE` identification.
- Parse RTSP server headers, supported methods, authentication challenges, and
  SDP session/media metadata without authenticating or starting playback.
- Expand ONVIF enumeration to device identity, services, capabilities, scopes,
  network interfaces, hardware identity, and time configuration.
- Parse ONVIF SOAP documents safely and independently of namespace prefixes.

### Vendor fingerprints

- Introduce declarative YAML fingerprint modules for correlating OUI, HTTP,
  ONVIF, RTSP, SSDP, and observed-path evidence.
- Ship initial narrow modules for Axis, Dahua, and Hikvision.
- Retain the CSV catalogue for compatibility and endpoint candidate data.
- Keep ports as supporting information only; a shared port cannot establish a
  vendor identity.

### Safety and compatibility

- Cap native RTSP responses at 64 KiB and ONVIF responses at 128 KiB.
- Limit ONVIF enumeration to six requests and stop immediately on an
  authentication challenge.
- Preserve discovery schema version 2 and all existing top-level confidence
  fields; new evidence, score subtotals, and probe plans are additive.
- Add PyYAML dependencies to source, Debian, Arch, and CI packaging metadata.

### Validation

- Expand the focused regression suite from 15 tests in 2.2.6 to 35 tests.
- Add fake RTSP server integration coverage, ONVIF request-budget tests,
  preliminary/final scoring parity, negative evidence, adaptive planning, and
  malformed fingerprint-module handling.
- Build and validate native Debian and Arch packages in GitHub Actions.

## 2.2.6 — 2026-08-18

CamSniff 2.2.6 is a security and correctness release centered on a simple
guarantee: discoveries and follow-up probes must remain inside the operator's
declared IPv4 scope. It also makes scan evidence more trustworthy, hardens
credential handling, and adds first-class Arch Linux packaging.

### Highlights

- Strict end-to-end target containment for active and passive discovery.
- More accurate camera classification with fewer port-only false positives.
- Safer credential validation and credential-free rendered reports.
- Native, CI-tested packages for Debian-family and Arch Linux systems.

### Security and scope

- Enforce the selected IPv4 target set before accepting discoveries or issuing
  follow-up probes.
- Restrict SSDP description URLs and redirects to the authorized target set.
- Create run directories and sensitive artifacts with owner-only permissions.
- Redact passwords and URL userinfo from Markdown and HTML reports.
- Stop passing a GPG passphrase as a visible command-line argument.

### Correctness

- Parse Masscan JSON structurally and TShark output with a real CSV parser.
- Interpret captured HTTP/RTSP requests directionally and avoid promoting
  clients as camera servers.
- Preserve TCP and UDP transport/state separately in discovery and IVRE data.
- Fix RTSP/HTTP credential attempt deduplication, FFmpeg timeout compatibility,
  RTSP credential encoding, bounded probe windows, and image validation.
- Remove port-only vendor claims and evidence-free camera classifications.
- Correct Nmap/Masscan summary counters and surface Avahi failures in logs.

### Packaging and maintenance

- Add native Arch Linux package metadata and CI alongside the Debian package.
- Add regression coverage for the critical scope, parsing, integration, profile,
  report, and credential paths.
- Make CoAP support explicitly opt-in instead of building unpinned source during
  ordinary dependency setup.
- Consolidate the README and refresh the manual and detailed guides.

### Behavior and compatibility notes

- Discovery output now declares `schema_version: 2` and includes typed
  `services` entries that preserve protocol and state. The legacy `ports` list
  remains available for existing consumers.
- Packaged installations store results under `/var/lib/camsniff/results`;
  source checkouts continue to use `dev/results`.
- Masscan is optional and is disabled automatically when unavailable.
- CoAP discovery is optional and no longer builds third-party source during
  ordinary dependency setup.

### Validation

- Passed 15 focused regression tests on Debian and Arch Linux build paths.
- Passed ShellCheck, Bash syntax checks, Actionlint, package metadata checks,
  and package-content inspection.
- Completed an isolated loopback-only smoke run using real Nmap and TShark.
- Verified owner-only permissions for run directories and sensitive artifacts.

## 2.2.5 — 2026-06-18

- Harden XML parsing, repair CSV catalogue rows, improve typing/linting, and
  reorganize helper logic for maintainability.

For older releases, see [`debian/changelog`](debian/changelog).
