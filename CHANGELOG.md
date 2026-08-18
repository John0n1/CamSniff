# Changelog

This file summarizes user-visible releases. Debian-specific release history is
retained in `debian/changelog`.

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
