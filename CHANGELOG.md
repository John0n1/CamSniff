# Changelog

This file summarizes user-visible releases. Debian-specific release history is
retained in `debian/changelog`.

## 2.2.6 — 2026-08-18

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

## 2.2.5 — 2026-06-18

- Harden XML parsing, repair CSV catalogue rows, improve typing/linting, and
  reorganize helper logic for maintainability.

For older releases, see [`debian/changelog`](debian/changelog).
