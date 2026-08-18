# Security policy

CamSniff performs network discovery, credential validation, packet capture, and
media acquisition. A vulnerability can therefore affect both scanned devices
and the operator's sensitive result data. Please report security issues
privately and avoid testing against systems you do not own or have explicit
permission to assess.

## Supported versions

| Version | Security support |
| --- | --- |
| Latest tagged release | Supported |
| `main` | Best-effort pre-release support |
| Older releases | Not supported; reproduce on the latest release first |

Security fixes are normally released from the newest maintained version rather
than backported to older packages.

## Reporting a vulnerability

Use GitHub's
[private vulnerability reporting](https://github.com/John0n1/CamSniff/security/advisories/new).
Do not open a public issue for a suspected vulnerability.

Include as much of the following as is safe to share:

- The affected CamSniff version, commit, and installation method.
- Operating system and relevant dependency versions.
- Impact and the security boundary that is crossed.
- Minimal reproduction steps using loopback, synthetic data, or an isolated
  authorized lab.
- Whether credentials, packet captures, device images, or target identifiers
  may be present in the report.
- A suggested remediation, if known.

Do not include live credentials, access tokens, private keys, unrestricted
packet captures, or third-party target details. State that sensitive evidence
exists and coordinate a safer transfer method with the maintainer.

## What to expect

The maintainer will review reports on a best-effort basis, confirm the affected
scope, and coordinate remediation and disclosure with the reporter. Response
and release timing depends on severity, reproducibility, and maintainer
availability. Please allow a reasonable remediation period before disclosure.

## Scope

Examples of issues that should be reported privately include:

- Escaping the declared target scope or probing an unintended host.
- Command, argument, template, CSV, JSON, XML, or report injection.
- Credential or sensitive artifact disclosure.
- Unsafe permissions, predictable paths, symlink attacks, or archive handling.
- SSRF or redirect behavior that reaches an unauthorized destination.
- A package or workflow vulnerability introduced by this repository.

General hardening suggestions without a demonstrated security impact may be
opened as regular issues. Vulnerabilities that exist solely in Nmap, Masscan,
TShark, FFmpeg, IVRE, or another upstream dependency should be reported to that
project; report them here as well only when CamSniff exposes or amplifies the
issue in a project-specific way.

## Safe research

Use only systems you own or are authorized to test. Minimize collection, redact
evidence, and delete sensitive artifacts when they are no longer needed. The
project does not authorize testing against any third-party system.
