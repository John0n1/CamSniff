# Contributing to CamSniff

Thanks for helping improve CamSniff. Contributions are welcome across code,
tests, documentation, packaging, protocol handling, and vendor data.

CamSniff is an authorization-sensitive reconnaissance tool. Test only against
systems you own or are explicitly permitted to assess. Never include live
credentials, tokens, private packet captures, sensitive images, or identifying
target data in an issue, commit, test fixture, or pull request.

## Before you start

- Search existing issues and pull requests before opening a new one.
- Use a GitHub issue for a reproducible bug or a scoped feature proposal.
- Report security vulnerabilities privately according to
  [SECURITY.md](SECURITY.md).
- Keep changes focused. Separate unrelated fixes into different pull requests.

For larger changes to scanning behavior, output schemas, credential probing,
or packaging, open an issue first so the design and compatibility impact can be
discussed before implementation.

## Development setup

Fork and clone the repository, then create a focused branch:

```bash
git clone https://github.com/<your-account>/CamSniff.git
cd CamSniff
git switch -c fix/short-description
```

Install project dependencies using your distribution package manager or:

```bash
make install-deps
```

The dependency installer changes the local system. Review it before running it,
especially on a development workstation. CoAP support is optional and must be
built explicitly with `make build-coap`.

## Project layout

- `scripts/camsniff.sh` coordinates discovery, probing, enrichment, and output.
- `scripts/core/` contains mode, scope, summary, port, and template helpers.
- `scripts/probes/` contains credential, SSDP, and ONVIF probes.
- `scripts/helpers/` contains parsers, profile resolution, and scoring logic.
- `scripts/integrations/` contains IVRE setup and ingestion.
- `data/catalog/` and `data/vendors/` contain evidence-backed device metadata.
- `packaging/arch/` and `debian/` contain distribution packaging.
- `tests/` contains the focused regression suite and safe fixtures.

## Making changes

### Shell and Python

- Preserve `set -euo pipefail` and quote shell expansions unless splitting is
  intentional.
- Keep every discovered or probed IPv4 address behind the scope helpers.
- Use structured parsers for JSON, CSV, and XML; do not parse structured output
  with fragile regular expressions.
- Treat discovery data, credentials, logs, and images as sensitive artifacts.
- Preserve the documented discovery schema or clearly document and test a
  deliberate schema change.

### Vendor and vulnerability data

- Prefer primary evidence such as vendor documentation, firmware manuals, or a
  reproducible observation on hardware you are authorized to test.
- Do not infer a vendor from a shared port or generic path alone.
- Keep vendor endpoint lists short and high-signal.
- Do not add real credentials. Placeholder templates are sufficient.
- Cite the source in the pull-request description. For CVEs, link the official
  advisory or CVE record and verify the affected model/version.

Vendor endpoint formats are documented in
[data/vendors/README.md](data/vendors/README.md). Preserve all columns in
`data/catalog/paths.csv` and validate the resulting CSV before submitting it.

## Validation

Run the checks relevant to your change. The expected minimum is:

```bash
make test
make lint
git diff --check
```

For packaging changes, also run:

```bash
make arch-verify
make arch-package
make build
```

For scanner-flow changes, use an isolated lab or an explicit loopback target.
Start with credential probing disabled:

```bash
sudo ./bin/camsniff \
  --yes \
  --mode stealth+ \
  --targets tests/fixtures/loopback-targets.txt \
  --interface lo \
  --skip-credentials \
  --skip-install \
  --report markdown
```

Never run broad modes against a network merely to validate a pull request.

## Pull requests

Complete the pull-request template and include:

- The problem and why the proposed change solves it.
- User-visible, security, schema, and compatibility effects.
- Exact validation commands and their results.
- Evidence for vendor paths, models, credentials defaults, or CVE mappings.
- Documentation and changelog updates when behavior changes.

Use clear, imperative commit messages. Maintainers may ask for a smaller patch,
additional regression coverage, or changes that preserve scan safety and data
compatibility.

By submitting a contribution, you agree that it may be distributed under the
project's [MIT License](LICENSE).
