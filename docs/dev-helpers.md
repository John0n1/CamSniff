# Development and release helpers

The top-level Makefile exposes the supported checks and package builds:

```bash
make test           # focused regression suite
make lint           # ShellCheck plus Bash syntax
make arch-verify    # compare PKGBUILD output with committed .SRCINFO
make arch-package   # package the current checkout for pacman
make build          # build Debian binary/source artifacts
make run MODE=medium RUN_FLAGS='--targets targets.txt --skip-credentials'
```

`make lint` expects ShellCheck to be installed; it does not mutate the system
or invoke a package manager. The Debian and Arch GitHub workflows build their
packages independently in the corresponding distribution environment.

Before a release:

1. Update `VERSION`, the banner/man page, `debian/changelog`, `PKGBUILD`, and
   `.SRCINFO` together.
2. Run the regression, syntax, metadata, and workflow checks.
3. Perform a loopback-only smoke run with credential probing disabled.
4. Build both packages and inspect their metadata and installed file lists.
5. Review `git diff --check` and commit the release as one coherent change.

Key implementation entry points:

- `scripts/camsniff.sh` — orchestration and artifact assembly.
- `scripts/core/` — modes, scope enforcement, summaries, and templates.
- `scripts/probes/` — credential, SSDP, and ONVIF probes.
- `scripts/helpers/` — parsing, profile enrichment, and confidence scoring.
- `scripts/integrations/` — IVRE setup and ingestion.
- `scripts/tools/` — reports and post-run analysis.
